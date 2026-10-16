"""Windows native process, filesystem, and socket event collector."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from proctrace.collectors.base import BaseCollector
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer

# Win32 Constants for ReadDirectoryChangesW
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100

FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


class WindowsCollector(BaseCollector):
    """Event collector for Windows systems utilizing Win32 APIs and process inspection."""

    def __init__(
        self,
        ring_buffer: RingBuffer,
        target_pid: Optional[int] = None,
        watch_dirs: Optional[List[str]] = None,
        poll_interval_ms: float = 25.0,
    ) -> None:
        super().__init__(ring_buffer=ring_buffer, target_pid=target_pid, name="windows")
        self.watch_dirs = watch_dirs or [os.getcwd()]
        self.poll_interval = max(0.005, poll_interval_ms / 1000.0)

        # Track previously observed state to detect diffs (new opens, connects, closes)
        self._known_files: Dict[int, Set[str]] = {}
        self._known_connections: Dict[int, Set[Tuple[str, int, str]]] = {}
        self._known_modules: Dict[int, Set[str]] = {}
        self._dir_threads: List[threading.Thread] = []

    def _collect(self) -> None:
        """Main collection loop."""
        # Start directory change listeners in background threads if on Windows
        if sys.platform == "win32":
            for d in self.watch_dirs:
                if os.path.isdir(d):
                    t = threading.Thread(
                        target=self._watch_directory_worker,
                        args=(d,),
                        daemon=True,
                        name=f"WinDirWatcher-{os.path.basename(d)}",
                    )
                    t.start()
                    self._dir_threads.append(t)

        while self.is_running:
            start_tick = time.perf_counter()
            self._poll_processes()
            elapsed = time.perf_counter() - start_tick
            sleep_time = max(0.001, self.poll_interval - elapsed)
            time.sleep(sleep_time)

    def _poll_processes(self) -> None:
        """Scan active tracked processes for open files, socket connections, and loaded modules."""
        # Update child processes if a target PID is set
        if self.target_pid is not None:
            try:
                parent = psutil.Process(self.target_pid)
                if not parent.is_running():
                    return
                for child in parent.children(recursive=True):
                    if child.pid not in self._tracked_pids:
                        self.track_pid(child.pid)
                        self.emit_event(
                            pid=child.pid,
                            ppid=parent.pid,
                            process_name=child.name(),
                            category=EventCategory.PROCESS,
                            operation=EventOperation.SPAWN,
                            target_path=" ".join(child.cmdline() if child.cmdline() else [child.name()]),
                            result=EventResult.SUCCESS,
                            duration_us=120.0,
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Inspect each tracked PID
        pids_to_scan = list(self.tracked_pids)
        for pid in pids_to_scan:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()

                # 1. Open Files
                try:
                    open_files = proc.open_files()
                    current_files = {f.path for f in open_files if f.path}
                    prev_files = self._known_files.setdefault(pid, set())
                    new_files = current_files - prev_files
                    closed_files = prev_files - current_files

                    for path in new_files:
                        is_write = False
                        # Determine if file was opened with write access
                        try:
                            # Look up file mode if available in open_files
                            for of in open_files:
                                if of.path == path and hasattr(of, "mode") and "w" in str(of.mode):
                                    is_write = True
                                    break
                        except Exception:
                            pass

                        op = EventOperation.WRITE if is_write else EventOperation.OPEN
                        res = EventResult.SUCCESS if os.path.exists(path) else EventResult.FAILED_NOT_FOUND

                        self.emit_event(
                            pid=pid,
                            process_name=proc_name,
                            category=EventCategory.FILESYSTEM,
                            operation=op,
                            target_path=path,
                            result=res,
                            duration_us=45.0,
                            errno_name=None if res == EventResult.SUCCESS else "ENOENT",
                        )

                    for path in closed_files:
                        self.emit_event(
                            pid=pid,
                            process_name=proc_name,
                            category=EventCategory.FILESYSTEM,
                            operation=EventOperation.CLOSE,
                            target_path=path,
                            result=EventResult.SUCCESS,
                            duration_us=15.0,
                        )

                    self._known_files[pid] = current_files
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # 2. Network Connections
                try:
                    conn_method = getattr(proc, "net_connections", proc.connections)
                    conns = conn_method(kind="all")
                    current_conns = set()
                    for c in conns:
                        raddr_str = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                        status_str = c.status
                        current_conns.add((raddr_str, c.laddr.port if c.laddr else 0, status_str))

                    prev_conns = self._known_connections.setdefault(pid, set())
                    new_conns = current_conns - prev_conns

                    for raddr, lport, status in new_conns:
                        if raddr:
                            res = EventResult.SUCCESS
                            errno = None
                            if status in ("CLOSE_WAIT", "SYN_SENT"):
                                res = EventResult.FAILED_CONN_REFUSED
                                errno = "WSAECONNREFUSED"

                            self.emit_event(
                                pid=pid,
                                process_name=proc_name,
                                category=EventCategory.NETWORK,
                                operation=EventOperation.CONNECT,
                                target_path=raddr,
                                result=res,
                                duration_us=350.0,
                                errno_name=errno,
                                details={"local_port": lport, "status": status},
                            )
                        elif lport:
                            self.emit_event(
                                pid=pid,
                                process_name=proc_name,
                                category=EventCategory.NETWORK,
                                operation=EventOperation.LISTEN,
                                target_path=f"0.0.0.0:{lport}",
                                result=EventResult.SUCCESS,
                                duration_us=180.0,
                                details={"status": status},
                            )

                    self._known_connections[pid] = current_conns
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # 3. Dynamic Libraries / Loaded DLLs
                try:
                    maps = proc.memory_maps(grouped=False)
                    current_modules = {m.path for m in maps if m.path and m.path.lower().endswith(".dll")}
                    prev_modules = self._known_modules.setdefault(pid, set())
                    new_modules = current_modules - prev_modules

                    for mod_path in new_modules:
                        self.emit_event(
                            pid=pid,
                            process_name=proc_name,
                            category=EventCategory.ENVIRONMENT,
                            operation=EventOperation.LOAD_LIBRARY,
                            target_path=mod_path,
                            result=EventResult.SUCCESS,
                            duration_us=85.0,
                        )

                    self._known_modules[pid] = current_modules
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.untrack_pid(pid)
                self._known_files.pop(pid, None)
                self._known_connections.pop(pid, None)
                self._known_modules.pop(pid, None)

    def _watch_directory_worker(self, path: str) -> None:
        """Background thread invoking ReadDirectoryChangesW for low-latency filesystem events."""
        if sys.platform != "win32":
            return

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            path,
            0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )

        if handle == -1 or handle == 0xFFFFFFFF:
            return

        buffer = ctypes.create_string_buffer(65536)
        bytes_returned = ctypes.c_ulong(0)

        notify_filter = (
            FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
        )

        try:
            while self.is_running:
                success = kernel32.ReadDirectoryChangesW(
                    handle,
                    buffer,
                    len(buffer),
                    True,  # bWatchSubtree
                    notify_filter,
                    ctypes.byref(bytes_returned),
                    None,
                    None,
                )

                if not success or bytes_returned.value == 0:
                    time.sleep(0.05)
                    continue

                # Parse FILE_NOTIFY_INFORMATION structures
                offset = 0
                while offset < bytes_returned.value:
                    next_entry_offset = int.from_bytes(buffer[offset : offset + 4], byteorder="little")
                    action = int.from_bytes(buffer[offset + 4 : offset + 8], byteorder="little")
                    name_length = int.from_bytes(buffer[offset + 8 : offset + 12], byteorder="little")
                    name_bytes = buffer[offset + 12 : offset + 12 + name_length]
                    rel_name = name_bytes.decode("utf-16le", errors="replace")

                    full_path = os.path.join(path, rel_name)

                    # Map Win32 actions to operations
                    op = EventOperation.OPEN
                    if action == FILE_ACTION_ADDED:
                        op = EventOperation.OPEN
                    elif action == FILE_ACTION_REMOVED:
                        op = EventOperation.DELETE
                    elif action == FILE_ACTION_MODIFIED:
                        op = EventOperation.WRITE
                    elif action in (FILE_ACTION_RENAMED_OLD_NAME, FILE_ACTION_RENAMED_NEW_NAME):
                        op = EventOperation.RENAME

                    self.emit_event(
                        pid=self.target_pid or os.getpid(),
                        process_name="kernel.fileio",
                        category=EventCategory.FILESYSTEM,
                        operation=op,
                        target_path=full_path,
                        result=EventResult.SUCCESS,
                        duration_us=30.0,
                        details={"win32_action": action},
                    )

                    if next_entry_offset == 0:
                        break
                    offset += next_entry_offset

        except Exception:
            pass
        finally:
            kernel32.CloseHandle(handle)
