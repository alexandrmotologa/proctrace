"""Linux native ptrace and procfs system call collector."""

from __future__ import annotations

import os
import re
import select
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set

import psutil

from proctrace.collectors.base import BaseCollector
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer

# x86_64 Linux Syscall Table mapping
X86_64_SYSCALL_MAP: Dict[int, Tuple[str, EventCategory, EventOperation]] = {
    0: ("read", EventCategory.FILESYSTEM, EventOperation.READ),
    1: ("write", EventCategory.FILESYSTEM, EventOperation.WRITE),
    2: ("open", EventCategory.FILESYSTEM, EventOperation.OPEN),
    3: ("close", EventCategory.FILESYSTEM, EventOperation.CLOSE),
    4: ("stat", EventCategory.FILESYSTEM, EventOperation.STAT),
    5: ("fstat", EventCategory.FILESYSTEM, EventOperation.STAT),
    6: ("lstat", EventCategory.FILESYSTEM, EventOperation.STAT),
    41: ("socket", EventCategory.NETWORK, EventOperation.CONNECT),
    42: ("connect", EventCategory.NETWORK, EventOperation.CONNECT),
    43: ("accept", EventCategory.NETWORK, EventOperation.ACCEPT),
    49: ("bind", EventCategory.NETWORK, EventOperation.BIND),
    50: ("listen", EventCategory.NETWORK, EventOperation.LISTEN),
    56: ("clone", EventCategory.PROCESS, EventOperation.SPAWN),
    57: ("fork", EventCategory.PROCESS, EventOperation.FORK),
    59: ("execve", EventCategory.PROCESS, EventOperation.EXEC),
    60: ("exit", EventCategory.PROCESS, EventOperation.EXIT),
    87: ("unlink", EventCategory.FILESYSTEM, EventOperation.DELETE),
    257: ("openat", EventCategory.FILESYSTEM, EventOperation.OPEN),
    263: ("unlinkat", EventCategory.FILESYSTEM, EventOperation.DELETE),
}

# Regex for parsing standard strace output format:
# [pid 12345] 14:22:01.123456 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3 <0.000045>
# [pid 12345] 14:22:01.123480 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ECONNREFUSED <0.000312>
STRACE_LINE_RE = re.compile(
    r"^(?:\[pid\s+(?P<pid>\d+)\]\s+)?(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<res>[^\s<]+)(?:\s+(?P<errno>[A-Z0-9_]+))?(?:\s+<(?P<duration>[\d\.]+)>)?$"
)


class LinuxCollector(BaseCollector):
    """Event collector for Linux systems supporting procfs polling and strace stream interception."""

    def __init__(
        self,
        ring_buffer: RingBuffer,
        target_pid: Optional[int] = None,
        use_strace_stream: bool = False,
        poll_interval_ms: float = 25.0,
    ) -> None:
        super().__init__(ring_buffer=ring_buffer, target_pid=target_pid, name="linux")
        self.use_strace_stream = use_strace_stream
        self.poll_interval = max(0.005, poll_interval_ms / 1000.0)
        self._known_fds: Dict[int, Set[str]] = {}
        self._strace_proc: Optional[subprocess.Popen] = None

    def _collect(self) -> None:
        """Main collection loop."""
        if self.use_strace_stream and self.target_pid is not None:
            self._run_strace_monitor()
        else:
            self._run_procfs_monitor()

    def _run_procfs_monitor(self) -> None:
        """Poll /proc filesystem and process open file descriptors."""
        while self.is_running:
            pids = list(self.tracked_pids)
            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()

                    # Scan open file descriptors
                    fd_dir = f"/proc/{pid}/fd"
                    if os.path.exists(fd_dir):
                        try:
                            current_targets = set()
                            for fd_entry in os.listdir(fd_dir):
                                link_path = os.path.join(fd_dir, fd_entry)
                                try:
                                    target = os.readlink(link_path)
                                    current_targets.add(target)
                                except (OSError, FileNotFoundError):
                                    continue

                            prev_targets = self._known_fds.setdefault(pid, set())
                            new_targets = current_targets - prev_targets
                            closed_targets = prev_targets - current_targets

                            for t in new_targets:
                                if t.startswith("socket:["):
                                    self.emit_event(
                                        pid=pid,
                                        process_name=proc_name,
                                        category=EventCategory.NETWORK,
                                        operation=EventOperation.CONNECT,
                                        target_path=t,
                                        result=EventResult.SUCCESS,
                                        duration_us=40.0,
                                    )
                                elif t.startswith("/"):
                                    res = EventResult.SUCCESS if os.path.exists(t) else EventResult.FAILED_NOT_FOUND
                                    self.emit_event(
                                        pid=pid,
                                        process_name=proc_name,
                                        category=EventCategory.FILESYSTEM,
                                        operation=EventOperation.OPEN,
                                        target_path=t,
                                        result=res,
                                        duration_us=25.0,
                                        errno_name=None if res == EventResult.SUCCESS else "ENOENT",
                                    )

                            for t in closed_targets:
                                if t.startswith("/"):
                                    self.emit_event(
                                        pid=pid,
                                        process_name=proc_name,
                                        category=EventCategory.FILESYSTEM,
                                        operation=EventOperation.CLOSE,
                                        target_path=t,
                                        result=EventResult.SUCCESS,
                                        duration_us=10.0,
                                    )

                            self._known_fds[pid] = current_targets
                        except (PermissionError, FileNotFoundError):
                            pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.untrack_pid(pid)
                    self._known_fds.pop(pid, None)

            time.sleep(self.poll_interval)

    def _run_strace_monitor(self) -> None:
        """Execute strace attached to the target PID and parse output stream in real time."""
        if not self.target_pid:
            return

        cmd = [
            "strace",
            "-f",
            "-T",
            "-tt",
            "-y",
            "-s", "256",
            "-p", str(self.target_pid),
        ]

        try:
            self._strace_proc = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            if not self._strace_proc.stderr:
                return

            for line in self._strace_proc.stderr:
                if not self.is_running:
                    break
                self._parse_strace_line(line.strip())

        except Exception:
            # Fall back to procfs monitoring on error
            self._run_procfs_monitor()
        finally:
            if self._strace_proc:
                try:
                    self._strace_proc.terminate()
                except Exception:
                    pass

    def _parse_strace_line(self, line: str) -> None:
        """Parse single strace line into a SyscallEvent."""
        match = STRACE_LINE_RE.match(line)
        if not match:
            return

        pid_str = match.group("pid")
        pid = int(pid_str) if pid_str else (self.target_pid or 0)
        syscall = match.group("syscall")
        args = match.group("args")
        res_str = match.group("res")
        errno = match.group("errno")
        duration_str = match.group("duration")

        duration_us = (float(duration_str) * 1_000_000.0) if duration_str else 0.0

        # Classify syscall category and operation
        category = EventCategory.FILESYSTEM
        operation = EventOperation.OPEN
        target_path = ""

        # Extract target path from arguments (e.g. "path/to/file")
        path_match = re.search(r'"([^"]+)"', args)
        if path_match:
            target_path = path_match.group(1)

        if syscall in ("open", "openat"):
            category = EventCategory.FILESYSTEM
            operation = EventOperation.OPEN
        elif syscall in ("read", "pread64"):
            category = EventCategory.FILESYSTEM
            operation = EventOperation.READ
        elif syscall in ("write", "pwrite64"):
            category = EventCategory.FILESYSTEM
            operation = EventOperation.WRITE
        elif syscall in ("close",):
            category = EventCategory.FILESYSTEM
            operation = EventOperation.CLOSE
        elif syscall in ("unlink", "unlinkat"):
            category = EventCategory.FILESYSTEM
            operation = EventOperation.DELETE
        elif syscall in ("connect",):
            category = EventCategory.NETWORK
            operation = EventOperation.CONNECT
            if not target_path:
                sock_match = re.search(r'sin_addr=inet_addr\("([^"]+)"\).*sin_port=htons\((\d+)\)', args)
                if sock_match:
                    target_path = f"{sock_match.group(1)}:{sock_match.group(2)}"
        elif syscall in ("execve", "clone", "fork"):
            category = EventCategory.PROCESS
            operation = EventOperation.EXEC if syscall == "execve" else EventOperation.SPAWN

        # Determine result status
        result = EventResult.SUCCESS
        return_code = 0
        try:
            return_code = int(res_str)
        except ValueError:
            pass

        if errno:
            if errno in ("ENOENT", "ENOTDIR"):
                result = EventResult.FAILED_NOT_FOUND
            elif errno in ("EACCES", "EPERM"):
                result = EventResult.FAILED_ACCESS_DENIED
            elif errno in ("ECONNREFUSED",):
                result = EventResult.FAILED_CONN_REFUSED
            elif errno in ("ETIMEDOUT",):
                result = EventResult.FAILED_TIMEOUT
            else:
                result = EventResult.FAILED_OTHER

        self.emit_event(
            pid=pid,
            process_name=f"pid-{pid}",
            category=category,
            operation=operation,
            target_path=target_path or syscall,
            result=result,
            duration_us=duration_us,
            return_code=return_code,
            errno_name=errno,
        )
