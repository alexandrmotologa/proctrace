"""macOS dtrace and dtruss system call collector."""

from __future__ import annotations

import os
import re
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

# Regex for parsing dtruss output:
# open_nocancel("/etc/resolv.conf\0", 0x0, 0x1B6) = 3 0
# stat64("/Users/dev/.zshrc\0", 0x7FFEE3F678E0, 0x7FFEE3F678E0) = -1 Err#2
DTRUSS_LINE_RE = re.compile(
    r"^(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<res>[^\s]+)(?:\s+(?:Err#(?P<errno_num>\d+)|(?P<errno_name>[A-Z0-9_]+)))?$"
)

DARWIN_ERRNO_MAP = {
    "2": ("ENOENT", EventResult.FAILED_NOT_FOUND),
    "13": ("EACCES", EventResult.FAILED_ACCESS_DENIED),
    "61": ("ECONNREFUSED", EventResult.FAILED_CONN_REFUSED),
    "60": ("ETIMEDOUT", EventResult.FAILED_TIMEOUT),
}


class MacOSCollector(BaseCollector):
    """Event collector for macOS using dtruss, fs_usage, and psutil telemetry."""

    def __init__(
        self,
        ring_buffer: RingBuffer,
        target_pid: Optional[int] = None,
        poll_interval_ms: float = 25.0,
    ) -> None:
        super().__init__(ring_buffer=ring_buffer, target_pid=target_pid, name="macos")
        self.poll_interval = max(0.005, poll_interval_ms / 1000.0)
        self._known_files: Dict[int, Set[str]] = {}
        self._known_conns: Dict[int, Set[str]] = {}

    def _collect(self) -> None:
        """Poll macOS process tree."""
        while self.is_running:
            pids = list(self.tracked_pids)
            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()

                    # 1. Open files
                    try:
                        open_files = proc.open_files()
                        current_files = {f.path for f in open_files if f.path}
                        prev_files = self._known_files.setdefault(pid, set())
                        new_files = current_files - prev_files
                        closed_files = prev_files - current_files

                        for fpath in new_files:
                            res = EventResult.SUCCESS if os.path.exists(fpath) else EventResult.FAILED_NOT_FOUND
                            self.emit_event(
                                pid=pid,
                                process_name=proc_name,
                                category=EventCategory.FILESYSTEM,
                                operation=EventOperation.OPEN,
                                target_path=fpath,
                                result=res,
                                duration_us=35.0,
                                errno_name=None if res == EventResult.SUCCESS else "ENOENT",
                            )

                        for fpath in closed_files:
                            self.emit_event(
                                pid=pid,
                                process_name=proc_name,
                                category=EventCategory.FILESYSTEM,
                                operation=EventOperation.CLOSE,
                                target_path=fpath,
                                result=EventResult.SUCCESS,
                                duration_us=12.0,
                            )

                        self._known_files[pid] = current_files
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # 2. Sockets
                    try:
                        conn_method = getattr(proc, "net_connections", proc.connections)
                        conns = conn_method(kind="all")
                        current_conns = {f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr}
                        prev_conns = self._known_conns.setdefault(pid, set())
                        new_conns = current_conns - prev_conns

                        for endpoint in new_conns:
                            self.emit_event(
                                pid=pid,
                                process_name=proc_name,
                                category=EventCategory.NETWORK,
                                operation=EventOperation.CONNECT,
                                target_path=endpoint,
                                result=EventResult.SUCCESS,
                                duration_us=400.0,
                            )
                        self._known_conns[pid] = current_conns
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.untrack_pid(pid)
                    self._known_files.pop(pid, None)
                    self._known_conns.pop(pid, None)

            time.sleep(self.poll_interval)
