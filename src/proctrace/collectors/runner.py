"""Managed subprocess runner that launches child processes and traces all activity."""

from __future__ import annotations

import shlex
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Union

from proctrace.collectors.base import BaseCollector
from proctrace.collectors.linux import LinuxCollector
from proctrace.collectors.macos import MacOSCollector
from proctrace.collectors.windows import WindowsCollector
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer


def get_default_collector(
    ring_buffer: RingBuffer,
    target_pid: Optional[int] = None,
    poll_interval_ms: float = 20.0,
) -> BaseCollector:
    """Instantiate the platform-appropriate event collector."""
    if sys.platform == "win32":
        return WindowsCollector(
            ring_buffer=ring_buffer,
            target_pid=target_pid,
            poll_interval_ms=poll_interval_ms,
        )
    elif sys.platform == "darwin":
        return MacOSCollector(
            ring_buffer=ring_buffer,
            target_pid=target_pid,
            poll_interval_ms=poll_interval_ms,
        )
    else:
        return LinuxCollector(
            ring_buffer=ring_buffer,
            target_pid=target_pid,
            poll_interval_ms=poll_interval_ms,
        )


class SubprocessRunner:
    """Executes a child process while concurrently capturing its system events."""

    def __init__(
        self,
        command: Union[str, List[str]],
        ring_buffer: RingBuffer,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True,
        on_event: Optional[Callable[[SyscallEvent], None]] = None,
    ) -> None:
        self.command = command
        self.ring_buffer = ring_buffer
        self.cwd = cwd
        self.env = env
        self.capture_output = capture_output
        self.on_event = on_event

        self.process: Optional[subprocess.Popen] = None
        self.collector: Optional[BaseCollector] = None
        self.exit_code: Optional[int] = None
        self.stdout_data: str = ""
        self.stderr_data: str = ""
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def run(self) -> int:
        """Launch the command, monitor all kernel activity until exit, and return exit code."""
        cmd_args = shlex.split(self.command) if isinstance(self.command, str) else list(self.command)
        proc_name = cmd_args[0] if cmd_args else "subprocess"

        if self.on_event:
            self.ring_buffer.subscribe(self.on_event)

        self.start_time = time.time()

        # Start child process
        self.process = subprocess.Popen(
            cmd_args,
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.PIPE if self.capture_output else None,
            stderr=subprocess.PIPE if self.capture_output else None,
            text=True,
        )

        child_pid = self.process.pid

        # Emit initial SPAWN event
        self.ring_buffer.append(
            SyscallEvent(
                timestamp=self.start_time,
                pid=child_pid,
                process_name=proc_name,
                category=EventCategory.PROCESS,
                operation=EventOperation.SPAWN,
                target_path=" ".join(cmd_args),
                result=EventResult.SUCCESS,
                duration_us=250.0,
                details={"cmd": cmd_args, "cwd": self.cwd},
            )
        )

        # Initialize and launch OS collector attached to child PID
        self.collector = get_default_collector(
            ring_buffer=self.ring_buffer,
            target_pid=child_pid,
        )
        self.collector.start()

        # Read streams and wait for process completion
        stdout_buf, stderr_buf = "", ""
        try:
            if self.capture_output:
                stdout_buf, stderr_buf = self.process.communicate()
            else:
                self.process.wait()
        finally:
            self.end_time = time.time()
            self.exit_code = self.process.returncode

            # Cease collector
            if self.collector:
                self.collector.stop()

            if self.on_event:
                self.ring_buffer.unsubscribe(self.on_event)

        self.stdout_data = stdout_buf or ""
        self.stderr_data = stderr_buf or ""

        # Emit concluding EXIT event
        elapsed_us = (self.end_time - self.start_time) * 1_000_000.0
        res = EventResult.SUCCESS if self.exit_code == 0 else EventResult.FAILED_OTHER
        self.ring_buffer.append(
            SyscallEvent(
                timestamp=self.end_time,
                pid=child_pid,
                process_name=proc_name,
                category=EventCategory.PROCESS,
                operation=EventOperation.EXIT,
                target_path=f"exit({self.exit_code})",
                result=res,
                return_code=self.exit_code,
                duration_us=elapsed_us,
                details={"exit_code": self.exit_code, "elapsed_s": round(self.end_time - self.start_time, 3)},
            )
        )

        return self.exit_code
