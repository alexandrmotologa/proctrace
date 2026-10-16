"""Abstract base collector defining the lifecycle and event emission protocol."""

from __future__ import annotations

import abc
import threading
import time
from typing import Any, Dict, Optional, Set

from proctrace.core.models import EventCategory, EventOperation, EventResult, SyscallEvent
from proctrace.core.ring_buffer import RingBuffer


class BaseCollector(abc.ABC):
    """Abstract collector capturing kernel, filesystem, and network events."""

    def __init__(
        self,
        ring_buffer: RingBuffer,
        target_pid: Optional[int] = None,
        name: str = "collector",
    ) -> None:
        self.ring_buffer = ring_buffer
        self.target_pid = target_pid
        self.name = name
        self._is_running = False
        self._thread: Optional[threading.Thread] = None
        self._tracked_pids: Set[int] = set()
        if target_pid:
            self._tracked_pids.add(target_pid)
        self._events_emitted = 0
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Return True if the collector thread or process is actively running."""
        return self._is_running

    @property
    def tracked_pids(self) -> Set[int]:
        """Return set of currently tracked process identifiers."""
        with self._lock:
            return set(self._tracked_pids)

    def track_pid(self, pid: int) -> None:
        """Register a new child or associated process identifier."""
        with self._lock:
            self._tracked_pids.add(pid)

    def untrack_pid(self, pid: int) -> None:
        """Remove a process identifier when it terminates."""
        with self._lock:
            self._tracked_pids.discard(pid)

    def is_tracked(self, pid: int) -> bool:
        """Check if a given PID is currently being tracked."""
        with self._lock:
            if not self._tracked_pids:
                return True  # If no specific PID filter is set, track everything
            return pid in self._tracked_pids

    def emit_event(
        self,
        pid: int,
        process_name: str,
        category: EventCategory,
        operation: EventOperation,
        target_path: str,
        result: EventResult = EventResult.SUCCESS,
        duration_us: float = 0.0,
        return_code: Optional[int] = 0,
        errno_name: Optional[str] = None,
        timestamp: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        ppid: Optional[int] = None,
        tid: Optional[int] = None,
        depth: int = 0,
    ) -> SyscallEvent:
        """Construct and push a SyscallEvent into the target ring buffer."""
        event = SyscallEvent(
            timestamp=timestamp if timestamp is not None else time.time(),
            pid=pid,
            ppid=ppid,
            tid=tid,
            process_name=process_name,
            category=category,
            operation=operation,
            target_path=target_path,
            result=result,
            duration_us=duration_us,
            return_code=return_code,
            errno_name=errno_name,
            details=details or {},
            depth=depth,
        )
        self.ring_buffer.append(event)
        with self._lock:
            self._events_emitted += 1
        return event

    def start(self) -> None:
        """Start the collector thread."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._start_time = time.time()
            self._thread = threading.Thread(
                target=self._run_wrapper,
                name=f"ProcTrace-{self.name}",
                daemon=True,
            )
            self._thread.start()

    def _run_wrapper(self) -> None:
        """Internal thread runner with exception containment."""
        try:
            self._collect()
        finally:
            with self._lock:
                self._is_running = False

    @abc.abstractmethod
    def _collect(self) -> None:
        """Subclass implementation of the event collection loop."""
        raise NotImplementedError

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the collector to cease operation and wait for thread termination."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def get_stats(self) -> Dict[str, Any]:
        """Collector diagnostics and telemetry."""
        with self._lock:
            emitted = self._events_emitted
            running = self._is_running
            pids = list(self._tracked_pids)
            elapsed = (time.time() - self._start_time) if self._start_time else 0.0

        return {
            "name": self.name,
            "running": running,
            "events_emitted": emitted,
            "tracked_pids": pids,
            "elapsed_seconds": round(elapsed, 2),
            "rate": round(emitted / max(elapsed, 0.001), 2) if elapsed > 0 else 0.0,
        }
