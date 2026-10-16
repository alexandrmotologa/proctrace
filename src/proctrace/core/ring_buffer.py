"""High-performance circular ring buffer for syscall events."""

from __future__ import annotations

import collections
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

from proctrace.core.models import EventCategory, EventResult, SyscallEvent


class RingBuffer:
    """Thread-safe circular ring buffer capable of holding up to 500,000 events.

    Provides microsecond-indexed lookups, rolling throughput calculation,
    and push-based subscriber callbacks.
    """

    def __init__(self, capacity: int = 500_000) -> None:
        if capacity <= 0:
            raise ValueError("Capacity must be greater than zero.")
        self._capacity = capacity
        self._buffer: List[Optional[SyscallEvent]] = [None] * capacity
        self._head: int = 0       # Next write index
        self._count: int = 0      # Current number of items in buffer (<= capacity)
        self._sequence: int = 0   # Total events ever added (monotonic)
        self._total_errors: int = 0
        self._lock = threading.RLock()

        # Rolling rate calculations (timestamps of events in the last 1.0 second)
        self._recent_timestamps: collections.deque[float] = collections.deque(maxlen=10_000)
        self._subscribers: List[Callable[[SyscallEvent], None]] = []

    @property
    def capacity(self) -> int:
        """Maximum event capacity of the ring buffer."""
        return self._capacity

    @property
    def count(self) -> int:
        """Current number of active events in memory."""
        with self._lock:
            return self._count

    @property
    def total_ingested(self) -> int:
        """Cumulative count of all ingested events since initialization."""
        with self._lock:
            return self._sequence

    @property
    def total_dropped(self) -> int:
        """Number of events overwritten due to ring capacity limits."""
        with self._lock:
            return max(0, self._sequence - self._capacity)

    @property
    def total_errors(self) -> int:
        """Cumulative count of failed or error events ingested."""
        with self._lock:
            return self._total_errors

    def subscribe(self, callback: Callable[[SyscallEvent], None]) -> None:
        """Register a subscriber callback invoked for every newly appended event."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[SyscallEvent], None]) -> None:
        """Remove an existing subscriber callback."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def append(self, event: SyscallEvent) -> int:
        """Append a new event into the circular buffer.

        Returns the monotonic sequence index of the appended event.
        """
        callbacks_to_fire: List[Callable[[SyscallEvent], None]] = []

        with self._lock:
            idx = self._head
            self._buffer[idx] = event
            self._head = (self._head + 1) % self._capacity
            if self._count < self._capacity:
                self._count += 1
            seq = self._sequence
            self._sequence += 1

            if event.is_error:
                self._total_errors += 1

            now = time.time()
            self._recent_timestamps.append(now)

            if self._subscribers:
                callbacks_to_fire = list(self._subscribers)

        # Notify subscribers outside the mutex to avoid holding the lock during user code
        for cb in callbacks_to_fire:
            try:
                cb(event)
            except Exception:
                pass

        return seq

    def extend(self, events: Sequence[SyscallEvent]) -> None:
        """Append multiple events in a single operation."""
        for event in events:
            self.append(event)

    def get_all(self) -> List[SyscallEvent]:
        """Return a chronological snapshot of all events currently in the buffer."""
        with self._lock:
            if self._count == 0:
                return []
            if self._count < self._capacity:
                # Buffer has not wrapped yet; return items 0 .. count-1
                return [self._buffer[i] for i in range(self._count) if self._buffer[i] is not None]  # type: ignore

            # Buffer has wrapped: oldest item is at self._head
            result: List[SyscallEvent] = []
            for i in range(self._capacity):
                pos = (self._head + i) % self._capacity
                item = self._buffer[pos]
                if item is not None:
                    result.append(item)
            return result

    def get_slice(self, offset: int = 0, limit: int = 100) -> List[SyscallEvent]:
        """Return a chronological slice of events using offset and limit."""
        all_events = self.get_all()
        if offset < 0:
            offset = max(0, len(all_events) + offset)
        return all_events[offset : offset + limit]

    def get_since(self, timestamp: float) -> List[SyscallEvent]:
        """Return all events recorded at or after the given timestamp."""
        with self._lock:
            events = self.get_all()
        return [ev for ev in events if ev.timestamp >= timestamp]

    def filter_events(
        self,
        pid: Optional[int] = None,
        category: Optional[EventCategory] = None,
        errors_only: bool = False,
        min_duration_us: float = 0.0,
        limit: Optional[int] = None,
    ) -> List[SyscallEvent]:
        """Retrieve events matching specified query criteria."""
        events = self.get_all()
        filtered: List[SyscallEvent] = []

        for ev in events:
            if pid is not None and ev.pid != pid:
                continue
            if category is not None and ev.category != category:
                continue
            if errors_only and not ev.is_error:
                continue
            if min_duration_us > 0.0 and ev.duration_us < min_duration_us:
                continue
            filtered.append(ev)
            if limit is not None and len(filtered) >= limit:
                break

        return filtered

    def get_events_per_second(self) -> float:
        """Compute the instantaneous throughput in events per second over the last 1.0 second."""
        now = time.time()
        one_sec_ago = now - 1.0
        with self._lock:
            while self._recent_timestamps and self._recent_timestamps[0] < one_sec_ago:
                self._recent_timestamps.popleft()
            return float(len(self._recent_timestamps))

    def get_stats(self) -> Dict[str, Any]:
        """Return operational statistics about the ring buffer."""
        with self._lock:
            count = self._count
            seq = self._sequence
            dropped = max(0, seq - self._capacity)
            errors = self._total_errors

        rate = self.get_events_per_second()
        return {
            "capacity": self._capacity,
            "active_count": count,
            "total_ingested": seq,
            "total_dropped": dropped,
            "total_errors": errors,
            "events_per_sec": rate,
            "utilization_pct": round((count / self._capacity) * 100.0, 2),
        }

    def clear(self) -> None:
        """Reset the buffer state completely."""
        with self._lock:
            self._buffer = [None] * self._capacity
            self._head = 0
            self._count = 0
            self._sequence = 0
            self._total_errors = 0
            self._recent_timestamps.clear()

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[SyscallEvent]:
        return iter(self.get_all())
