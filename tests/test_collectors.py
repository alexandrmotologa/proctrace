"""Unit tests for platform collectors and strace line parsing."""

import time
from proctrace.collectors.base import BaseCollector
from proctrace.collectors.linux import LinuxCollector
from proctrace.collectors.windows import WindowsCollector
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
)
from proctrace.core.ring_buffer import RingBuffer


class DummyCollector(BaseCollector):
    def _collect(self) -> None:
        while self.is_running:
            time.sleep(0.01)


def test_base_collector_lifecycle():
    rb = RingBuffer(capacity=100)
    col = DummyCollector(ring_buffer=rb, target_pid=123)

    assert col.is_tracked(123) is True
    assert col.is_tracked(999) is False

    col.track_pid(999)
    assert col.is_tracked(999) is True

    col.untrack_pid(999)
    assert col.is_tracked(999) is False

    col.start()
    assert col.is_running is True

    # Emit an event
    col.emit_event(
        pid=123,
        process_name="dummy",
        category=EventCategory.PROCESS,
        operation=EventOperation.SPAWN,
        target_path="dummy.exe",
    )
    assert rb.count == 1

    stats = col.get_stats()
    assert stats["events_emitted"] == 1
    assert stats["running"] is True

    col.stop()
    assert col.is_running is False


def test_linux_strace_parsing():
    rb = RingBuffer(capacity=100)
    col = LinuxCollector(ring_buffer=rb, target_pid=456)

    # Valid strace file open line
    line1 = '[pid 456] 12:00:00.123456 openat(AT_FDCWD, "/etc/config.json", O_RDONLY) = 3 <0.000045>'
    col._parse_strace_line(line1)
    assert rb.count == 1
    ev1 = rb.get_all()[0]
    assert ev1.operation == EventOperation.OPEN
    assert ev1.target_path == "/etc/config.json"
    assert ev1.result == EventResult.SUCCESS

    # Failed ENOENT line
    line2 = '[pid 456] 12:00:00.123500 openat(AT_FDCWD, "/missing/.env", O_RDONLY) = -1 ENOENT <0.000010>'
    col._parse_strace_line(line2)
    assert rb.count == 2
    ev2 = rb.get_all()[1]
    assert ev2.result == EventResult.FAILED_NOT_FOUND
    assert ev2.errno_name == "ENOENT"
    assert ev2.is_error is True


def test_windows_collector_init():
    rb = RingBuffer(capacity=100)
    col = WindowsCollector(ring_buffer=rb, target_pid=100)
    assert col.name == "windows"
    assert col.target_pid == 100
