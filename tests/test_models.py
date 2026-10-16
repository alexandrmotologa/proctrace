"""Unit tests for core models."""

import time
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    ProcessInfo,
    SyscallEvent,
    TraceSession,
)


def test_syscall_event_properties():
    now = time.time()
    event = SyscallEvent(
        timestamp=now,
        pid=1234,
        ppid=1000,
        process_name="node.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.OPEN,
        target_path="C:\\app\\.env",
        result=EventResult.FAILED_NOT_FOUND,
        duration_us=45.5,
        return_code=-2,
        errno_name="ENOENT",
    )

    assert event.is_error is True
    assert event.formatted_duration == "45.5 µs"
    assert event.category == EventCategory.FILESYSTEM
    assert event.operation == EventOperation.OPEN
    assert event.result == EventResult.FAILED_NOT_FOUND

    # Serialization roundtrip
    d = event.to_dict()
    assert d["pid"] == 1234
    assert d["errno_name"] == "ENOENT"
    assert d["is_error"] is True

    recovered = SyscallEvent.from_dict(d)
    assert recovered.pid == event.pid
    assert recovered.category == event.category
    assert recovered.result == event.result
    assert recovered.target_path == event.target_path
    assert recovered.duration_us == event.duration_us


def test_syscall_event_duration_formatting():
    e1 = SyscallEvent(time.time(), 1, "test", EventCategory.FILESYSTEM, EventOperation.READ, "f", duration_us=0.5)
    assert "ns" in e1.formatted_duration

    e2 = SyscallEvent(time.time(), 1, "test", EventCategory.FILESYSTEM, EventOperation.READ, "f", duration_us=500.0)
    assert "µs" in e2.formatted_duration

    e3 = SyscallEvent(time.time(), 1, "test", EventCategory.FILESYSTEM, EventOperation.READ, "f", duration_us=15_000.0)
    assert "ms" in e3.formatted_duration

    e4 = SyscallEvent(time.time(), 1, "test", EventCategory.FILESYSTEM, EventOperation.READ, "f", duration_us=2_500_000.0)
    assert "s" in e4.formatted_duration


def test_process_info():
    p = ProcessInfo(pid=500, name="python.exe", cmdline=["python", "script.py"], children=[501, 502])
    data = p.to_dict()
    assert data["pid"] == 500
    assert data["children"] == [501, 502]


def test_trace_session():
    session = TraceSession(target_cmd="npm install", start_time=100.0, end_time=105.5)
    assert session.duration_seconds == 5.5
    d = session.to_dict()
    assert d["target_cmd"] == "npm install"
    assert d["duration_seconds"] == 5.5
