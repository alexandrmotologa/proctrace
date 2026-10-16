"""Unit tests for event filtering, system noise suppression, and anomaly correlation."""

import time
from proctrace.core.filter import (
    AnomalyCorrelator,
    EventFilter,
)
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)


def test_event_filter_categories_and_errors():
    ev_ok = SyscallEvent(
        timestamp=time.time(),
        pid=100,
        process_name="python",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.READ,
        target_path="/app/data.csv",
        result=EventResult.SUCCESS,
    )
    ev_err = SyscallEvent(
        timestamp=time.time(),
        pid=100,
        process_name="python",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.OPEN,
        target_path="/app/.env",
        result=EventResult.FAILED_NOT_FOUND,
        errno_name="ENOENT",
    )
    ev_net = SyscallEvent(
        timestamp=time.time(),
        pid=100,
        process_name="python",
        category=EventCategory.NETWORK,
        operation=EventOperation.CONNECT,
        target_path="127.0.0.1:8080",
        result=EventResult.SUCCESS,
    )

    # Filter only errors
    flt_err = EventFilter(errors_only=True)
    assert flt_err.matches(ev_err) is True
    assert flt_err.matches(ev_ok) is False
    assert flt_err.matches(ev_net) is False

    # Filter by category
    flt_net = EventFilter(categories=[EventCategory.NETWORK])
    assert flt_net.matches(ev_net) is True
    assert flt_net.matches(ev_ok) is False

    # Filter by extension
    flt_ext = EventFilter(include_extensions=[".env"])
    assert flt_ext.matches(ev_err) is True
    assert flt_ext.matches(ev_ok) is False


def test_event_filter_system_noise_suppression():
    ev_system = SyscallEvent(
        timestamp=time.time(),
        pid=100,
        process_name="app.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.OPEN,
        target_path="C:\\Windows\\System32\\kernel32.dll",
        result=EventResult.SUCCESS,
    )
    ev_user = SyscallEvent(
        timestamp=time.time(),
        pid=100,
        process_name="app.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.OPEN,
        target_path="C:\\Projects\\app\\config.json",
        result=EventResult.SUCCESS,
    )

    flt_no_system = EventFilter(exclude_system=True)
    assert flt_no_system.matches(ev_system) is False
    assert flt_no_system.matches(ev_user) is True


def test_anomaly_correlator():
    events = [
        SyscallEvent(time.time(), 10, "node", EventCategory.FILESYSTEM, EventOperation.OPEN, "/app/.env", result=EventResult.FAILED_NOT_FOUND, errno_name="ENOENT"),
        SyscallEvent(time.time(), 10, "node", EventCategory.FILESYSTEM, EventOperation.OPEN, "/app/.env", result=EventResult.FAILED_NOT_FOUND, errno_name="ENOENT"),
        SyscallEvent(time.time(), 10, "node", EventCategory.FILESYSTEM, EventOperation.OPEN, "/etc/shadow", result=EventResult.FAILED_ACCESS_DENIED, errno_name="EACCES"),
        SyscallEvent(time.time(), 10, "node", EventCategory.NETWORK, EventOperation.CONNECT, "127.0.0.1:5432", result=EventResult.FAILED_CONN_REFUSED, errno_name="ECONNREFUSED"),
        SyscallEvent(time.time(), 10, "node", EventCategory.FILESYSTEM, EventOperation.READ, "/var/log/big.log", result=EventResult.SUCCESS, duration_us=25_000.0),
    ]

    correlator = AnomalyCorrelator(slow_threshold_us=10_000.0)
    report = correlator.correlate(events)

    assert report.total_scanned == 5
    assert len(report.missing_files) == 1
    assert report.missing_files[0].target == "/app/.env"
    assert report.missing_files[0].count == 2
    assert report.missing_files[0].details["is_config"] is True

    assert len(report.access_denied) == 1
    assert report.access_denied[0].target == "/etc/shadow"

    assert len(report.failed_connections) == 1
    assert report.failed_connections[0].target == "127.0.0.1:5432"

    assert len(report.slow_syscalls) == 1
    assert report.slow_syscalls[0].target == "/var/log/big.log"
    assert report.slow_syscalls[0].details["duration_us"] == 25_000.0
