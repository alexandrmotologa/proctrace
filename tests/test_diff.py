"""Unit tests for the trace diff and regression detection engine."""

import time
from proctrace.core.diff import TraceDiffer
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)


def test_trace_diff_detection():
    # Baseline: 3 events, all successful
    base_events = [
        SyscallEvent(100.0, 10, "app", EventCategory.FILESYSTEM, EventOperation.OPEN, "config.json", EventResult.SUCCESS, duration_us=50.0),
        SyscallEvent(100.1, 10, "app", EventCategory.NETWORK, EventOperation.CONNECT, "127.0.0.1:8000", EventResult.SUCCESS, duration_us=100.0),
        SyscallEvent(100.2, 10, "app", EventCategory.FILESYSTEM, EventOperation.READ, "data.txt", EventResult.SUCCESS, duration_us=500.0),
    ]

    # Candidate: 1 new missing file (.env), 1 new endpoint (api.com), 1 latency regression (data.txt: 500us -> 3000us)
    curr_events = [
        SyscallEvent(200.0, 10, "app", EventCategory.FILESYSTEM, EventOperation.OPEN, "config.json", EventResult.SUCCESS, duration_us=50.0),
        SyscallEvent(200.1, 10, "app", EventCategory.FILESYSTEM, EventOperation.OPEN, ".env", EventResult.FAILED_NOT_FOUND, errno_name="ENOENT", duration_us=20.0),
        SyscallEvent(200.2, 10, "app", EventCategory.NETWORK, EventOperation.CONNECT, "127.0.0.1:8000", EventResult.SUCCESS, duration_us=105.0),
        SyscallEvent(200.3, 10, "app", EventCategory.NETWORK, EventOperation.CONNECT, "api.com:443", EventResult.SUCCESS, duration_us=1200.0),
        SyscallEvent(200.4, 10, "app", EventCategory.FILESYSTEM, EventOperation.READ, "data.txt", EventResult.SUCCESS, duration_us=3000.0),
    ]

    differ = TraceDiffer(min_regression_pct=50.0, min_regression_delta_us=1000.0)
    report = differ.compare(base_events, curr_events)

    assert report.baseline_count == 3
    assert report.current_count == 5
    assert report.count_delta == 2

    # Verify new missing file
    assert ".env" in report.new_missing_files

    # Verify new network endpoint
    assert "api.com:443" in report.new_network_endpoints

    # Verify latency regression on data.txt
    assert len(report.latency_regressions) == 1
    reg = report.latency_regressions[0]
    assert reg.target_path == "data.txt"
    assert reg.baseline_us == 500.0
    assert reg.current_us == 3000.0
    assert reg.delta_us == 2500.0
    assert reg.increase_pct == 500.0

    # Test Markdown rendering
    md = report.to_markdown()
    assert "ProcTrace Trace Diff Report" in md
    assert ".env" in md
    assert "api.com:443" in md
