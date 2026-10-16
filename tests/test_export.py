"""Unit tests for JSON, CSV, Chrome Trace, and Markdown report exporters."""

import json
import time
from pathlib import Path
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
    TraceSession,
)
from proctrace.export.chrome_trace import export_to_chrome_trace
from proctrace.export.csv_export import export_to_csv
from proctrace.export.json_export import export_to_json
from proctrace.export.markdown_report import export_to_markdown_report


def sample_events():
    return [
        SyscallEvent(
            timestamp=100.0,
            pid=42,
            ppid=1,
            process_name="test_app",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path="config.json",
            result=EventResult.SUCCESS,
            duration_us=120.0,
        ),
        SyscallEvent(
            timestamp=100.1,
            pid=42,
            ppid=1,
            process_name="test_app",
            category=EventCategory.NETWORK,
            operation=EventOperation.CONNECT,
            target_path="127.0.0.1:8000",
            result=EventResult.FAILED_CONN_REFUSED,
            duration_us=450.0,
            return_code=-1,
            errno_name="ECONNREFUSED",
        ),
    ]


def test_export_to_json(tmp_path: Path):
    events = sample_events()
    session = TraceSession(target_cmd="python test.py", start_time=100.0, end_time=101.0)
    out_file = tmp_path / "trace.json"

    json_str = export_to_json(events, output_path=out_file, session=session)
    data = json.loads(json_str)

    assert data["total_events"] == 2
    assert data["error_count"] == 1
    assert data["session"]["target_cmd"] == "python test.py"
    assert out_file.exists()


def test_export_to_csv(tmp_path: Path):
    events = sample_events()
    out_file = tmp_path / "trace.csv"

    csv_str = export_to_csv(events, output_path=out_file)
    lines = csv_str.strip().split("\n")

    assert len(lines) == 3  # Header + 2 events
    assert "config.json" in lines[1]
    assert "ECONNREFUSED" in lines[2]
    assert out_file.exists()


def test_export_to_chrome_trace(tmp_path: Path):
    events = sample_events()
    out_file = tmp_path / "chrome_trace.json"

    trace_str = export_to_chrome_trace(events, output_path=out_file)
    data = json.loads(trace_str)

    assert "traceEvents" in data
    assert any(e.get("name") == "process_name" for e in data["traceEvents"])
    assert any("CONNECT 127.0.0.1:8000" in e.get("name", "") for e in data["traceEvents"])
    assert out_file.exists()


def test_export_to_markdown_report(tmp_path: Path):
    events = sample_events()
    out_file = tmp_path / "report.md"

    md_str = export_to_markdown_report(events, output_path=out_file)
    assert "# ProcTrace Incident Triage Report" in md_str
    assert "Total Events: 2" in md_str
    assert "Failed Network Connections" in md_str
    assert "127.0.0.1:8000" in md_str
    assert out_file.exists()
