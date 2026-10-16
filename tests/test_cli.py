"""Tests for the Typer CLI commands."""

import json
from pathlib import Path
from typer.testing import CliRunner
from proctrace.cli.main import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "ProcTrace" in result.stdout


def test_cli_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "ProcTrace System Diagnostic" in result.stdout
    assert "Ring Buffer Speed" in result.stdout


def test_cli_run_headless(tmp_path: Path):
    out_json = tmp_path / "test_run.json"
    result = runner.invoke(app, [
        "run",
        "--no-tui",
        "--output-json", str(out_json),
        "--",
        "python", "-c", "print('proctrace test')"
    ])
    assert result.exit_code == 0
    assert out_json.exists()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["total_events"] >= 2


def test_cli_export(tmp_path: Path):
    trace_file = tmp_path / "trace.json"
    trace_data = {
        "format": "proctrace-trace-v1",
        "events": [
            {
                "id": "abc12345",
                "timestamp": 1000.0,
                "pid": 1234,
                "process_name": "worker",
                "category": "FILESYSTEM",
                "operation": "OPEN",
                "target_path": "data.txt",
                "result": "SUCCESS",
                "duration_us": 50.0,
            }
        ]
    }
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_data, f)

    csv_out = tmp_path / "out.csv"
    res = runner.invoke(app, ["export", str(trace_file), "--format", "csv", "--output", str(csv_out)])
    assert res.exit_code == 0
    assert csv_out.exists()
    assert "data.txt" in csv_out.read_text(encoding="utf-8")


def test_cli_diff(tmp_path: Path):
    t1 = tmp_path / "t1.json"
    t2 = tmp_path / "t2.json"

    t1.write_text(json.dumps({
        "events": [
            {"id": "1", "timestamp": 100.0, "pid": 10, "process_name": "app", "category": "FILESYSTEM", "operation": "OPEN", "target_path": "a.txt", "result": "SUCCESS", "duration_us": 10.0}
        ]
    }), encoding="utf-8")

    t2.write_text(json.dumps({
        "events": [
            {"id": "1", "timestamp": 100.0, "pid": 10, "process_name": "app", "category": "FILESYSTEM", "operation": "OPEN", "target_path": "a.txt", "result": "SUCCESS", "duration_us": 10.0},
            {"id": "2", "timestamp": 100.1, "pid": 10, "process_name": "app", "category": "FILESYSTEM", "operation": "OPEN", "target_path": ".env", "result": "FAILED_NOT_FOUND", "errno_name": "ENOENT", "duration_us": 5.0}
        ]
    }), encoding="utf-8")

    res = runner.invoke(app, ["diff", str(t1), str(t2)])
    assert res.exit_code == 0
    assert "Trace Comparison Summary" in res.stdout
    assert ".env" in res.stdout


def test_cli_explain(tmp_path: Path):
    trace_file = tmp_path / "err_trace.json"
    trace_file.write_text(json.dumps({
        "events": [
            {"id": "1", "timestamp": 100.0, "pid": 10, "process_name": "node", "category": "FILESYSTEM", "operation": "OPEN", "target_path": ".env", "result": "FAILED_NOT_FOUND", "errno_name": "ENOENT", "duration_us": 5.0}
        ]
    }), encoding="utf-8")

    res = runner.invoke(app, ["explain", str(trace_file)])
    assert res.exit_code == 0
    assert "Missing Environment/Config File" in res.stdout


def test_cli_audit(tmp_path: Path):
    trace_file = tmp_path / "audit_trace.json"
    trace_file.write_text(json.dumps({
        "events": [
            {"id": "1", "timestamp": 100.0, "pid": 10, "process_name": "node", "category": "FILESYSTEM", "operation": "READ", "target_path": "/root/.ssh/id_rsa", "result": "SUCCESS", "duration_us": 15.0}
        ]
    }), encoding="utf-8")

    res = runner.invoke(app, ["audit", str(trace_file)])
    assert res.exit_code == 0
    assert "Security & Sandbox Audit" in res.stdout
    assert "SSH Private Key" in res.stdout


def test_cli_assert_policy():
    res = runner.invoke(app, ["assert", "--no-missing-configs", "--", "python", "-c", "print('ok')"])
    assert res.exit_code == 0
    assert "[PASS] All policies passed successfully." in res.stdout

