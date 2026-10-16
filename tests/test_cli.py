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
