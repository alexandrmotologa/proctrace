"""CLI entry point and subcommands for ProcTrace."""

from __future__ import annotations

import json
import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from proctrace import __version__
from proctrace.collectors.base import BaseCollector
from proctrace.collectors.runner import SubprocessRunner, get_default_collector
from proctrace.core.filter import AnomalyCorrelator, EventFilter
from proctrace.core.models import SyscallEvent, TraceSession
from proctrace.core.ring_buffer import RingBuffer
from proctrace.export.chrome_trace import export_to_chrome_trace
from proctrace.export.csv_export import export_to_csv
from proctrace.export.json_export import export_to_json
from proctrace.export.markdown_report import export_to_markdown_report
from proctrace.analysis.explainer import RootCauseExplainer
from proctrace.core.diff import TraceDiffer
from proctrace.security.auditor import PolicyGuard, SecurityAuditor
from proctrace.tui.app import ProcTraceTUI
from proctrace.web.server import create_app

app = typer.Typer(
    name="proctrace",
    help="Cross-Platform Process Activity & Syscall Waterfall Monitor.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold green]ProcTrace[/bold green] version [cyan]{__version__}[/cyan]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command(name="run", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run_command(
    ctx: typer.Context,
    tui: bool = typer.Option(True, "--tui/--no-tui", help="Launch interactive Textual TUI."),
    web: bool = typer.Option(False, "--web/--no-web", help="Launch Web Studio concurrently."),
    web_port: int = typer.Option(8995, "--web-port", help="Port for Web Studio."),
    errors_only: bool = typer.Option(False, "--errors-only", "-e", help="Filter for failed syscalls only."),
    filter_config: Optional[Path] = typer.Option(None, "--filter-config", "-f", help="Path to YAML filter config."),
    output_json: Optional[Path] = typer.Option(None, "--output-json", help="Export trace to JSON on exit."),
    output_csv: Optional[Path] = typer.Option(None, "--output-csv", help="Export trace to CSV on exit."),
    output_chrome: Optional[Path] = typer.Option(None, "--output-chrome", help="Export to Chrome Trace (Perfetto)."),
    output_report: Optional[Path] = typer.Option(None, "--output-report", help="Generate Markdown incident report."),
) -> None:
    """Run a target command under ProcTrace and capture all process and kernel activity."""
    cmd_args = ctx.args
    if not cmd_args:
        console.print("[bold red]Error:[/bold red] No command provided. Usage: `proctrace run -- <cmd>`")
        raise typer.Exit(1)

    cmd_str = " ".join(cmd_args)
    ring_buffer = RingBuffer(capacity=500_000)
    session = TraceSession(target_cmd=cmd_str, start_time=time.time())

    # Optional Web Studio launcher in background thread
    web_server_thread = None
    if web:
        web_app = create_app(ring_buffer, session)
        config = uvicorn.Config(web_app, host="127.0.0.1", port=web_port, log_level="warning")
        server = uvicorn.Server(config)
        web_server_thread = threading.Thread(target=server.run, daemon=True)
        web_server_thread.start()
        console.print(f"[bold cyan]Web Studio live at:[/] http://127.0.0.1:{web_port}")

    runner = SubprocessRunner(
        command=cmd_args,
        ring_buffer=ring_buffer,
        capture_output=True,
    )

    if tui and sys.stdin.isatty():
        # Run subprocess in worker thread and TUI in main thread
        runner_thread = threading.Thread(target=runner.run, daemon=True)
        runner_thread.start()

        tui_app = ProcTraceTUI(ring_buffer, title_info=cmd_str)
        tui_app.run()
        runner_thread.join(timeout=1.0)
    else:
        # Headless console execution with real-time log prints
        console.print(f"[bold green]Starting trace on:[/] {cmd_str}")

        def print_event(e: SyscallEvent) -> None:
            if errors_only and not e.is_error:
                return
            style = "bold red" if e.is_error else "cyan"
            status = f"[{style}]{e.result.value}[/{style}]"
            console.print(f"[{e.timestamp:.3f}] [yellow]{e.process_name}[/] ({e.pid}) {e.operation.value} {e.target_path} -> {status} ({e.formatted_duration})")

        ring_buffer.subscribe(print_event)
        exit_code = runner.run()
        console.print(f"[bold green]Process finished with exit code:[/] {exit_code}")

    session.end_time = time.time()
    session.total_events = ring_buffer.total_ingested
    session.error_events = ring_buffer.total_errors

    # Export outputs if requested
    events = ring_buffer.get_all()
    if output_json:
        export_to_json(events, output_json, session=session)
        console.print(f"[green]Trace JSON saved to:[/] {output_json}")
    if output_csv:
        export_to_csv(events, output_csv)
        console.print(f"[green]Trace CSV saved to:[/] {output_csv}")
    if output_chrome:
        export_to_chrome_trace(events, output_chrome)
        console.print(f"[green]Chrome Trace (Perfetto) saved to:[/] {output_chrome}")
    if output_report:
        export_to_markdown_report(events, output_report, session=session)
        console.print(f"[green]Incident report saved to:[/] {output_report}")


@app.command(name="attach")
def attach_command(
    pid: int = typer.Argument(..., help="Process ID to monitor."),
    tui: bool = typer.Option(True, "--tui/--no-tui", help="Launch interactive Textual TUI."),
    web: bool = typer.Option(False, "--web/--no-web", help="Launch Web Studio."),
    web_port: int = typer.Option(8995, "--web-port", help="Port for Web Studio."),
) -> None:
    """Attach to an existing running process and trace its activity."""
    ring_buffer = RingBuffer(capacity=500_000)
    session = TraceSession(target_pid=pid, start_time=time.time())

    collector = get_default_collector(ring_buffer=ring_buffer, target_pid=pid)
    collector.start()

    if web:
        web_app = create_app(ring_buffer, session)
        config = uvicorn.Config(web_app, host="127.0.0.1", port=web_port, log_level="warning")
        server = uvicorn.Server(config)
        web_server_thread = threading.Thread(target=server.run, daemon=True)
        web_server_thread.start()
        console.print(f"[bold cyan]Web Studio live at:[/] http://127.0.0.1:{web_port}")

    try:
        if tui and sys.stdin.isatty():
            tui_app = ProcTraceTUI(ring_buffer, title_info=f"PID {pid}")
            tui_app.run()
        else:
            console.print(f"[bold green]Attached to PID {pid}. Press Ctrl+C to stop.[/]")
            while collector.is_running:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()
        console.print("[yellow]Detached from process.[/]")


@app.command(name="web")
def web_command(
    port: int = typer.Option(8995, "--port", "-p", help="Port to serve Web Studio on."),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host interface to bind."),
    load_trace: Optional[Path] = typer.Option(None, "--load-trace", "-l", help="Load saved JSON trace file."),
) -> None:
    """Launch the interactive ProcTrace Web Studio in browser."""
    ring_buffer = RingBuffer(capacity=500_000)
    session = TraceSession(start_time=time.time())

    if load_trace and load_trace.exists():
        console.print(f"[cyan]Loading trace from:[/] {load_trace}")
        with open(load_trace, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "events" in data:
                loaded_events = [SyscallEvent.from_dict(d) for d in data["events"]]
                ring_buffer.extend(loaded_events)
                console.print(f"[green]Loaded {len(loaded_events):,} events into buffer.[/]")

    app_instance = create_app(ring_buffer, session)
    console.print(Panel(
        f"[bold green]ProcTrace Web Studio[/bold green]\n"
        f"Server listening at: [bold cyan]http://{host}:{port}[/bold cyan]\n"
        f"Real-time WebSocket stream active at [bold cyan]ws://{host}:{port}/ws/live[/bold cyan]",
        title="Web Studio",
        border_style="green",
    ))
    uvicorn.run(app_instance, host=host, port=port, log_level="info")


@app.command(name="export")
def export_command(
    trace_file: Path = typer.Argument(..., help="Source trace JSON file."),
    format: str = typer.Option("chrome", "--format", "-f", help="Target format: json, csv, chrome, report."),
    output: Path = typer.Option(..., "--output", "-o", help="Destination output file path."),
) -> None:
    """Convert an existing JSON trace file into CSV, Chrome Trace Format, or a Markdown Report."""
    if not trace_file.exists():
        console.print(f"[red]Error:[/] Trace file {trace_file} does not exist.")
        raise typer.Exit(1)

    with open(trace_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        events = [SyscallEvent.from_dict(d) for d in data.get("events", [])]

    fmt = format.lower()
    if fmt == "csv":
        export_to_csv(events, output)
    elif fmt in ("chrome", "perfetto"):
        export_to_chrome_trace(events, output)
    elif fmt in ("report", "markdown", "md"):
        export_to_markdown_report(events, output)
    else:
        export_to_json(events, output)

    console.print(f"[green]Successfully exported {len(events)} events to:[/] {output}")


@app.command(name="doctor")
def doctor_command() -> None:
    """Inspect environment, operating system tracing capabilities, and buffer throughput."""
    table = Table(title="ProcTrace System Diagnostic (Doctor)")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="white")

    # Python version
    py_ver = platform.python_version()
    table.add_row("Python Runtime", "OK", f"Python {py_ver} ({platform.python_implementation()})")

    # Operating System
    os_name = sys.platform
    table.add_row("Operating System", "OK", f"{platform.system()} {platform.release()} ({platform.machine()})")

    # Collector capabilities
    if os_name == "win32":
        table.add_row("Windows Collector", "Supported", "Win32 API, ReadDirectoryChangesW, psutil hooks")
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            priv_status = "Elevated (Admin)" if is_admin else "Standard User (Kernel hooks active)"
            table.add_row("Process Privileges", "OK", priv_status)
        except Exception:
            table.add_row("Process Privileges", "Warning", "Could not check admin status")
    elif os_name.startswith("linux"):
        has_strace = any(os.access(os.path.join(p, "strace"), os.X_OK) for p in os.environ.get("PATH", "").split(os.path.pathsep))
        strace_status = "Available" if has_strace else "Not found in PATH (procfs fallback active)"
        table.add_row("Linux Collector", "Supported", f"ptrace / procfs ({strace_status})")
    elif os_name == "darwin":
        table.add_row("macOS Collector", "Supported", "dtrace / dtruss / EndpointSecurity fallback")

    # Benchmark ring buffer throughput
    test_buffer = RingBuffer(capacity=100_000)
    test_event = SyscallEvent(
        timestamp=time.time(),
        pid=os.getpid(),
        process_name="doctor",
        category="FILESYSTEM",  # type: ignore
        operation="OPEN",       # type: ignore
        target_path="benchmark.txt",
        duration_us=10.0,
    )

    t0 = time.perf_counter()
    for _ in range(50_000):
        test_buffer.append(test_event)
    bench_time = time.perf_counter() - t0
    rate = 50_000.0 / max(bench_time, 0.0001)

    table.add_row("Ring Buffer Speed", "High Speed", f"{int(rate):,} events/sec ({bench_time*1000:.1f}ms for 50k events)")

    console.print(table)
    console.print("\n[bold green]Ready to trace process activity![/bold green]")


@app.command(name="diff")
def diff_command(
    baseline_trace: Path = typer.Argument(..., help="Baseline trace JSON file."),
    current_trace: Path = typer.Argument(..., help="Candidate/current trace JSON file."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save markdown diff report to file."),
    json_output: bool = typer.Option(False, "--json", help="Output diff as JSON."),
) -> None:
    """Compare two traces to identify regressions, new errors, and latency shifts."""
    if not baseline_trace.exists():
        console.print(f"[red]Error:[/] Baseline trace '{baseline_trace}' not found.")
        raise typer.Exit(1)
    if not current_trace.exists():
        console.print(f"[red]Error:[/] Candidate trace '{current_trace}' not found.")
        raise typer.Exit(1)

    with open(baseline_trace, "r", encoding="utf-8") as f:
        base_data = json.load(f)
    with open(current_trace, "r", encoding="utf-8") as f:
        curr_data = json.load(f)

    base_events = [SyscallEvent.from_dict(e) for e in base_data.get("events", [])]
    curr_events = [SyscallEvent.from_dict(e) for e in curr_data.get("events", [])]

    differ = TraceDiffer()
    report = differ.compare(base_events, curr_events)

    if json_output:
        console.print_json(json.dumps(report.to_dict()))
    else:
        # Render colored rich table summary
        table = Table(title="Trace Comparison Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Baseline", style="white")
        table.add_column("Candidate", style="white")
        table.add_column("Delta", style="yellow")

        table.add_row("Total Events", str(report.baseline_count), str(report.current_count), f"{report.count_delta:+d}")
        table.add_row("Total Errors", str(report.baseline_errors), str(report.current_errors), f"{report.error_delta:+d}")
        table.add_row("New Missing Files (ENOENT)", "0", str(len(report.new_missing_files)), f"+{len(report.new_missing_files)}")
        table.add_row("New Network Endpoints", "0", str(len(report.new_network_endpoints)), f"+{len(report.new_network_endpoints)}")
        table.add_row("Latency Regressions (>50%)", "0", str(len(report.latency_regressions)), f"+{len(report.latency_regressions)}")
        console.print(table)

        if report.new_missing_files:
            console.print("\n[bold red]New Missing Files (ENOENT):[/bold red]")
            for p in report.new_missing_files:
                console.print(f"  [red][X][/red] {p}")

        if report.latency_regressions:
            console.print("\n[bold yellow]Latency Regressions:[/bold yellow]")
            for r in report.latency_regressions[:10]:
                console.print(f"  [yellow]![/yellow] {r.operation} {r.target_path}: {r.baseline_us:.1f}µs -> {r.current_us:.1f}µs (+{r.increase_pct:.1f}%)")

    if output:
        md = report.to_markdown()
        output.write_text(md, encoding="utf-8")
        console.print(f"\n[green]Diff report saved to:[/] {output}")


@app.command(name="explain")
def explain_command(
    trace_file: Path = typer.Argument(..., help="Trace JSON file to analyze."),
    json_output: bool = typer.Option(False, "--json", help="Output explanations as JSON."),
) -> None:
    """Analyze intercepted failures and produce root-cause explanations with remediation steps."""
    if not trace_file.exists():
        console.print(f"[red]Error:[/] Trace file '{trace_file}' not found.")
        raise typer.Exit(1)

    with open(trace_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    events = [SyscallEvent.from_dict(e) for e in data.get("events", [])]

    explainer = RootCauseExplainer()
    explanations = explainer.explain(events)

    if json_output:
        console.print_json(json.dumps([ex.to_dict() for ex in explanations]))
        return

    if not explanations:
        console.print("[bold green][OK] No actionable failure patterns detected in trace.[/bold green]")
        return

    console.print(f"[bold cyan]Identified {len(explanations)} root-cause diagnostic finding(s):[/bold cyan]\n")
    for idx, ex in enumerate(explanations, 1):
        sev_color = "red" if ex.severity == "CRITICAL" else "yellow"
        console.print(Panel(
            f"[bold {sev_color}]Rule:[/] {ex.rule_name}\n"
            f"[bold {sev_color}]Root Cause:[/] {ex.root_cause}\n\n"
            f"[bold green]Suggested Remediation:[/bold green]\n"
            + "\n".join(f"  * {step}" for step in ex.remediation_steps),
            title=f"Finding #{idx}: [{sev_color}]{ex.title}[/{sev_color}]",
            border_style=sev_color,
        ))


@app.command(name="audit")
def audit_command(
    trace_file: Path = typer.Argument(..., help="Trace JSON file to audit."),
    json_output: bool = typer.Option(False, "--json", help="Output security audit as JSON."),
) -> None:
    """Audit trace for credential file access, sensitive token reads, and data exfiltration."""
    if not trace_file.exists():
        console.print(f"[red]Error:[/] Trace file '{trace_file}' not found.")
        raise typer.Exit(1)

    with open(trace_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    events = [SyscallEvent.from_dict(e) for e in data.get("events", [])]

    auditor = SecurityAuditor()
    rep = auditor.audit(events)

    if json_output:
        console.print_json(json.dumps(rep.to_dict()))
        return

    sev_color = "green" if rep.risk_level == "CLEAN" else ("yellow" if rep.risk_level in ("LOW", "MEDIUM") else "red")
    console.print(Panel(
        f"Risk Level: [bold {sev_color}]{rep.risk_level}[/bold {sev_color}]\n"
        f"Risk Score: [bold {sev_color}]{rep.risk_score} / 100[/bold {sev_color}]\n"
        f"Total Findings: [bold]{rep.total_findings}[/bold]\n"
        f"Exfiltration Suspects: [bold]{len(rep.exfiltration_suspects)}[/bold]",
        title="Security & Sandbox Audit",
        border_style=sev_color,
    ))

    if rep.findings:
        table = Table(title="Security Findings")
        table.add_column("Severity", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Target", style="yellow")
        table.add_column("PID", style="white")

        for f in rep.findings:
            f_color = "red" if f.severity == "CRITICAL" else ("yellow" if f.severity == "HIGH" else "white")
            table.add_row(f"[{f_color}]{f.severity}[/{f_color}]", f.title, f.target, str(f.event.pid))

        console.print(table)


@app.command(name="assert", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def assert_command(
    ctx: typer.Context,
    no_missing_configs: bool = typer.Option(False, "--no-missing-configs", help="Fail if any configuration file lookups fail with ENOENT."),
    no_unencrypted_http: bool = typer.Option(False, "--no-unencrypted-http", help="Fail if unencrypted outbound HTTP connections (port 80) occur."),
    max_latency_ms: Optional[float] = typer.Option(None, "--max-latency-ms", help="Fail if any syscall exceeds latency limit."),
    max_errors: int = typer.Option(0, "--max-errors", help="Maximum allowable error budget (default: 0)."),
    output_json: Optional[Path] = typer.Option(None, "--output-json", help="Export trace to JSON on exit."),
) -> None:
    """Execute command in CI/CD mode and assert operational, performance, and security policies."""
    cmd_args = ctx.args
    if not cmd_args:
        console.print("[bold red]Error:[/bold red] No command provided. Usage: `proctrace assert [OPTIONS] -- <cmd>`")
        raise typer.Exit(1)

    ring_buffer = RingBuffer(capacity=500_000)
    runner = SubprocessRunner(
        command=cmd_args,
        ring_buffer=ring_buffer,
        capture_output=True,
    )

    exit_code = runner.run()
    events = ring_buffer.get_all()

    guard = PolicyGuard(
        no_missing_configs=no_missing_configs,
        no_unencrypted_http=no_unencrypted_http,
        max_latency_ms=max_latency_ms,
        max_error_count=max_errors,
    )
    result = guard.evaluate(events)

    if output_json:
        export_to_json(events, output_json)

    if result.passed and exit_code == 0:
        console.print(f"[bold green][PASS] All policies passed successfully.[/bold green] (Command exited with code {exit_code})")
        raise typer.Exit(0)
    else:
        console.print(f"[bold red][FAIL] CI Policy Assertion Failed![/bold red] ({result.total_violations} violation(s))")
        for v in result.violations:
            console.print(f"  [red]* [{v.policy_name}][/red] {v.message} (Target: {v.target})")
        raise typer.Exit(1)

