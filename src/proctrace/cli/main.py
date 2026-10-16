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
