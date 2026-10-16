"""Generate humanized Markdown incident triage summaries from syscall traces."""

from __future__ import annotations

import collections
from pathlib import Path
from typing import Optional, Sequence, Union

from proctrace.core.filter import AnomalyCorrelator
from proctrace.core.models import SyscallEvent, TraceSession


def export_to_markdown_report(
    events: Sequence[SyscallEvent],
    output_path: Optional[Union[str, Path]] = None,
    session: Optional[TraceSession] = None,
) -> str:
    """Compile trace events into an incident triage report."""
    correlator = AnomalyCorrelator()
    anomalies = correlator.correlate(events)

    total_events = len(events)
    error_events = sum(1 for e in events if e.is_error)
    pids = sorted({e.pid for e in events})

    # Category counts
    cat_counts = collections.Counter(e.category.value for e in events)

    lines = [
        "# ProcTrace Incident Triage Report",
        "",
        "## Summary",
        "",
        f"- Total Events: {total_events}",
        f"- Failed Operations: {error_events}",
        f"- Monitored PIDs: {', '.join(str(p) for p in pids)}",
    ]

    if session and session.target_cmd:
        lines.append(f"- Command: `{session.target_cmd}`")
    if session:
        lines.append(f"- Duration: {session.duration_seconds:.2f} seconds")

    lines.extend([
        "",
        "## Event Breakdown by Category",
        "",
        "| Category | Event Count | Percentage |",
        "|---|---|---|",
    ])

    for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / max(1, total_events)) * 100.0
        lines.append(f"| {cat} | {count} | {pct:.1f}% |")

    # Missing files section
    if anomalies.missing_files:
        lines.extend([
            "",
            "## Missing Files and Broken Paths (ENOENT)",
            "",
            "| Missing Path | Attempts | Classification |",
            "|---|---|---|",
        ])
        for item in anomalies.missing_files[:20]:
            is_cfg = item.details.get("is_config", False)
            is_lib = item.details.get("is_lib", False)
            kind = "Configuration File" if is_cfg else ("Dynamic Library" if is_lib else "File / Directory")
            lines.append(f"| `{item.target}` | {item.count} | {kind} |")

    # Access Denied section
    if anomalies.access_denied:
        lines.extend([
            "",
            "## Permission Denials (EACCES)",
            "",
            "| Target Path | Attempts |",
            "|---|---|",
        ])
        for item in anomalies.access_denied[:20]:
            lines.append(f"| `{item.target}` | {item.count} |")

    # Failed network connections
    if anomalies.failed_connections:
        lines.extend([
            "",
            "## Failed Network Connections",
            "",
            "| Destination | Attempts | Error Status |",
            "|---|---|---|",
        ])
        for item in anomalies.failed_connections[:20]:
            lines.append(f"| `{item.target}` | {item.count} | {item.details.get('result', 'FAILED')} |")

    # Slowest syscalls
    if anomalies.slow_syscalls:
        lines.extend([
            "",
            "## Latency Bottlenecks (Slowest System Calls)",
            "",
            "| Operation | Target | Latency | PID |",
            "|---|---|---|---|",
        ])
        for item in anomalies.slow_syscalls[:15]:
            dur = item.details.get("duration_us", 0.0)
            dur_str = f"{dur / 1000.0:.2f} ms" if dur >= 1000.0 else f"{dur:.1f} us"
            lines.append(f"| {item.details.get('operation')} | `{item.target}` | {dur_str} | {item.details.get('pid')} |")

    content = "\n".join(lines) + "\n"

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(content)

    return content
