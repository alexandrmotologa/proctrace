"""Export syscall traces in Chrome Trace Event Format for Perfetto and chrome://tracing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from proctrace.core.models import SyscallEvent


def export_to_chrome_trace(
    events: Sequence[SyscallEvent],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Format events as Chrome Trace Event Format JSON for Perfetto or chrome://tracing."""
    trace_events: List[Dict[str, Any]] = []

    # Find earliest timestamp to normalize timestamps relative to start
    base_ts = min((e.timestamp for e in events), default=0.0)

    # Process and thread metadata events
    pids_seen = set()
    for ev in events:
        if ev.pid not in pids_seen:
            pids_seen.add(ev.pid)
            trace_events.append(
                {
                    "name": "process_name",
                    "ph": "M",
                    "pid": ev.pid,
                    "tid": 0,
                    "args": {"name": f"{ev.process_name} (PID {ev.pid})"},
                }
            )

    for ev in events:
        # Microseconds relative to trace start
        ts_us = int((ev.timestamp - base_ts) * 1_000_000.0)
        dur_us = max(1.0, ev.duration_us)

        name = f"{ev.operation.value} {ev.target_path}"
        if len(name) > 80:
            name = name[:77] + "..."

        event_dict: Dict[str, Any] = {
            "name": name,
            "cat": ev.category.value,
            "ph": "X",  # Complete event with duration
            "ts": ts_us,
            "dur": dur_us,
            "pid": ev.pid,
            "tid": ev.tid if ev.tid is not None else 1,
            "args": {
                "id": ev.id,
                "operation": ev.operation.value,
                "target": ev.target_path,
                "result": ev.result.value,
                "return_code": ev.return_code,
                "errno": ev.errno_name,
                "is_error": ev.is_error,
                **ev.details,
            },
        }

        # Color indication in chrome://tracing
        if ev.is_error:
            event_dict["cname"] = "terrible"  # Red

        trace_events.append(event_dict)

    result = {
        "traceEvents": trace_events,
        "displayTimeUnit": "ms",
        "metadata": {
            "source": "ProcTrace",
            "version": "0.1.0",
        },
    }

    json_str = json.dumps(result, indent=2)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
