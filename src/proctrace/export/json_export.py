"""Export captured syscall events to formatted JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from proctrace.core.models import SyscallEvent, TraceSession


def export_to_json(
    events: Sequence[SyscallEvent],
    output_path: Optional[Union[str, Path]] = None,
    session: Optional[TraceSession] = None,
    indent: int = 2,
) -> str:
    """Serialize events and session metadata to a JSON string or file."""
    data: Dict[str, Any] = {
        "format": "proctrace-trace-v1",
        "session": session.to_dict() if session else None,
        "total_events": len(events),
        "error_count": sum(1 for e in events if e.is_error),
        "events": [event.to_dict() for event in events],
    }

    json_str = json.dumps(data, indent=indent, default=str)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
