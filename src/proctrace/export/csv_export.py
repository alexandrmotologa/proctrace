"""Export captured syscall events to comma-separated values (CSV)."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Optional, Sequence, Union

from proctrace.core.models import SyscallEvent

CSV_HEADERS = [
    "id",
    "timestamp",
    "pid",
    "ppid",
    "tid",
    "process_name",
    "category",
    "operation",
    "target_path",
    "result",
    "duration_us",
    "return_code",
    "errno_name",
    "is_error",
]


def export_to_csv(
    events: Sequence[SyscallEvent],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Format events as CSV and write to file or return as string."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_HEADERS)

    for ev in events:
        writer.writerow(
            [
                ev.id,
                f"{ev.timestamp:.6f}",
                ev.pid,
                ev.ppid if ev.ppid is not None else "",
                ev.tid if ev.tid is not None else "",
                ev.process_name,
                ev.category.value,
                ev.operation.value,
                ev.target_path,
                ev.result.value,
                f"{ev.duration_us:.2f}",
                ev.return_code if ev.return_code is not None else "",
                ev.errno_name or "",
                "true" if ev.is_error else "false",
            ]
        )

    content = buf.getvalue()

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(content)

    return content
