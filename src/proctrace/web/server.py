"""FastAPI Web Studio backend with WebSockets and Chrome DevTools waterfall API."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from proctrace.analysis.explainer import RootCauseExplainer
from proctrace.core.diff import TraceDiffer
from proctrace.core.filter import AnomalyCorrelator, EventFilter
from proctrace.core.models import EventCategory, SyscallEvent, TraceSession
from proctrace.core.ring_buffer import RingBuffer
from proctrace.export.chrome_trace import export_to_chrome_trace
from proctrace.export.csv_export import export_to_csv
from proctrace.export.json_export import export_to_json
from proctrace.security.auditor import SecurityAuditor

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    ring_buffer: RingBuffer,
    session: Optional[TraceSession] = None,
) -> FastAPI:
    """Create and configure the FastAPI web studio application."""
    app = FastAPI(title="ProcTrace Web Studio", version="0.1.0")

    # Mount static assets
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Active WebSocket clients
    active_connections: List[WebSocket] = []
    lock = asyncio.Lock()

    @app.get("/", response_class=HTMLResponse)
    async def get_index() -> Response:
        """Serve the waterfall web studio single-page application."""
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return HTMLResponse("<h1>ProcTrace Web Studio</h1><p>Static assets missing.</p>")

    @app.get("/api/events")
    async def get_events(
        offset: int = Query(0, ge=0),
        limit: int = Query(500, ge=1, le=5000),
        pid: Optional[int] = None,
        category: Optional[str] = None,
        errors_only: bool = False,
        search: Optional[str] = None,
        min_duration_us: float = 0.0,
    ) -> Dict[str, Any]:
        """Query captured events with filtering and pagination."""
        all_events = ring_buffer.get_all()

        cat_enum = None
        if category and category.upper() != "ALL":
            try:
                cat_enum = EventCategory(category.upper())
            except ValueError:
                pass

        flt = EventFilter(
            categories=[cat_enum] if cat_enum else None,
            errors_only=errors_only,
            target_pids=[pid] if pid else None,
            path_pattern=search,
            min_duration_us=min_duration_us,
        )

        filtered = flt.filter_events(all_events)
        total_filtered = len(filtered)
        sliced = filtered[offset : offset + limit]

        return {
            "total": total_filtered,
            "offset": offset,
            "limit": limit,
            "events": [e.to_dict() for e in sliced],
        }

    @app.get("/api/stats")
    async def get_stats() -> Dict[str, Any]:
        """Retrieve real-time buffer telemetry and metrics."""
        stats = ring_buffer.get_stats()
        events = ring_buffer.get_all()
        unique_paths = len({e.target_path for e in events if e.target_path})
        unique_pids = len({e.pid for e in events})
        max_duration = max((e.duration_us for e in events), default=0.0)

        stats["unique_paths"] = unique_paths
        stats["unique_pids"] = unique_pids
        stats["max_duration_us"] = max_duration
        return stats

    @app.get("/api/anomalies")
    async def get_anomalies() -> Dict[str, Any]:
        """Compute anomaly correlation and failure diagnosis report."""
        events = ring_buffer.get_all()
        correlator = AnomalyCorrelator()
        report = correlator.correlate(events)
        return report.to_dict()

    @app.get("/api/explanations")
    async def get_explanations() -> List[Dict[str, Any]]:
        """Compute root-cause explanations and suggested remediations."""
        events = ring_buffer.get_all()
        explainer = RootCauseExplainer()
        findings = explainer.explain(events)
        return [f.to_dict() for f in findings]

    @app.get("/api/security")
    async def get_security_audit() -> Dict[str, Any]:
        """Audit trace for credential access and potential exfiltration."""
        events = ring_buffer.get_all()
        auditor = SecurityAuditor()
        audit_rep = auditor.audit(events)
        return audit_rep.to_dict()

    @app.get("/api/tree")
    async def get_process_tree() -> List[Dict[str, Any]]:
        """Construct hierarchical process call tree."""
        events = ring_buffer.get_all()
        pids: Dict[int, Dict[str, Any]] = {}
        for ev in events:
            if ev.pid not in pids:
                pids[ev.pid] = {
                    "pid": ev.pid,
                    "ppid": ev.ppid,
                    "name": ev.process_name,
                    "event_count": 0,
                    "error_count": 0,
                    "first_seen": ev.timestamp,
                    "last_seen": ev.timestamp,
                    "children": [],
                }
            pids[ev.pid]["event_count"] += 1
            if ev.is_error:
                pids[ev.pid]["error_count"] += 1
            pids[ev.pid]["last_seen"] = max(pids[ev.pid]["last_seen"], ev.timestamp)

        roots = []
        for pid_val, info in pids.items():
            parent_pid = info["ppid"]
            if parent_pid and parent_pid in pids and parent_pid != pid_val:
                pids[parent_pid]["children"].append(info)
            else:
                roots.append(info)
        return roots

    @app.post("/api/diff")
    async def compute_trace_diff(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Compare uploaded candidate trace events against current ring buffer."""
        curr_events = ring_buffer.get_all()
        base_events_raw = payload.get("events", [])
        base_events = [SyscallEvent.from_dict(e) for e in base_events_raw]
        differ = TraceDiffer()
        diff_report = differ.compare(base_events, curr_events)
        return diff_report.to_dict()

    @app.post("/api/clear")
    async def clear_buffer() -> Dict[str, str]:
        """Clear all events in the ring buffer."""
        ring_buffer.clear()
        return {"status": "cleared"}

    @app.get("/api/export/{fmt}")
    async def export_trace(fmt: str) -> Response:
        """Download recorded trace in JSON, CSV, or Chrome Trace format."""
        events = ring_buffer.get_all()
        fmt = fmt.lower()

        if fmt == "csv":
            content = export_to_csv(events)
            return Response(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=proctrace.csv"},
            )
        elif fmt in ("chrome", "perfetto"):
            content = export_to_chrome_trace(events)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=proctrace_perfetto.json"},
            )
        else:
            content = export_to_json(events, session=session)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=proctrace.json"},
            )

    @app.websocket("/ws/live")
    async def websocket_live_stream(websocket: WebSocket) -> None:
        """Stream live events over WebSocket to connected browser clients."""
        await websocket.accept()
        async with lock:
            active_connections.append(websocket)

        last_timestamp = 0.0

        try:
            while True:
                # Poll ring buffer for new events since last check
                events = ring_buffer.get_since(last_timestamp)
                if events:
                    # Update bookmark to the latest event timestamp plus microsecond epsilon
                    last_timestamp = max(e.timestamp for e in events) + 0.000001
                    payload = {
                        "type": "batch",
                        "events": [e.to_dict() for e in events[-200:]],  # Throttle burst to 200/frame
                        "stats": ring_buffer.get_stats(),
                    }
                    await websocket.send_json(payload)

                await asyncio.sleep(0.05)  # 20 fps push rate
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        finally:
            async with lock:
                if websocket in active_connections:
                    active_connections.remove(websocket)

    return app
