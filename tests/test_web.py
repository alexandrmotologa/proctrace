"""Tests for the Web Studio FastAPI endpoints."""

from fastapi.testclient import TestClient
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer
from proctrace.web.server import create_app


def test_web_studio_endpoints():
    rb = RingBuffer(capacity=100)
    rb.append(
        SyscallEvent(
            timestamp=100.0,
            pid=123,
            process_name="test_worker",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path="/missing/config.yaml",
            result=EventResult.FAILED_NOT_FOUND,
            errno_name="ENOENT",
        )
    )

    app = create_app(ring_buffer=rb)
    client = TestClient(app)

    # 1. Main index
    res = client.get("/")
    assert res.status_code == 200
    assert "ProcTrace" in res.text

    # 2. Query events
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["events"][0]["target_path"] == "/missing/config.yaml"

    # 3. Stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.json()
    assert stats["total_ingested"] == 1
    assert stats["total_errors"] == 1

    # 4. Anomalies
    res = client.get("/api/anomalies")
    assert res.status_code == 200
    anomalies = res.json()
    assert len(anomalies["missing_files"]) == 1
    assert anomalies["missing_files"][0]["target"] == "/missing/config.yaml"

    # 5. Export endpoints
    res_json = client.get("/api/export/json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"].startswith("application/json")

    res_csv = client.get("/api/export/csv")
    assert res_csv.status_code == 200
    assert res_csv.headers["content-type"].startswith("text/csv")

    res_chrome = client.get("/api/export/chrome")
    assert res_chrome.status_code == 200
    assert "traceEvents" in res_chrome.json()

    # 6. Explanations
    res_exp = client.get("/api/explanations")
    assert res_exp.status_code == 200
    assert isinstance(res_exp.json(), list)

    # 7. Security audit
    res_sec = client.get("/api/security")
    assert res_sec.status_code == 200
    assert "risk_score" in res_sec.json()

    # 8. Process tree
    res_tree = client.get("/api/tree")
    assert res_tree.status_code == 200
    assert len(res_tree.json()) == 1
    assert res_tree.json()[0]["pid"] == 123

    # 9. Diff endpoint
    res_diff = client.post("/api/diff", json={"events": []})
    assert res_diff.status_code == 200
    assert "summary" in res_diff.json()

    # 10. Clear buffer
    res_clear = client.post("/api/clear")
    assert res_clear.status_code == 200
    assert rb.count == 0
