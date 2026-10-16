"""Unit tests for the root-cause explainer and remediation recommender."""

from proctrace.analysis.explainer import RootCauseExplainer
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)


def test_explainer_missing_config():
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=500,
            process_name="node",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path="app/.env",
            result=EventResult.FAILED_NOT_FOUND,
            errno_name="ENOENT",
        )
    ]

    explainer = RootCauseExplainer()
    findings = explainer.explain(events)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_name == "missing_config_file"
    assert f.severity == "CRITICAL"
    assert "app/.env" in f.target
    assert any(".env" in step for step in f.remediation_steps)


def test_explainer_known_service_refused():
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=500,
            process_name="python",
            category=EventCategory.NETWORK,
            operation=EventOperation.CONNECT,
            target_path="127.0.0.1:5432",
            result=EventResult.FAILED_CONN_REFUSED,
            errno_name="ECONNREFUSED",
        )
    ]

    explainer = RootCauseExplainer()
    findings = explainer.explain(events)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_name == "connection_refused_known_service"
    assert "PostgreSQL" in f.title
    assert any("postgres" in step.lower() for step in f.remediation_steps)


def test_explainer_missing_shared_lib():
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=500,
            process_name="ruby",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path="/usr/lib/libssl.so.1.1",
            result=EventResult.FAILED_NOT_FOUND,
            errno_name="ENOENT",
        )
    ]

    explainer = RootCauseExplainer()
    findings = explainer.explain(events)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_name == "missing_dynamic_library"
    assert any("libssl-dev" in step for step in f.remediation_steps)
