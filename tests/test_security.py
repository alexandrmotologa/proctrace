"""Unit tests for the security auditor and policy guard."""

from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.security.auditor import PolicyGuard, SecurityAuditor


def test_security_auditor_credential_access():
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=777,
            process_name="untrusted_script",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.READ,
            target_path="/home/user/.ssh/id_rsa",
            result=EventResult.SUCCESS,
        )
    ]

    auditor = SecurityAuditor()
    report = auditor.audit(events)

    assert report.risk_score >= 35
    assert report.risk_level in ("MEDIUM", "HIGH", "CRITICAL")
    assert len(report.findings) == 1
    assert "SSH Private Key" in report.findings[0].title


def test_security_auditor_data_exfiltration():
    # Process reads sensitive aws credentials and immediately connects to external IP
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=888,
            process_name="malicious_package",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.READ,
            target_path="C:\\Users\\dev\\.aws\\credentials",
            result=EventResult.SUCCESS,
        ),
        SyscallEvent(
            timestamp=101.5,
            pid=888,
            process_name="malicious_package",
            category=EventCategory.NETWORK,
            operation=EventOperation.CONNECT,
            target_path="198.51.100.24:8080",
            result=EventResult.SUCCESS,
        ),
    ]

    auditor = SecurityAuditor(exfiltration_window_seconds=5.0)
    report = auditor.audit(events)

    assert len(report.exfiltration_suspects) == 1
    assert report.exfiltration_suspects[0]["remote_endpoint"] == "198.51.100.24:8080"
    assert report.risk_level == "CRITICAL"


def test_policy_guard_enforcement():
    # Trace with an unencrypted HTTP connection and missing config
    events = [
        SyscallEvent(
            timestamp=100.0,
            pid=123,
            process_name="app",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path="/app/.env",
            result=EventResult.FAILED_NOT_FOUND,
            errno_name="ENOENT",
        ),
        SyscallEvent(
            timestamp=100.5,
            pid=123,
            process_name="app",
            category=EventCategory.NETWORK,
            operation=EventOperation.CONNECT,
            target_path="insecure-api.com:80",
            result=EventResult.SUCCESS,
        ),
        SyscallEvent(
            timestamp=101.0,
            pid=123,
            process_name="app",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.WRITE,
            target_path="data.db",
            result=EventResult.SUCCESS,
            duration_us=75_000.0,  # 75ms
        ),
    ]

    guard = PolicyGuard(
        no_missing_configs=True,
        no_unencrypted_http=True,
        max_latency_ms=50.0,
        max_error_count=0,
    )
    res = guard.evaluate(events)

    assert res.passed is False
    assert res.total_violations >= 3
    violation_names = [v.policy_name for v in res.violations]
    assert "no_missing_configs" in violation_names
    assert "no_unencrypted_http" in violation_names
    assert "max_latency" in violation_names
