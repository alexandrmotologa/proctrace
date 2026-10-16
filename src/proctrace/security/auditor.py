"""Security auditing, sensitive path inspection, and CI/CD policy enforcement."""

from __future__ import annotations

import collections
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from proctrace.core.models import EventCategory, EventOperation, EventResult, SyscallEvent

# Known sensitive files and credential paths
SENSITIVE_PATTERNS = [
    (r"(\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|id_dsa))", "SSH Private Key", "CRITICAL"),
    (r"(\.aws[\\/](?:credentials|config))", "AWS Cloud Credentials", "CRITICAL"),
    (r"(\.azure[\\/].*)", "Azure Cloud Credentials", "HIGH"),
    (r"(\.kube[\\/]config)", "Kubernetes Cluster Config", "CRITICAL"),
    (r"(\.docker[\\/]config\.json)", "Docker Registry Credentials", "HIGH"),
    (r"(\.npmrc|\.pypirc)", "Package Registry Auth Tokens", "HIGH"),
    (r"(\.git-credentials|\.gitconfig)", "Git Credentials", "MEDIUM"),
    (r"(/etc/shadow|/etc/sudoers)", "System Secrets / Sudoers", "CRITICAL"),
    (r"(Windows[\\/]System32[\\/]config[\\/]SAM)", "Windows SAM Registry Hive", "CRITICAL"),
    (r"(\.kdbx|\.1password|\.vault)", "Encrypted Password Database", "HIGH"),
]


@dataclass
class SecurityFinding:
    """A detected security risk or policy violation."""

    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    target: str
    description: str
    event: SyscallEvent
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAuditReport:
    """Overall security posture evaluation of the monitored process execution."""

    risk_score: int  # 0 to 100
    risk_level: str  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    total_findings: int
    findings: List[SecurityFinding] = field(default_factory=list)
    exfiltration_suspects: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert security report to dictionary."""
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_findings": self.total_findings,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "target": f.target,
                    "description": f.description,
                    "pid": f.event.pid,
                    "process_name": f.event.process_name,
                    "timestamp": f.event.timestamp,
                    "details": f.details,
                }
                for f in self.findings
            ],
            "exfiltration_suspects": self.exfiltration_suspects,
        }


class SecurityAuditor:
    """Audits system call activity to detect credential access and data exfiltration."""

    def __init__(self, exfiltration_window_seconds: float = 5.0) -> None:
        self.exfiltration_window = exfiltration_window_seconds

    def audit(self, events: Sequence[SyscallEvent]) -> SecurityAuditReport:
        """Evaluate events against security threat heuristics."""
        findings: List[SecurityFinding] = []
        sensitive_reads: List[SyscallEvent] = []
        exfiltration_suspects: List[Dict[str, Any]] = []

        # 1. Detect sensitive file access
        for ev in events:
            if ev.category == EventCategory.FILESYSTEM and ev.operation in (EventOperation.OPEN, EventOperation.READ):
                path = ev.target_path or ""
                for pattern, desc, sev in SENSITIVE_PATTERNS:
                    if re.search(pattern, path, re.IGNORECASE):
                        finding = SecurityFinding(
                            rule_id="sensitive_credential_access",
                            severity=sev,
                            title=f"Access to {desc}",
                            target=path,
                            description=f"Process '{ev.process_name}' (PID {ev.pid}) accessed sensitive path: {path}",
                            event=ev,
                            details={"credential_type": desc},
                        )
                        findings.append(finding)
                        sensitive_reads.append(ev)
                        break

        # 2. Exfiltration heuristic: Sensitive read followed by external network connection
        for s_ev in sensitive_reads:
            for net_ev in events:
                if (
                    net_ev.pid == s_ev.pid
                    and net_ev.category == EventCategory.NETWORK
                    and net_ev.operation == EventOperation.CONNECT
                    and (0.0 <= (net_ev.timestamp - s_ev.timestamp) <= self.exfiltration_window)
                ):
                    # Check if destination is not loopback
                    dest = net_ev.target_path or ""
                    if not (dest.startswith("127.") or dest.startswith("localhost") or dest.startswith("0.0.0.0")):
                        suspect = {
                            "pid": s_ev.pid,
                            "process_name": s_ev.process_name,
                            "sensitive_file": s_ev.target_path,
                            "remote_endpoint": dest,
                            "time_delta_seconds": round(net_ev.timestamp - s_ev.timestamp, 3),
                        }
                        exfiltration_suspects.append(suspect)
                        findings.append(
                            SecurityFinding(
                                rule_id="potential_data_exfiltration",
                                severity="CRITICAL",
                                title="Potential Credential Exfiltration Detected",
                                target=f"{s_ev.target_path} -> {dest}",
                                description=(
                                    f"Process '{s_ev.process_name}' read sensitive credential '{s_ev.target_path}' "
                                    f"and initiated outbound network connection to '{dest}' "
                                    f"{suspect['time_delta_seconds']}s later."
                                ),
                                event=net_ev,
                                details=suspect,
                            )
                        )

        # Calculate risk score
        score = 0
        for f in findings:
            if f.severity == "CRITICAL":
                score += 35
            elif f.severity == "HIGH":
                score += 20
            elif f.severity == "MEDIUM":
                score += 10
            elif f.severity == "LOW":
                score += 5

        score = min(100, score)
        level = "CLEAN"
        if score >= 70:
            level = "CRITICAL"
        elif score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"

        return SecurityAuditReport(
            risk_score=score,
            risk_level=level,
            total_findings=len(findings),
            findings=findings,
            exfiltration_suspects=exfiltration_suspects,
        )


@dataclass
class PolicyViolation:
    """Represents a failed CI/CD policy requirement."""

    policy_name: str
    target: str
    message: str
    event: SyscallEvent


@dataclass
class PolicyEvaluationResult:
    """Result of policy verification check."""

    passed: bool
    total_violations: int
    violations: List[PolicyViolation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "passed": self.passed,
            "total_violations": self.total_violations,
            "violations": [
                {
                    "policy_name": v.policy_name,
                    "target": v.target,
                    "message": v.message,
                    "pid": v.event.pid,
                    "process_name": v.event.process_name,
                }
                for v in self.violations
            ],
        }


class PolicyGuard:
    """Validates execution traces against operational and compliance policies."""

    def __init__(
        self,
        no_missing_configs: bool = False,
        no_unencrypted_http: bool = False,
        max_latency_ms: Optional[float] = None,
        allowed_paths: Optional[List[str]] = None,
        blocked_paths: Optional[List[str]] = None,
        max_error_count: int = 0,
    ) -> None:
        self.no_missing_configs = no_missing_configs
        self.no_unencrypted_http = no_unencrypted_http
        self.max_latency_ms = max_latency_ms
        self.allowed_paths = [p.lower() for p in allowed_paths] if allowed_paths else None
        self.blocked_paths = [p.lower() for p in blocked_paths] if blocked_paths else None
        self.max_error_count = max_error_count

    def evaluate(self, events: Sequence[SyscallEvent]) -> PolicyEvaluationResult:
        """Audit events against configured policy invariants."""
        violations: List[PolicyViolation] = []
        error_count = 0

        for ev in events:
            path_lower = (ev.target_path or "").lower()

            # 1. Error budget
            if ev.is_error:
                error_count += 1

            # 2. No missing configs
            if self.no_missing_configs:
                if ev.result == EventResult.FAILED_NOT_FOUND or ev.errno_name in ("ENOENT", "ERROR_FILE_NOT_FOUND"):
                    if any(path_lower.endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf")):
                        violations.append(
                            PolicyViolation(
                                policy_name="no_missing_configs",
                                target=ev.target_path,
                                message=f"Required configuration file was not found: {ev.target_path}",
                                event=ev,
                            )
                        )

            # 3. No unencrypted HTTP (port 80)
            if self.no_unencrypted_http:
                if ev.category == EventCategory.NETWORK and ev.operation == EventOperation.CONNECT:
                    if path_lower.endswith(":80") and not (path_lower.startswith("127.") or path_lower.startswith("localhost")):
                        violations.append(
                            PolicyViolation(
                                policy_name="no_unencrypted_http",
                                target=ev.target_path,
                                message=f"Unencrypted HTTP connection attempted to remote endpoint: {ev.target_path}",
                                event=ev,
                            )
                        )

            # 4. Maximum latency limit
            if self.max_latency_ms is not None:
                max_us = self.max_latency_ms * 1000.0
                if ev.duration_us > max_us:
                    violations.append(
                        PolicyViolation(
                            policy_name="max_latency",
                            target=ev.target_path,
                            message=f"Syscall latency {ev.duration_us/1000.0:.2f}ms exceeded limit of {self.max_latency_ms:.2f}ms",
                            event=ev,
                        )
                    )

            # 5. Blocked paths
            if self.blocked_paths:
                for blocked in self.blocked_paths:
                    if blocked in path_lower:
                        violations.append(
                            PolicyViolation(
                                policy_name="blocked_path_access",
                                target=ev.target_path,
                                message=f"Access to prohibited path: {ev.target_path}",
                                event=ev,
                            )
                        )

            # 6. Allowed path boundary
            if self.allowed_paths and ev.category == EventCategory.FILESYSTEM and ev.target_path:
                # Exclude Windows system files from allowed paths check to avoid false positives on system DLLs
                if not any(path_lower.startswith(prefix) for prefix in ("c:\\windows", "/usr/", "/lib/")):
                    is_allowed = any(path_lower.startswith(allowed) for allowed in self.allowed_paths)
                    if not is_allowed:
                        violations.append(
                            PolicyViolation(
                                policy_name="sandbox_boundary_violation",
                                target=ev.target_path,
                                message=f"Path outside allowed sandbox boundaries: {ev.target_path}",
                                event=ev,
                            )
                        )

        if error_count > self.max_error_count:
            violations.append(
                PolicyViolation(
                    policy_name="max_error_count",
                    target="session",
                    message=f"Total error count ({error_count}) exceeded error budget ({self.max_error_count})",
                    event=events[-1] if events else SyscallEvent(0, 0, "system", EventCategory.PROCESS, EventOperation.EXIT, "session"),
                )
            )

        passed = len(violations) == 0
        return PolicyEvaluationResult(passed=passed, total_violations=len(violations), violations=violations)
