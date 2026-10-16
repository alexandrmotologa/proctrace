"""Automated root-cause diagnostic engine and actionable remediation recommender."""

from __future__ import annotations

import collections
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from proctrace.core.models import EventCategory, EventOperation, EventResult, SyscallEvent

# Standard database and service default ports
KNOWN_PORT_SERVICES: Dict[int, Tuple[str, str, str]] = {
    5432: ("PostgreSQL", "PostgreSQL database server", "systemctl status postgresql || docker ps | grep postgres"),
    3306: ("MySQL/MariaDB", "MySQL database server", "systemctl status mysql || docker ps | grep mysql"),
    6379: ("Redis", "Redis cache/queue broker", "systemctl status redis || docker ps | grep redis"),
    27017: ("MongoDB", "MongoDB document store", "systemctl status mongod || docker ps | grep mongo"),
    8000: ("HTTP Backend", "Local HTTP development server", "Check if backend application or dev server is running on port 8000"),
    8080: ("HTTP Backend", "Local HTTP development server", "Check if service is running on port 8080"),
    3000: ("Node/Frontend Server", "Node.js or React development server", "npm run dev or check port 3000 listeners"),
    9200: ("Elasticsearch", "Elasticsearch search cluster", "curl -I http://localhost:9200"),
    5672: ("RabbitMQ", "RabbitMQ message broker", "systemctl status rabbitmq-server"),
}

# Known library package dependencies
KNOWN_LIBRARY_PACKAGES: Dict[str, Dict[str, str]] = {
    "libssl": {
        "linux": "apt install libssl-dev || yum install openssl-devel",
        "macos": "brew install openssl",
        "windows": "Install OpenSSL binaries or build tools",
    },
    "libcrypto": {
        "linux": "apt install libssl-dev || yum install openssl-devel",
        "macos": "brew install openssl",
        "windows": "Install OpenSSL binaries",
    },
    "vcruntime140": {
        "linux": "N/A (Windows binary running under Wine requires wine-mono/wine-gecko)",
        "macos": "N/A",
        "windows": "Install Microsoft Visual C++ 2015-2022 Redistributable (x64)",
    },
    "msvcp140": {
        "linux": "N/A",
        "macos": "N/A",
        "windows": "Install Microsoft Visual C++ 2015-2022 Redistributable (x64)",
    },
    "libpq": {
        "linux": "apt install libpq-dev || yum install postgresql-devel",
        "macos": "brew install libpq",
        "windows": "Install PostgreSQL client tools",
    },
    "libsqlite3": {
        "linux": "apt install libsqlite3-dev",
        "macos": "brew install sqlite",
        "windows": "Download sqlite3.dll and place in PATH",
    },
}


@dataclass
class DiagnosticExplanation:
    """An explained root cause with concrete remediation steps."""

    rule_name: str
    title: str
    severity: str  # CRITICAL, WARNING, INFO
    target: str
    root_cause: str
    remediation_steps: List[str]
    evidence_events: List[SyscallEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert explanation to dictionary."""
        return {
            "rule_name": self.rule_name,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "root_cause": self.root_cause,
            "remediation_steps": self.remediation_steps,
            "evidence_count": len(self.evidence_events),
        }


class RootCauseExplainer:
    """Analyzes intercepted failures and produces actionable remediation guidance."""

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None) -> None:
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()

    def explain(self, events: Sequence[SyscallEvent]) -> List[DiagnosticExplanation]:
        """Scan event sequence and deduce root cause explanations."""
        explanations: List[DiagnosticExplanation] = []

        # Group failures by target
        missing_files: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)
        conn_refused: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)
        access_denied: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)

        for ev in events:
            if ev.result == EventResult.FAILED_NOT_FOUND or ev.errno_name in ("ENOENT", "ERROR_FILE_NOT_FOUND", "ERROR_PATH_NOT_FOUND"):
                if ev.target_path:
                    missing_files[ev.target_path].append(ev)
            elif ev.result == EventResult.FAILED_CONN_REFUSED or ev.errno_name in ("ECONNREFUSED", "WSAECONNREFUSED"):
                if ev.target_path:
                    conn_refused[ev.target_path].append(ev)
            elif ev.result == EventResult.FAILED_ACCESS_DENIED or ev.errno_name in ("EACCES", "EPERM", "ERROR_ACCESS_DENIED"):
                if ev.target_path:
                    access_denied[ev.target_path].append(ev)

        # 1. Evaluate missing configuration files
        for target, sample_events in missing_files.items():
            base_name = os.path.basename(target).lower()

            # Check if this is an environment file
            if base_name in (".env", ".env.local", ".env.production", ".env.development", "config.json", "settings.yaml"):
                remediations = []
                dir_path = os.path.dirname(target) or str(self.workspace_root)

                # Check if template files exist on disk
                example_files = [".env.example", ".env.template", ".env.sample", ".env.defaults"]
                found_template = None
                for candidate in example_files:
                    full_cand = os.path.join(dir_path, candidate)
                    if os.path.exists(full_cand):
                        found_template = candidate
                        break

                if found_template:
                    remediations.append(f"Copy the existing template file: `cp {found_template} {base_name}`")
                else:
                    remediations.append(f"Create a `{base_name}` file in `{dir_path}` with required variables.")
                remediations.append("Alternatively, inject configuration via process environment variables in Docker, CI, or shell.")

                explanations.append(
                    DiagnosticExplanation(
                        rule_name="missing_config_file",
                        title=f"Missing Environment/Config File: {base_name}",
                        severity="CRITICAL",
                        target=target,
                        root_cause=f"The process attempted to read '{target}' ({len(sample_events)} times), but the file does not exist on disk.",
                        remediation_steps=remediations,
                        evidence_events=sample_events,
                    )
                )

            # Check if this is a missing shared library / DLL
            elif any(base_name.endswith(ext) for ext in (".so", ".dll", ".dylib")) or ".so." in base_name:
                lib_match = None
                for key in KNOWN_LIBRARY_PACKAGES:
                    if key in base_name:
                        lib_match = key
                        break

                remediations = []
                if lib_match:
                    pkg_info = KNOWN_LIBRARY_PACKAGES[lib_match]
                    remediations.append(f"Install package on Linux: `{pkg_info.get('linux', 'Check package manager')}`")
                    remediations.append(f"Install on macOS: `{pkg_info.get('macos', 'brew install ...')}`")
                    remediations.append(f"Install on Windows: `{pkg_info.get('windows', 'Install Visual C++ or runtime DLL')}`")
                else:
                    remediations.append(f"Ensure the library containing `{base_name}` is installed and present in LD_LIBRARY_PATH, PATH, or system library directories.")

                explanations.append(
                    DiagnosticExplanation(
                        rule_name="missing_dynamic_library",
                        title=f"Missing Dynamic Shared Library: {base_name}",
                        severity="CRITICAL",
                        target=target,
                        root_cause=f"Dynamic linker failed to locate library '{base_name}' when loading process executable or modules.",
                        remediation_steps=remediations,
                        evidence_events=sample_events,
                    )
                )

        # 2. Evaluate connection refused errors
        for target, sample_events in conn_refused.items():
            port_match = re.search(r":(\d+)$", target)
            port_num = int(port_match.group(1)) if port_match else None

            service_info = KNOWN_PORT_SERVICES.get(port_num) if port_num else None
            remediations = []

            if service_info:
                svc_name, svc_desc, svc_cmd = service_info
                remediations.append(f"Verify that {svc_name} is running: `{svc_cmd}`")
                remediations.append(f"Confirm that the server is listening on {target} and not only on a different network interface (e.g. 127.0.0.1 vs 0.0.0.0).")
                remediations.append("Check firewall or security group rules if connecting across hosts.")

                explanations.append(
                    DiagnosticExplanation(
                        rule_name="connection_refused_known_service",
                        title=f"Connection Refused by {svc_name} ({target})",
                        severity="CRITICAL",
                        target=target,
                        root_cause=f"Attempted TCP connection to {svc_desc} on port {port_num} was rejected ({len(sample_events)} attempts). The service is likely stopped or not listening.",
                        remediation_steps=remediations,
                        evidence_events=sample_events,
                    )
                )
            else:
                remediations.append(f"Check if any application is actively listening on {target}: `lsof -i :{port_num or ''}` or `netstat -ano`")
                remediations.append("Ensure the host address is reachable and not blocked by firewall or proxy.")

                explanations.append(
                    DiagnosticExplanation(
                        rule_name="connection_refused_generic",
                        title=f"Network Connection Refused: {target}",
                        severity="WARNING",
                        target=target,
                        root_cause=f"Socket connection to destination {target} was actively refused by the target host or local networking stack.",
                        remediation_steps=remediations,
                        evidence_events=sample_events,
                    )
                )

        # 3. Evaluate permission denied errors
        for target, sample_events in access_denied.items():
            remediations = [
                f"Check file permissions and ownership: `ls -la '{target}'`",
                f"Grant read/write permissions if appropriate: `chmod u+rw '{target}'`",
                "Ensure the process runs with adequate system privileges (e.g. elevated or user permissions matching file owner).",
            ]

            explanations.append(
                DiagnosticExplanation(
                    rule_name="permission_denied",
                    title=f"Access Denied (EACCES / EPERM): {target}",
                    severity="CRITICAL",
                    target=target,
                    root_cause=f"The operating system denied access to '{target}' for PID {sample_events[0].pid} ({len(sample_events)} attempts).",
                    remediation_steps=remediations,
                    evidence_events=sample_events,
                )
            )

        return explanations
