"""Event filtering rules, noise suppression, and anomaly correlation."""

from __future__ import annotations

import collections
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

import yaml

from proctrace.core.models import EventCategory, EventOperation, EventResult, SyscallEvent


# Standard operating system paths that often introduce noise into application traces
DEFAULT_SYSTEM_PATH_PREFIXES = (
    # Windows
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "c:\\windows\\assembly\\",
    "\\registry\\",
    # Linux
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/etc/ld.so.cache",
    "/etc/ld.so.nohwcap",
    "/proc/stat",
    "/sys/",
    # macOS
    "/system/library/",
    "/usr/lib/",
    "/library/apple/",
)


class EventFilter:
    """Configurable matching rule engine for syscall events."""

    def __init__(
        self,
        categories: Optional[Iterable[EventCategory]] = None,
        operations: Optional[Iterable[EventOperation]] = None,
        errors_only: bool = False,
        exclude_system: bool = False,
        target_pids: Optional[Iterable[int]] = None,
        include_extensions: Optional[Iterable[str]] = None,
        path_pattern: Optional[str] = None,
        min_duration_us: float = 0.0,
    ) -> None:
        self.categories: Optional[Set[EventCategory]] = set(categories) if categories else None
        self.operations: Optional[Set[EventOperation]] = set(operations) if operations else None
        self.errors_only: bool = errors_only
        self.exclude_system: bool = exclude_system
        self.target_pids: Optional[Set[int]] = set(target_pids) if target_pids else None
        self.include_extensions: Optional[Set[str]] = (
            {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in include_extensions}
            if include_extensions
            else None
        )
        self.path_pattern_str = path_pattern
        self.path_regex: Optional[re.Pattern] = re.compile(path_pattern, re.IGNORECASE) if path_pattern else None
        self.min_duration_us: float = min_duration_us

    def matches(self, event: SyscallEvent) -> bool:
        """Evaluate if the given event satisfies all active filter rules."""
        if self.errors_only and not event.is_error:
            return False

        if self.categories is not None and event.category not in self.categories:
            return False

        if self.operations is not None and event.operation not in self.operations:
            return False

        if self.target_pids is not None and event.pid not in self.target_pids:
            return False

        if self.min_duration_us > 0.0 and event.duration_us < self.min_duration_us:
            return False

        lower_path = (event.target_path or "").lower()

        if self.exclude_system:
            for sys_prefix in DEFAULT_SYSTEM_PATH_PREFIXES:
                if lower_path.startswith(sys_prefix) or sys_prefix in lower_path:
                    return False

        if self.include_extensions is not None:
            matches_ext = any(lower_path.endswith(ext) for ext in self.include_extensions)
            if not matches_ext:
                return False

        if self.path_regex is not None:
            if not self.path_regex.search(event.target_path):
                return False

        return True

    def filter_events(self, events: Iterable[SyscallEvent]) -> List[SyscallEvent]:
        """Apply filter over an iterable collection of events."""
        return [ev for ev in events if self.matches(ev)]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventFilter:
        """Construct filter from dictionary."""
        categories = None
        if "categories" in data and data["categories"]:
            categories = [
                EventCategory(c) if isinstance(c, str) else c
                for c in data["categories"]
            ]

        operations = None
        if "operations" in data and data["operations"]:
            operations = [
                EventOperation(o) if isinstance(o, str) else o
                for o in data["operations"]
            ]

        return cls(
            categories=categories,
            operations=operations,
            errors_only=bool(data.get("errors_only", False)),
            exclude_system=bool(data.get("exclude_system", False)),
            target_pids=data.get("target_pids"),
            include_extensions=data.get("include_extensions"),
            path_pattern=data.get("path_pattern"),
            min_duration_us=float(data.get("min_duration_us", 0.0)),
        )

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> EventFilter:
        """Load filter configuration from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)


@dataclass
class AnomalyItem:
    """A detected anomalous pattern or repeated failure."""

    kind: str  # MISSING_FILE, PERMISSION_DENIED, REFUSED_CONNECTION, SLOW_SYSCALL
    summary: str
    target: str
    count: int
    sample_event: SyscallEvent
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyReport:
    """Correlated report of errors, broken lookups, and latency outliers."""

    total_scanned: int = 0
    total_anomalies: int = 0
    missing_files: List[AnomalyItem] = field(default_factory=list)
    access_denied: List[AnomalyItem] = field(default_factory=list)
    failed_connections: List[AnomalyItem] = field(default_factory=list)
    slow_syscalls: List[AnomalyItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert anomaly report to dictionary."""
        return {
            "total_scanned": self.total_scanned,
            "total_anomalies": self.total_anomalies,
            "missing_files": [
                {
                    "target": item.target,
                    "count": item.count,
                    "summary": item.summary,
                    "details": item.details,
                }
                for item in self.missing_files
            ],
            "access_denied": [
                {
                    "target": item.target,
                    "count": item.count,
                    "summary": item.summary,
                    "details": item.details,
                }
                for item in self.access_denied
            ],
            "failed_connections": [
                {
                    "target": item.target,
                    "count": item.count,
                    "summary": item.summary,
                    "details": item.details,
                }
                for item in self.failed_connections
            ],
            "slow_syscalls": [
                {
                    "target": item.target,
                    "duration_us": item.details.get("duration_us", 0.0),
                    "summary": item.summary,
                }
                for item in self.slow_syscalls
            ],
        }


class AnomalyCorrelator:
    """Analyzes a stream of syscall events to diagnose root cause failures."""

    def __init__(self, slow_threshold_us: float = 10_000.0) -> None:
        self.slow_threshold_us = slow_threshold_us

    def correlate(self, events: Sequence[SyscallEvent]) -> AnomalyReport:
        """Scan events and build an anomaly triage report."""
        report = AnomalyReport(total_scanned=len(events))

        missing_map: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)
        access_map: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)
        conn_map: Dict[str, List[SyscallEvent]] = collections.defaultdict(list)
        slow_list: List[SyscallEvent] = []

        for ev in events:
            # Check for missing files / ENOENT
            if ev.result == EventResult.FAILED_NOT_FOUND or ev.errno_name in ("ENOENT", "ERROR_FILE_NOT_FOUND", "ERROR_PATH_NOT_FOUND"):
                missing_map[ev.target_path].append(ev)

            # Check for permission denied / EACCES
            elif ev.result == EventResult.FAILED_ACCESS_DENIED or ev.errno_name in ("EACCES", "EPERM", "ERROR_ACCESS_DENIED"):
                access_map[ev.target_path].append(ev)

            # Check for connection refused / timeout
            elif ev.result in (EventResult.FAILED_CONN_REFUSED, EventResult.FAILED_TIMEOUT) or ev.errno_name in (
                "ECONNREFUSED", "WSAECONNREFUSED", "ETIMEDOUT", "WSAETIMEDOUT"
            ):
                conn_map[ev.target_path].append(ev)

            # Check for high latency
            if ev.duration_us >= self.slow_threshold_us:
                slow_list.append(ev)

        # Aggregate missing files
        for target, sample_events in sorted(missing_map.items(), key=lambda x: len(x[1]), reverse=True):
            first = sample_events[0]
            is_config = any(target.lower().endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf"))
            is_lib = any(target.lower().endswith(ext) for ext in (".dll", ".so", ".dylib"))
            tag = "Config file missing" if is_config else ("Dynamic library missing" if is_lib else "Path not found")

            report.missing_files.append(
                AnomalyItem(
                    kind="MISSING_FILE",
                    summary=f"{tag}: {target} ({len(sample_events)} attempts)",
                    target=target,
                    count=len(sample_events),
                    sample_event=first,
                    details={"is_config": is_config, "is_lib": is_lib, "pids": list({e.pid for e in sample_events})},
                )
            )

        # Aggregate access denied
        for target, sample_events in sorted(access_map.items(), key=lambda x: len(x[1]), reverse=True):
            first = sample_events[0]
            report.access_denied.append(
                AnomalyItem(
                    kind="PERMISSION_DENIED",
                    summary=f"Access denied to target: {target} ({len(sample_events)} attempts)",
                    target=target,
                    count=len(sample_events),
                    sample_event=first,
                    details={"pids": list({e.pid for e in sample_events})},
                )
            )

        # Aggregate failed connections
        for target, sample_events in sorted(conn_map.items(), key=lambda x: len(x[1]), reverse=True):
            first = sample_events[0]
            report.failed_connections.append(
                AnomalyItem(
                    kind="REFUSED_CONNECTION",
                    summary=f"Network connection failed: {target} ({len(sample_events)} attempts)",
                    target=target,
                    count=len(sample_events),
                    sample_event=first,
                    details={"pids": list({e.pid for e in sample_events}), "result": first.result.value},
                )
            )

        # Sort slow syscalls
        slow_list.sort(key=lambda e: e.duration_us, reverse=True)
        for ev in slow_list[:50]:  # Top 50 slowest
            report.slow_syscalls.append(
                AnomalyItem(
                    kind="SLOW_SYSCALL",
                    summary=f"High latency {ev.operation.value} ({ev.formatted_duration}) on {ev.target_path}",
                    target=ev.target_path,
                    count=1,
                    sample_event=ev,
                    details={"duration_us": ev.duration_us, "pid": ev.pid, "operation": ev.operation.value},
                )
            )

        report.total_anomalies = (
            len(report.missing_files)
            + len(report.access_denied)
            + len(report.failed_connections)
            + len(report.slow_syscalls)
        )
        return report
