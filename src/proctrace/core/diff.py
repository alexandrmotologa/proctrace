"""Trace comparison and regression analysis engine."""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from proctrace.core.models import SyscallEvent


@dataclass
class LatencyRegression:
    """Represents a syscall operation that exhibited a latency increase."""

    operation: str
    target_path: str
    baseline_us: float
    current_us: float
    delta_us: float
    increase_pct: float


@dataclass
class TraceDiffReport:
    """Comprehensive comparison between baseline and candidate traces."""

    baseline_count: int
    current_count: int
    count_delta: int
    baseline_errors: int
    current_errors: int
    error_delta: int
    new_missing_files: List[str] = field(default_factory=list)
    resolved_missing_files: List[str] = field(default_factory=list)
    new_network_endpoints: List[str] = field(default_factory=list)
    removed_network_endpoints: List[str] = field(default_factory=list)
    new_errors: List[Dict[str, Any]] = field(default_factory=list)
    latency_regressions: List[LatencyRegression] = field(default_factory=list)
    new_paths_accessed: List[str] = field(default_factory=list)
    removed_paths_accessed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert diff report to dictionary."""
        return {
            "summary": {
                "baseline_events": self.baseline_count,
                "current_events": self.current_count,
                "event_delta": self.count_delta,
                "baseline_errors": self.baseline_errors,
                "current_errors": self.current_errors,
                "error_delta": self.error_delta,
            },
            "new_missing_files": self.new_missing_files,
            "resolved_missing_files": self.resolved_missing_files,
            "new_network_endpoints": self.new_network_endpoints,
            "removed_network_endpoints": self.removed_network_endpoints,
            "latency_regressions": [
                {
                    "operation": r.operation,
                    "target_path": r.target_path,
                    "baseline_us": r.baseline_us,
                    "current_us": r.current_us,
                    "delta_us": r.delta_us,
                    "increase_pct": round(r.increase_pct, 1),
                }
                for r in self.latency_regressions
            ],
            "new_errors": self.new_errors,
            "new_paths_accessed": self.new_paths_accessed[:100],
            "removed_paths_accessed": self.removed_paths_accessed[:100],
        }

    def to_markdown(self) -> str:
        """Render diff report as humanized markdown."""
        lines = [
            "# ProcTrace Trace Diff Report",
            "",
            "## Summary",
            "",
            f"- Baseline Events: {self.baseline_count}",
            f"- Candidate Events: {self.current_count} (Delta: {self.count_delta:+d})",
            f"- Baseline Errors: {self.baseline_errors}",
            f"- Candidate Errors: {self.current_errors} (Delta: {self.error_delta:+d})",
        ]

        # New missing files
        if self.new_missing_files:
            lines.extend([
                "",
                "## New Missing Files (ENOENT Regressions)",
                "",
                "The following paths failed in the candidate trace but succeeded or were not requested in the baseline:",
                "",
            ])
            for path in self.new_missing_files:
                lines.append(f"- `{path}`")

        # Resolved missing files
        if self.resolved_missing_files:
            lines.extend([
                "",
                "## Resolved Missing Files (Fixes)",
                "",
                "The following paths previously failed with ENOENT but are now resolved:",
                "",
            ])
            for path in self.resolved_missing_files:
                lines.append(f"- `{path}`")

        # Network changes
        if self.new_network_endpoints:
            lines.extend([
                "",
                "## New Network Endpoints Contacted",
                "",
            ])
            for ep in self.new_network_endpoints:
                lines.append(f"- `{ep}`")

        # Latency regressions
        if self.latency_regressions:
            lines.extend([
                "",
                "## Latency Regressions (>50% slower and >1000 µs delta)",
                "",
                "| Operation | Target Path | Baseline | Candidate | Delta | Slowdown |",
                "|---|---|---|---|---|---|",
            ])
            for r in self.latency_regressions[:25]:
                base_str = f"{r.baseline_us:.1f} µs" if r.baseline_us < 1000 else f"{r.baseline_us/1000:.2f} ms"
                curr_str = f"{r.current_us:.1f} µs" if r.current_us < 1000 else f"{r.current_us/1000:.2f} ms"
                delta_str = f"+{r.delta_us/1000:.2f} ms" if r.delta_us >= 1000 else f"+{r.delta_us:.1f} µs"
                lines.append(f"| {r.operation} | `{r.target_path}` | {base_str} | {curr_str} | {delta_str} | +{r.increase_pct:.1f}% |")

        return "\n".join(lines) + "\n"


class TraceDiffer:
    """Compares two syscall event streams to pinpoint functional and performance regressions."""

    def __init__(
        self,
        min_regression_pct: float = 50.0,
        min_regression_delta_us: float = 1000.0,
    ) -> None:
        self.min_regression_pct = min_regression_pct
        self.min_regression_delta_us = min_regression_delta_us

    def compare(
        self,
        baseline_events: Sequence[SyscallEvent],
        current_events: Sequence[SyscallEvent],
    ) -> TraceDiffReport:
        """Execute comprehensive diff analysis between baseline and current events."""
        base_count = len(baseline_events)
        curr_count = len(current_events)
        base_errs = sum(1 for e in baseline_events if e.is_error)
        curr_errs = sum(1 for e in current_events if e.is_error)

        # 1. Missing files comparison (ENOENT)
        base_missing = {
            e.target_path
            for e in baseline_events
            if e.errno_name in ("ENOENT", "ERROR_FILE_NOT_FOUND", "ERROR_PATH_NOT_FOUND") and e.target_path
        }
        curr_missing = {
            e.target_path
            for e in current_events
            if e.errno_name in ("ENOENT", "ERROR_FILE_NOT_FOUND", "ERROR_PATH_NOT_FOUND") and e.target_path
        }

        new_missing = sorted(curr_missing - base_missing)
        resolved_missing = sorted(base_missing - curr_missing)

        # 2. Network endpoints comparison
        base_endpoints = {
            e.target_path
            for e in baseline_events
            if e.category.value == "NETWORK" and e.target_path
        }
        curr_endpoints = {
            e.target_path
            for e in current_events
            if e.category.value == "NETWORK" and e.target_path
        }

        new_endpoints = sorted(curr_endpoints - base_endpoints)
        removed_endpoints = sorted(base_endpoints - curr_endpoints)

        # 3. Path accessed diff
        base_paths = {e.target_path for e in baseline_events if e.target_path}
        curr_paths = {e.target_path for e in current_events if e.target_path}
        new_paths = sorted(curr_paths - base_paths)
        removed_paths = sorted(base_paths - curr_paths)

        # 4. Latency regressions on matched (operation, target_path)
        base_latencies: Dict[Tuple[str, str], List[float]] = collections.defaultdict(list)
        for e in baseline_events:
            if e.target_path:
                base_latencies[(e.operation.value, e.target_path)].append(e.duration_us)

        curr_latencies: Dict[Tuple[str, str], List[float]] = collections.defaultdict(list)
        for e in current_events:
            if e.target_path:
                curr_latencies[(e.operation.value, e.target_path)].append(e.duration_us)

        regressions: List[LatencyRegression] = []
        for key, curr_vals in curr_latencies.items():
            if key in base_latencies:
                base_avg = sum(base_latencies[key]) / len(base_latencies[key])
                curr_avg = sum(curr_vals) / len(curr_vals)
                delta = curr_avg - base_avg
                if base_avg > 0:
                    pct = (delta / base_avg) * 100.0
                else:
                    pct = 100.0 if delta > 0 else 0.0

                if delta >= self.min_regression_delta_us and pct >= self.min_regression_pct:
                    regressions.append(
                        LatencyRegression(
                            operation=key[0],
                            target_path=key[1],
                            baseline_us=base_avg,
                            current_us=curr_avg,
                            delta_us=delta,
                            increase_pct=pct,
                        )
                    )

        regressions.sort(key=lambda r: r.delta_us, reverse=True)

        # 5. New error events
        base_error_keys = {(e.operation.value, e.target_path, e.errno_name) for e in baseline_events if e.is_error}
        new_errors = []
        for e in current_events:
            if e.is_error:
                key = (e.operation.value, e.target_path, e.errno_name)
                if key not in base_error_keys:
                    new_errors.append(e.to_dict())

        return TraceDiffReport(
            baseline_count=base_count,
            current_count=curr_count,
            count_delta=curr_count - base_count,
            baseline_errors=base_errs,
            current_errors=curr_errs,
            error_delta=curr_errs - base_errs,
            new_missing_files=new_missing,
            resolved_missing_files=resolved_missing,
            new_network_endpoints=new_endpoints,
            removed_network_endpoints=removed_endpoints,
            new_errors=new_errors,
            latency_regressions=regressions,
            new_paths_accessed=new_paths,
            removed_paths_accessed=removed_paths,
        )
