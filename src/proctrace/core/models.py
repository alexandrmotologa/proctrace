"""Domain models representing system calls, process events, and trace sessions."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class EventCategory(str, enum.Enum):
    """Broad functional grouping of system events."""

    FILESYSTEM = "FILESYSTEM"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    ENVIRONMENT = "ENVIRONMENT"
    MEMORY = "MEMORY"
    SECURITY = "SECURITY"


class EventOperation(str, enum.Enum):
    """Specific system call or kernel operation."""

    # Filesystem operations
    OPEN = "OPEN"
    READ = "READ"
    WRITE = "WRITE"
    CLOSE = "CLOSE"
    DELETE = "DELETE"
    STAT = "STAT"
    RENAME = "RENAME"
    SEEK = "SEEK"
    SYNC = "SYNC"

    # Network operations
    CONNECT = "CONNECT"
    ACCEPT = "ACCEPT"
    LISTEN = "LISTEN"
    DNS_LOOKUP = "DNS_LOOKUP"
    SEND = "SEND"
    RECV = "RECV"
    BIND = "BIND"

    # Process operations
    SPAWN = "SPAWN"
    FORK = "FORK"
    EXEC = "EXEC"
    THREAD_CREATE = "THREAD_CREATE"
    EXIT = "EXIT"
    KILL = "KILL"

    # Environment operations
    ENV_LOOKUP = "ENV_LOOKUP"
    ENV_SET = "ENV_SET"
    LOAD_LIBRARY = "LOAD_LIBRARY"


class EventResult(str, enum.Enum):
    """Normalized outcome status of a system call."""

    SUCCESS = "SUCCESS"
    FAILED_NOT_FOUND = "FAILED_NOT_FOUND"          # ENOENT / ERROR_FILE_NOT_FOUND
    FAILED_ACCESS_DENIED = "FAILED_ACCESS_DENIED"  # EACCES / ERROR_ACCESS_DENIED
    FAILED_CONN_REFUSED = "FAILED_CONN_REFUSED"    # ECONNREFUSED / WSAECONNREFUSED
    FAILED_TIMEOUT = "FAILED_TIMEOUT"              # ETIMEDOUT / WSAETIMEDOUT
    FAILED_OTHER = "FAILED_OTHER"


@dataclass(slots=True)
class SyscallEvent:
    """Represents a single intercepted system call or kernel activity event."""

    timestamp: float  # Microsecond precision epoch timestamp (seconds)
    pid: int
    process_name: str
    category: EventCategory
    operation: EventOperation
    target_path: str
    result: EventResult = EventResult.SUCCESS
    duration_us: float = 0.0  # Latency in microseconds
    return_code: Optional[int] = 0
    errno_name: Optional[str] = None
    ppid: Optional[int] = None
    tid: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def is_error(self) -> bool:
        """Return True if the call resulted in a failure or non-zero error."""
        if self.result != EventResult.SUCCESS:
            return True
        if self.return_code is not None and self.return_code < 0:
            return True
        if self.errno_name and self.errno_name not in ("SUCCESS", "0", "OK"):
            return True
        return False

    @property
    def formatted_duration(self) -> str:
        """Human-readable duration representation."""
        if self.duration_us < 1.0:
            return f"{self.duration_us * 1000.0:.1f} ns"
        if self.duration_us < 1000.0:
            return f"{self.duration_us:.1f} µs"
        if self.duration_us < 1_000_000.0:
            return f"{self.duration_us / 1000.0:.2f} ms"
        return f"{self.duration_us / 1_000_000.0:.2f} s"

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a JSON-serializable dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "ppid": self.ppid,
            "tid": self.tid,
            "process_name": self.process_name,
            "category": self.category.value if isinstance(self.category, EventCategory) else str(self.category),
            "operation": self.operation.value if isinstance(self.operation, EventOperation) else str(self.operation),
            "target_path": self.target_path,
            "result": self.result.value if isinstance(self.result, EventResult) else str(self.result),
            "duration_us": self.duration_us,
            "return_code": self.return_code,
            "errno_name": self.errno_name,
            "details": self.details,
            "depth": self.depth,
            "is_error": self.is_error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SyscallEvent:
        """Construct a SyscallEvent from a dictionary."""
        category = EventCategory(data["category"]) if isinstance(data["category"], str) else data["category"]
        operation = EventOperation(data["operation"]) if isinstance(data["operation"], str) else data["operation"]
        result = EventResult(data["result"]) if isinstance(data.get("result"), str) else data.get("result", EventResult.SUCCESS)

        return cls(
            id=data.get("id", uuid.uuid4().hex[:12]),
            timestamp=float(data["timestamp"]),
            pid=int(data["pid"]),
            ppid=data.get("ppid"),
            tid=data.get("tid"),
            process_name=data.get("process_name", "unknown"),
            category=category,
            operation=operation,
            target_path=data.get("target_path", ""),
            result=result,
            duration_us=float(data.get("duration_us", 0.0)),
            return_code=data.get("return_code"),
            errno_name=data.get("errno_name"),
            details=data.get("details", {}),
            depth=int(data.get("depth", 0)),
        )


@dataclass(slots=True)
class ProcessInfo:
    """Information regarding a traced process and its hierarchy."""

    pid: int
    name: str
    ppid: Optional[int] = None
    cmdline: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    exit_time: Optional[float] = None
    exit_code: Optional[int] = None
    children: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert process info to dictionary."""
        return asdict(self)


@dataclass(slots=True)
class TraceSession:
    """Metadata describing an active or completed trace recording session."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    target_cmd: Optional[str] = None
    target_pid: Optional[int] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    total_events: int = 0
    error_events: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate elapsed session time in seconds."""
        end = self.end_time or time.time()
        return max(0.0, end - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "target_cmd": self.target_cmd,
            "target_pid": self.target_pid,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "total_events": self.total_events,
            "error_events": self.error_events,
            "metadata": self.metadata,
        }
