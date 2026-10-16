"""Generate realistic syscall events for demo and visual assets."""

import time
from proctrace.core.models import (
    EventCategory,
    EventOperation,
    EventResult,
    SyscallEvent,
)
from proctrace.core.ring_buffer import RingBuffer
from proctrace.export.json_export import export_to_json


def create_demo_events() -> list[SyscallEvent]:
    base_time = time.time() - 3.5
    events = []

    # 1. Process spawn
    events.append(SyscallEvent(
        timestamp=base_time + 0.05,
        pid=4102,
        ppid=1200,
        process_name="node.exe",
        category=EventCategory.PROCESS,
        operation=EventOperation.SPAWN,
        target_path="node server.js --port 3000",
        result=EventResult.SUCCESS,
        duration_us=350.0,
        details={"cwd": "B:\\workgit\\api-service"},
    ))

    # 2. Dynamic library loads
    libs = [
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\ws2_32.dll",
        "C:\\Program Files\\nodejs\\node.dll",
    ]
    for i, lib in enumerate(libs):
        events.append(SyscallEvent(
            timestamp=base_time + 0.12 + (i * 0.04),
            pid=4102,
            process_name="node.exe",
            category=EventCategory.ENVIRONMENT,
            operation=EventOperation.LOAD_LIBRARY,
            target_path=lib,
            result=EventResult.SUCCESS,
            duration_us=85.0 + (i * 15.0),
        ))

    # 3. Missing configuration files (ENOENT)
    configs = [
        ("B:\\workgit\\api-service\\.env.local", "ENOENT"),
        ("B:\\workgit\\api-service\\.env", "ENOENT"),
        ("B:\\workgit\\api-service\\config\\production.json", "ENOENT"),
    ]
    for i, (cfg, err) in enumerate(configs):
        events.append(SyscallEvent(
            timestamp=base_time + 0.35 + (i * 0.08),
            pid=4102,
            process_name="node.exe",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.OPEN,
            target_path=cfg,
            result=EventResult.FAILED_NOT_FOUND,
            return_code=-2,
            errno_name=err,
            duration_us=42.0,
            details={"flags": "O_RDONLY"},
        ))

    # 4. Successful fallback config read
    events.append(SyscallEvent(
        timestamp=base_time + 0.65,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.OPEN,
        target_path="B:\\workgit\\api-service\\config\\default.json",
        result=EventResult.SUCCESS,
        duration_us=65.0,
    ))
    events.append(SyscallEvent(
        timestamp=base_time + 0.68,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.READ,
        target_path="B:\\workgit\\api-service\\config\\default.json",
        result=EventResult.SUCCESS,
        duration_us=180.0,
        details={"bytes_read": 1420},
    ))
    events.append(SyscallEvent(
        timestamp=base_time + 0.72,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.CLOSE,
        target_path="B:\\workgit\\api-service\\config\\default.json",
        result=EventResult.SUCCESS,
        duration_us=12.0,
    ))

    # 5. Socket listen
    events.append(SyscallEvent(
        timestamp=base_time + 0.95,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.NETWORK,
        operation=EventOperation.LISTEN,
        target_path="0.0.0.0:3000",
        result=EventResult.SUCCESS,
        duration_us=210.0,
        details={"backlog": 511},
    ))

    # 6. Database connection refused
    events.append(SyscallEvent(
        timestamp=base_time + 1.20,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.NETWORK,
        operation=EventOperation.CONNECT,
        target_path="127.0.0.1:5432",
        result=EventResult.FAILED_CONN_REFUSED,
        return_code=-111,
        errno_name="ECONNREFUSED",
        duration_us=1200.0,
        details={"protocol": "TCP", "retry": 1},
    ))
    events.append(SyscallEvent(
        timestamp=base_time + 1.45,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.NETWORK,
        operation=EventOperation.CONNECT,
        target_path="127.0.0.1:5432",
        result=EventResult.FAILED_CONN_REFUSED,
        return_code=-111,
        errno_name="ECONNREFUSED",
        duration_us=1150.0,
        details={"protocol": "TCP", "retry": 2},
    ))

    # 7. Outbound HTTP telemetry
    events.append(SyscallEvent(
        timestamp=base_time + 1.85,
        pid=4102,
        process_name="node.exe",
        category=EventCategory.NETWORK,
        operation=EventOperation.CONNECT,
        target_path="140.82.121.4:443",
        result=EventResult.SUCCESS,
        duration_us=4500.0,
        details={"host": "api.github.com", "tls": "TLSv1.3"},
    ))

    # 8. Child process spawn (worker thread / child compiler)
    events.append(SyscallEvent(
        timestamp=base_time + 2.10,
        pid=4108,
        ppid=4102,
        process_name="esbuild.exe",
        category=EventCategory.PROCESS,
        operation=EventOperation.SPAWN,
        target_path="esbuild src/index.ts --bundle",
        result=EventResult.SUCCESS,
        duration_us=420.0,
    ))

    # 9. Source bundle file reads and write
    for idx, f in enumerate(["src/index.ts", "src/auth.ts", "src/db.ts"]):
        events.append(SyscallEvent(
            timestamp=base_time + 2.25 + (idx * 0.12),
            pid=4108,
            ppid=4102,
            process_name="esbuild.exe",
            category=EventCategory.FILESYSTEM,
            operation=EventOperation.READ,
            target_path=f"B:\\workgit\\api-service\\{f}",
            result=EventResult.SUCCESS,
            duration_us=140.0 + (idx * 30.0),
        ))

    # Output bundle write (slow I/O)
    events.append(SyscallEvent(
        timestamp=base_time + 2.75,
        pid=4108,
        ppid=4102,
        process_name="esbuild.exe",
        category=EventCategory.FILESYSTEM,
        operation=EventOperation.WRITE,
        target_path="B:\\workgit\\api-service\\dist\\bundle.js",
        result=EventResult.SUCCESS,
        duration_us=14200.0,  # 14.2ms
        details={"bytes": 48590},
    ))

    # Child exit
    events.append(SyscallEvent(
        timestamp=base_time + 3.10,
        pid=4108,
        ppid=4102,
        process_name="esbuild.exe",
        category=EventCategory.PROCESS,
        operation=EventOperation.EXIT,
        target_path="exit(0)",
        result=EventResult.SUCCESS,
        return_code=0,
        duration_us=1000.0,
    ))

    return events


if __name__ == "__main__":
    demo_events = create_demo_events()
    export_to_json(demo_events, "docs/demo_trace.json")
    print(f"Generated {len(demo_events)} demo events saved to docs/demo_trace.json")
