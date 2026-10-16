# ProcTrace Architecture

ProcTrace intercepts, correlates, and displays operating system events in real time. It is designed to replace traditional tools like Sysinternals Process Monitor and strace by providing cross-platform collectors, microsecond timestamp precision, and DevTools-style waterfall rendering.

## System Topology

```
+-----------------------------------------------------------------------+
|                           User Application                            |
|                 (CLI run, attach, or background process)              |
+-----------------------------------+-----------------------------------+
                                    |
+-----------------------------------v-----------------------------------+
|                       OS Kernel Event Collectors                      |
|                                                                       |
|  * Windows: ReadDirectoryChangesW, IP Helper (netstat), psutil        |
|  * Linux: ptrace syscall registers, procfs (/proc/<pid>/fd)           |
|  * macOS: dtrace, dtruss probes, Endpoint Security API                |
+-----------------------------------+-----------------------------------+
                                    | SyscallEvent stream
+-----------------------------------v-----------------------------------+
|                        Lock-Free Ring Buffer                          |
|  * 500,000 pre-allocated circular slots                              |
|  * Atomic index management with threading locks                       |
|  * Throughput benchmark: >1.3M events/sec                             |
|  * Microsecond timestamp indexing                                     |
+-----------------------------------+-----------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
+---------v-------------------------+       +-----------------v---------+
|     Filter & Anomaly Engine       |       |       Export Pipeline     |
|  * Composite EventFilter rules    |       |  * Structured JSON        |
|  * Noise suppression (System32)   |       |  * Standard CSV           |
|  * Missing files triage (ENOENT)  |       |  * Chrome Trace (Perfetto)|
|  * Broken sockets (ECONNREFUSED)  |       |  * Markdown Incident Log  |
+-----------------+-----------------+       +---------------------------+
                  |
        +---------+---------+
        |                   |
+-------v---------+ +-------v---------+
|   Textual TUI   | |   Web Studio    |
| * ASCII bars    | | * HTML5 Canvas  |
| * Sparkline     | | * WebSockets    |
| * Inspection    | | * DevTools UI   |
+-----------------+ +-----------------+
```

## Core Components

### 1. Data Model (`proctrace.core.models`)
- `SyscallEvent`: Single event instance containing timestamp, PID, PPID, process name, category, operation, target path, return code, errno name, duration in microseconds, and arbitrary details dictionary.
- `EventCategory`: Groups events into `FILESYSTEM`, `NETWORK`, `PROCESS`, `ENVIRONMENT`, `MEMORY`, and `SECURITY`.
- `EventOperation`: Specific actions such as `OPEN`, `READ`, `WRITE`, `CLOSE`, `DELETE`, `CONNECT`, `ACCEPT`, `LISTEN`, `SPAWN`, `EXEC`, `EXIT`, `LOAD_LIBRARY`.
- `EventResult`: Normalized status code indicating `SUCCESS`, `FAILED_NOT_FOUND`, `FAILED_ACCESS_DENIED`, `FAILED_CONN_REFUSED`, `FAILED_TIMEOUT`, or `FAILED_OTHER`.

### 2. High-Speed Ring Buffer (`proctrace.core.ring_buffer`)
Pre-allocates memory for up to 500,000 events. When the buffer reaches capacity, it overwrites the oldest events in circular order without allocating new memory blocks. Subscribers can listen to real-time events through push callbacks.

### 3. Filter Engine & Anomaly Correlator (`proctrace.core.filter`)
- `EventFilter`: Matches events against category sets, operation sets, target PIDs, duration thresholds, regex patterns, and file extensions.
- Noise Suppression: Strips OS runtime internal noise such as `C:\Windows\System32`, `WinSxS`, `/usr/lib`, `/lib64`, and `/etc/ld.so.cache`.
- `AnomalyCorrelator`: Groups failed lookups to pinpoint missing configuration files (`.env`, `settings.json`), missing shared libraries (`.dll`, `.so`), and refused ports.

### 4. Interactive Surfaces
- Textual TUI (`proctrace.tui.app`): Terminal dashboard with live scrolling events, ASCII waterfall timeline, fuzzy search, and modal inspection.
- Web Studio (`proctrace.web.server`): FastAPI server streaming events over WebSockets at 20 frames per second to an HTML5 waterfall interface with process swimlanes, process hierarchy trees, and diagnostic modals.

### 5. Regression Diff Engine (`proctrace.core.diff`)
- `TraceDiffer`: Compares two recorded runs (baseline vs current) to surface latency regressions (>50% slowdown), newly missing files (`ENOENT`), new or removed network endpoints, and error rate changes.
- Outputs Markdown summary tables and machine-readable JSON diffs for automated regression testing.

### 6. Root Cause Explainer (`proctrace.analysis.explainer`)
- `RootCauseExplainer`: Maps raw syscall failure patterns to human-actionable root causes and exact terminal remediation commands.
- Automatically handles:
  - Missing `.env` configurations (detects existing `.env.example` templates and suggests `cp .env.example .env`).
  - Missing shared libraries (`vcruntime140.dll`, `libssl`, `libcrypto`) with precise package manager installation commands (`apt`, `brew`, `vcredist`).
  - Connection refused errors on well-known ports (PostgreSQL 5432, MySQL 3306, Redis 6379, MongoDB 27017) with service start commands.
  - Permission denied (`EACCES`) paths with explicit `chmod` or ownership guidance.

### 7. Security Auditor and Policy Guard (`proctrace.security.auditor`)
- `SecurityAuditor`: Scans syscall traces for sensitive file access (SSH keys, AWS credentials, Docker config, kubeconfig, `/etc/shadow`, Windows SAM). Detects data exfiltration patterns when sensitive file reads are followed by outbound external network connections within 5 seconds.
- `PolicyGuard`: Enforces CI/CD operational constraints (`--no-missing-configs`, `--no-unencrypted-http`, `--max-latency-ms`, `--max-errors`). Causes `proctrace assert` to exit with status code 1 when rules fail.

