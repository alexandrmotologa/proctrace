# ProcTrace: Master Implementation Plan

> Cross-Platform Process Activity and Syscall Waterfall Monitor
>
> A developer-focused alternative to Sysinternals Process Monitor and strace. Delivers real-time observation of filesystem calls, socket connections, process trees, and permission errors with an interactive TUI and Chrome DevTools waterfall timeline.

## 1. Architecture Overview

When a script, compiler, or service crashes silently or fails with generic errors like "Configuration file not found" or "Access denied", developers waste hours guessing what occurred. Sysinternals Process Monitor is Windows-only with a dated interface, while strace produces dense text streams that degrade application throughput.

ProcTrace delivers low-overhead cross-platform process activity monitoring:

1. Kernel and System Event Collectors:
   - Windows: ETW (Event Tracing for Windows), Win32 Debug and Process Tracking, ReadDirectoryChangesW, and IP Helper socket state tables.
   - Linux: Native ptrace syscall interception with register decoding (openat, read, write, connect, execve), procfs integration, and fallback streaming.
   - macOS: DTrace and dtruss probe integration with Endpoint Security event parsing.
   - Subprocess Runner: Process launcher attaching tracing hooks, tracking child processes, and capturing stdout/stderr and exit codes.

2. Event Categories:
   - Filesystem: Open, Read, Write, Close, Delete, Stat, Rename.
   - Network: Socket Connect, Listen, Accept, DNS Resolution, Send, Recv.
   - Process: Spawn, Fork, Exec, Thread Creation, Exit code.
   - Environment: Environment variable lookups, dynamic library loads.

3. Failure Isolation:
   - Identifies failed syscalls (ENOENT, EACCES, ECONNREFUSED, Access Denied) with root cause classification.
   - Pinpoints missing config files (.env, YAML, JSON), missing shared libraries, and refused ports.

4. Waterfall Timeline Interface:
   - Terminal UI (Textual): Interactive split screen monitor, ASCII waterfall timeline, fuzzy search, and event inspector.
   - Web Studio (FastAPI + WebSockets): Chrome DevTools style waterfall timeline with microsecond precision, pan, zoom, swimlanes, and live event streaming.
   - Trace Exporter: JSON, CSV, and Chrome Trace Event Format (compatible with chrome://tracing and Perfetto).

```
+-----------------------------------------------------------------------------------+
|                                    PROCTRACE                                      |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|    OS Kernel Event Collector    |                 |   High-Speed Ring Buffer      |
|  * Windows: ETW & Win32 Hooks   |                 |  * Pre-allocated circular ring|
|  * Linux: ptrace / procfs       |                 |  * 500,000 event capacity     |
|  * macOS: dtrace / dtruss       |                 |  * Microsecond timestamps     |
+-------+-------------------------+                 +-----------------------+-------+
        |                                                                   |
        +---------------------------------+---------------------------------+
                                          |
                        +-----------------v-----------------+
                        |     Filter & Correlation Engine   |
                        |  * Target PID and child tree      |
                        |  * ENOENT / EACCES Error Isolator |
                        |  * Path and Socket Regex Matcher  |
                        |  * System noise suppression       |
                        +-----------------+-----------------+
                                          |
                        +-----------------v-----------------+
                        |   Waterfall Timeline Studio & CLI |
                        |  * Textual Interactive TUI        |
                        |  * Web Studio (FastAPI/Canvas)    |
                        |  * Chrome Trace (Perfetto) Export |
                        |  * CLI run, attach, and doctor    |
                        +-----------------------------------+
```

## 2. Directory Structure

```
proctrace/
├── pyproject.toml
├── README.md
├── LICENSE
├── configs/
│   ├── filters/
│   │   ├── missing-files.yaml        # Filters strictly for ENOENT and file not found
│   │   ├── network-only.yaml         # Filters strictly for socket and DNS events
│   │   ├── slow-io.yaml              # Syscalls exceeding latency thresholds (>10ms)
│   │   └── full-audit.yaml           # Captures all syscall operations
├── docs/
│   ├── architecture.md
│   ├── cli-reference.md
│   ├── os-collector-internals.md
│   └── waterfall-guide.md
├── src/
│   └── proctrace/
│       ├── __init__.py
│       ├── py.typed
│       ├── cli/
│       │   ├── __init__.py
│       │   └── main.py               # Typer CLI application
│       ├── core/
│       │   ├── __init__.py
│       │   ├── models.py             # SyscallEvent, EventCategory, EventResult, ProcessInfo
│       │   ├── ring_buffer.py        # 500k event circular buffer with microsecond index
│       │   ├── filter.py             # Event filter rules and error classification
│       │   └── diff.py               # TraceDiffer and regression analysis engine
│       ├── analysis/
│       │   ├── __init__.py
│       │   └── explainer.py          # RootCauseExplainer diagnostic engine
│       ├── security/
│       │   ├── __init__.py
│       │   └── auditor.py            # SecurityAuditor and PolicyGuard enforcement
│       ├── collectors/
│       │   ├── __init__.py
│       │   ├── base.py               # Abstract BaseCollector interface
│       │   ├── runner.py             # Managed subprocess launcher with child tracing
│       │   ├── windows.py            # Windows Win32, ETW, Directory and Socket tracer
│       │   ├── linux.py              # Linux ptrace and procfs tracer
│       │   └── macos.py              # macOS dtrace and dtruss tracer
│       ├── export/
│       │   ├── __init__.py
│       │   ├── json_export.py        # Structured JSON trace generator
│       │   ├── csv_export.py         # CSV log generator
│       │   ├── chrome_trace.py       # Chrome Trace Event Format for Perfetto
│       │   └── markdown_report.py    # Incident triage summary report
│       ├── tui/
│       │   ├── __init__.py
│       │   └── app.py                # Textual TUI with live streaming and waterfall
│       └── web/
│           ├── __init__.py
│           ├── server.py             # FastAPI WebSocket and REST server
│           └── static/
│               ├── index.html        # DevTools style waterfall interface
│               ├── app.js            # Canvas rendering, swimlanes, and triage modals
│               └── style.css         # Dark theme UI styling
└── tests/
    ├── test_models.py
    ├── test_ring_buffer.py
    ├── test_filter.py
    ├── test_diff.py
    ├── test_explainer.py
    ├── test_security.py
    ├── test_export.py
    ├── test_collectors.py
    ├── test_runner.py
    ├── test_cli.py
    └── test_web.py
```

## 3. Implementation Phases

### Phase 1: Core Domain Models and Ring Buffer
- Define EventCategory: FILESYSTEM, NETWORK, PROCESS, ENVIRONMENT, MEMORY.
- Define EventOperation: OPEN, READ, WRITE, CLOSE, DELETE, STAT, RENAME, CONNECT, ACCEPT, LISTEN, DNS_LOOKUP, SPAWN, EXIT, ENV_LOOKUP, LOAD_LIBRARY.
- Define EventResult: SUCCESS, FAILED_NOT_FOUND, FAILED_ACCESS_DENIED, FAILED_CONN_REFUSED, FAILED_TIMEOUT, FAILED_OTHER.
- Define SyscallEvent dataclass with microsecond timestamps, latency, PID, PPID, process name, path/socket, result, and return code.
- Implement RingBuffer:
  - 500,000 capacity pre-allocated ring buffer.
  - Thread-safe append and slice retrieval.
  - Snapshot querying by time range, PID, and category.
  - Statistics tracking: total events, drop counts, error rates, throughput per second.

### Phase 2: OS Kernel and Process Collectors
- Abstract BaseCollector with lifecycle management, buffer binding, and rate metrics.
- SubprocessRunner:
  - Spawns target command (`proctrace run -- <cmd>`).
  - Captures process tree recursively across forks and child processes.
  - Intercepts filesystem activity, socket bindings, and child launches.
- Windows Collector:
  - Native Win32 API integration via ctypes and psutil.
  - Directory change tracking via ReadDirectoryChangesW with action and path mapping.
  - Active socket tracking via IP Helper API (GetExtendedTcpTable, GetExtendedUdpTable).
  - Process creation monitoring via Win32 Job Objects and Toolhelp32 snapshots.
  - ETW provider hook integration for elevated kernel capture.
- Linux Collector:
  - Native ptrace interface decoding syscall numbers for x86_64 and arm64.
  - Register extraction for openat, read, write, connect, execve, unlink.
  - Decodes errno return values (-ENOENT, -EACCES, -ECONNREFUSED).
  - Fallback streaming through strace integration.
- macOS Collector:
  - DTrace and dtruss real-time probe execution and output parsing.
  - Correlates syscall entry and return probes with microsecond deltas.

### Phase 3: Filtering, Correlation, and Anomaly Detection
- EventFilter with composite matching:
  - Category and operation filtering.
  - Error isolation: `--errors-only` mode filters for non-zero return codes and failed statuses.
  - Path matching: glob patterns and regular expressions.
  - Extension whitelisting: `.env`, `.json`, `.yaml`, `.so`, `.dll`.
  - System noise suppression: removes standard OS paths like System32, WinSxS, /usr/lib, /lib64.
- Anomaly Correlator:
  - Missing file detector: groups repeated ENOENT lookups to pinpoint configuration or asset failures.
  - Network failure detector: groups refused connections by target host and port.
  - Latency outlier detector: flags syscalls exceeding configured microsecond thresholds.

### Phase 4: Interactive TUI Waterfall Monitor
- Textual TUI Application:
  - Header: active process name, PID, events per second sparkline, error count.
  - Live Event Table: color-coded stream with microsecond timestamps and results.
  - Waterfall Timeline View: ASCII visual bars depicting start offsets and duration.
  - Filter Bar: instant fuzzy search, category toggle, and error switch.
  - Detail Inspector: modal dialog showing complete syscall arguments, environment context, and result codes.

### Phase 5: Web Studio and Chrome DevTools Waterfall
- FastAPI backend with WebSocket streaming at 60 fps.
- Chrome DevTools style waterfall frontend:
  - HTML5 Canvas timeline renderer with microsecond time scale.
  - Swimlanes grouped by process or thread.
  - Interactive pan and zoom via mouse drag and wheel.
  - Color-coded waterfall bars: green for filesystem, blue for network, orange for process, red for errors.
  - Slide-over detail drawer displaying syscall parameters, paths, and durations.
  - KPI cards: throughput, total events, error count, unique files accessed, active sockets.

### Phase 6: Exporters and Incident Reports
- JSON Trace Exporter: structured dump for programmatic post-processing.
- CSV Exporter: compatible with spreadsheet and log analysis tools.
- Chrome Trace Event Exporter: exports trace in Chrome format for loading into `chrome://tracing` and `ui.perfetto.dev`.
- Markdown Incident Summary: automated markdown report highlighting root causes of failures.

### Phase 7: CLI and System Verification
- Typer CLI commands:
  - `proctrace run`: execute and trace command.
  - `proctrace attach`: monitor running PID.
  - `proctrace web`: start web studio.
  - `proctrace export`: convert recorded traces.
  - `proctrace doctor`: check OS tracing capabilities and permissions.
- Test suite with pytest:
  - Unit tests for models, ring buffer, filtering, and exporters.
  - Integration tests for subprocess runner, collectors, CLI commands, and web endpoints.

### Phase 8: Advanced Analysis, Regression Diffs, and CI/CD Policy Assertions
- Trace Differ and Regression Detector (`proctrace.core.diff`):
  - Baseline vs current trace comparison with `TraceDiffer`.
  - Automatic detection of latency regressions exceeding 50% delta.
  - Identification of newly broken file lookups (`ENOENT`) and socket failures.
  - Surfacing added and removed network host:port endpoints.
  - Markdown table generation and machine-readable JSON exports.
  - CLI command: `proctrace diff <baseline> <current> [--output <report.md>] [--json]`.
- Root Cause Explainer Engine (`proctrace.analysis.explainer`):
  - Intelligent heuristic diagnostic engine parsing raw syscall failures into root causes.
  - Missing `.env` detection with `.env.example` file template discovery and copy recommendations.
  - Dynamic library load failures (`libssl`, `libcrypto`, `vcruntime140.dll`) mapped to exact package manager install commands (`apt`, `brew`, `vcredist`).
  - Known service port connection refused diagnostics (PostgreSQL:5432, MySQL:3306, Redis:6379, MongoDB:27017) with service start commands.
  - Permission denied (`EACCES`) triage with path ownership and `chmod` recommendations.
  - CLI command: `proctrace explain <trace.json> [--json]`.
- Security Auditor and Exfiltration Detector (`proctrace.security.auditor`):
  - Sensitive credential file access auditing (`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.docker/config.json`, `/etc/shadow`, Windows SAM).
  - Outbound data exfiltration chain detection: flags external socket connections occurring within 5 seconds of sensitive credential file reads.
  - CLI command: `proctrace audit <trace.json> [--json]`.
- CI/CD Operational Policy Guard (`proctrace.security.auditor`):
  - Enforcement of zero-missing-config policies (`--no-missing-configs`).
  - Block unencrypted plaintext HTTP traffic (`--no-unencrypted-http`).
  - Strict maximum latency budgets per system call (`--max-latency-ms <ms>`).
  - Maximum allowable error budgets (`--max-errors <count>`).
  - Non-zero exit code (status 1) on assertion failure for automated pipeline integration.
  - CLI command: `proctrace assert [OPTIONS] -- <command>`.
- Enhanced Web Studio Features:
  - Process Hierarchy Tree modal visualizing parent-child relationship chains.
  - Process Swimlanes view mode grouping events by distinct PID.
  - Remediation Triage modal directly displaying root-cause diagnostics and shell commands.
  - Security and Exfiltration modal providing credential audit summaries and risk badges.

