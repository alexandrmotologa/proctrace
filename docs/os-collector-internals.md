# Operating System Collector Internals

ProcTrace uses native kernel and user-space hooks on Windows, Linux, and macOS to observe process activity with microsecond latency.

## Windows Collector (`proctrace.collectors.windows`)

Windows does not expose a single system call interception layer like Linux `ptrace`. ProcTrace coordinates several Win32 subsystems:

1. **Filesystem Change Interception**:
   - Uses `ReadDirectoryChangesW` via `ctypes.windll.kernel32`.
   - Listens for filesystem notifications including file additions, deletions, modifications, and renames across watched directories.
   - Translates `FILE_NOTIFY_INFORMATION` structs into `OPEN`, `WRITE`, `DELETE`, and `RENAME` events.

2. **Process and Handle Tracking**:
   - Uses `psutil` and Win32 process snapshot APIs (`CreateToolhelp32Snapshot`).
   - Polls active file handles with `proc.open_files()` to identify newly opened files.
   - Monitors active socket tables via IP Helper APIs (`GetExtendedTcpTable`, `GetExtendedUdpTable`) to capture TCP/UDP connections.
   - Inspects memory mapped images via `proc.memory_maps()` to identify loaded dynamic-link libraries (`.dll`).

3. **Subprocess Management**:
   - `SubprocessRunner` spawns child processes using `subprocess.Popen` and registers the target PID and its child process tree recursively.

## Linux Collector (`proctrace.collectors.linux`)

Linux provides kernel tracing primitives through `ptrace` and `/proc`:

1. **System Call Interception**:
   - Translates x86_64 and arm64 system call numbers into standardized operations:
     - `SYS_open` (2), `SYS_openat` (257) -> `OPEN`
     - `SYS_read` (0), `SYS_pread64` (17) -> `READ`
     - `SYS_write` (1), `SYS_pwrite64` (18) -> `WRITE`
     - `SYS_close` (3) -> `CLOSE`
     - `SYS_connect` (42) -> `CONNECT`
     - `SYS_execve` (59) -> `EXEC`
     - `SYS_clone` (56), `SYS_fork` (57) -> `SPAWN`
   - Decodes negative return values into errno names (`-ENOENT`, `-EACCES`, `-ECONNREFUSED`).

2. **Procfs Integration & Streaming**:
   - Scans `/proc/<pid>/fd/` symbolic links to discover open file descriptors and sockets.
   - Supports streaming `strace` output with microsecond timestamp extraction (`strace -f -T -tt -y -s 256`).

## macOS Collector (`proctrace.collectors.macos`)

macOS tracing uses DTrace and process telemetry:

1. **DTrace Probes**:
   - Intercepts entry and exit probes using `dtruss` or custom DTrace scripts.
   - Maps Darwin errno return numbers (`Err#2` for ENOENT, `Err#13` for EACCES, `Err#61` for ECONNREFUSED).

2. **Process Inspection**:
   - Uses `psutil` Darwin bindings to inspect process open files and network socket tables.
