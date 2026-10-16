# ProcTrace CLI Reference

The `proctrace` command line interface controls process execution, attachment, web studio serving, and trace format exports.

## Global Options

- `--version`, `-v`: Display current ProcTrace version.
- `--help`: Print help text and command list.

## Commands

### `proctrace run`
Executes a target command under ProcTrace monitoring.

```bash
proctrace run [OPTIONS] -- COMMAND [ARGS]...
```

#### Options
- `--tui / --no-tui`: Launch the interactive Textual TUI (default: true in interactive terminals).
- `--web / --no-web`: Start the Web Studio server concurrently in the background (default: false).
- `--web-port INTEGER`: Port for Web Studio (default: 8995).
- `--errors-only`, `-e`: Filter for failed syscalls only.
- `--filter-config`, `-f PATH`: Path to a YAML filter preset.
- `--output-json PATH`: Export trace to structured JSON on exit.
- `--output-csv PATH`: Export trace to CSV spreadsheet on exit.
- `--output-chrome PATH`: Export trace in Chrome Trace Event Format for Perfetto.
- `--output-report PATH`: Export an incident triage Markdown report.

#### Examples
```bash
# Run command with interactive TUI
proctrace run -- python app.py

# Run command headlessly and export to Perfetto
proctrace run --no-tui --output-chrome trace.json -- npm test

# Run command while serving Web Studio on port 8995
proctrace run --web --web-port 8995 -- node server.js
```

---

### `proctrace attach`
Attaches ProcTrace to an existing running process by PID.

```bash
proctrace attach [OPTIONS] PID
```

#### Options
- `--tui / --no-tui`: Launch interactive Textual TUI (default: true).
- `--web / --no-web`: Start Web Studio server concurrently (default: false).
- `--web-port INTEGER`: Port for Web Studio (default: 8995).

#### Examples
```bash
# Attach TUI to background process
proctrace attach 4120

# Attach to process and serve Web Studio
proctrace attach 4120 --web --web-port 8995
```

---

### `proctrace web`
Launches the standalone Web Studio server to inspect live or pre-recorded traces.

```bash
proctrace web [OPTIONS]
```

#### Options
- `--port`, `-p INTEGER`: Port to bind Web Studio (default: 8995).
- `--host`, `-h TEXT`: Network interface address (default: 127.0.0.1).
- `--load-trace`, `-l PATH`: Pre-load a saved JSON trace file into the ring buffer.

#### Examples
```bash
# Start empty web studio
proctrace web --port 8995

# Open an existing trace recording in the Web Studio
proctrace web --load-trace trace.json
```

---

### `proctrace export`
Converts recorded trace files between formats.

```bash
proctrace export [OPTIONS] TRACE_FILE
```

#### Options
- `--format`, `-f TEXT`: Target format: `json`, `csv`, `chrome` (Perfetto), or `report` (Markdown).
- `--output`, `-o PATH`: Destination file path.

#### Examples
```bash
# Convert JSON trace to Perfetto format
proctrace export trace.json --format chrome --output trace_perfetto.json

# Generate Markdown triage report
proctrace export trace.json --format report --output incident.md
```

---

### `proctrace doctor`
Inspects system capabilities, permissions, kernel collector availability, and benchmarks ring buffer throughput.

```bash
proctrace doctor
```
