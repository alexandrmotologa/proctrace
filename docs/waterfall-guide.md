# Syscall Waterfall Timeline Guide

The ProcTrace waterfall timeline visualizes system calls with microsecond precision, modeled after the Chrome DevTools Network and Performance panels.

## Timeline Anatomy

Each system call is represented by a horizontal waterfall bar:

```
T+0ms                                  T+50ms                                 T+100ms
|--------------------------------------|--------------------------------------|
[■■■■■] OPEN .env (42 µs)
        [■■■■■■■■■■■■■■■■] READ config.json (180 µs)
                         [■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■] CONNECT 127.0.0.1:5432 (1.2 ms)
```

### Visual Indicators

1. **Horizontal Position**:
   - The left edge corresponds to the exact start offset: `event.timestamp - session.start_time`.
2. **Bar Width**:
   - Proportional to the system call duration (`event.duration_us`). Fast system calls retain a minimum 3-pixel width for visibility.
3. **Category Color Coding**:
   - Green: Filesystem (`OPEN`, `READ`, `WRITE`, `CLOSE`, `DELETE`).
   - Blue: Network (`CONNECT`, `ACCEPT`, `LISTEN`).
   - Orange: Process (`SPAWN`, `FORK`, `EXEC`, `EXIT`).
   - Purple: Environment (`LOAD_LIBRARY`, `ENV_LOOKUP`).
   - Bright Red: Failed system calls (`ENOENT`, `EACCES`, `ECONNREFUSED`).

## Navigation & Controls

- **Pan and Zoom**: Scroll horizontally or use the time range slider to zoom into high-frequency bursts.
- **Errors Only Toggle**: Hides successful events and displays broken lookups and failed connections.
- **Slide-over Drawer**: Click any waterfall bar to view full parameters, return codes, errno strings, and copy the raw event as JSON.
- **Anomaly Triage Modal**: Click "Anomaly Triage" in the top bar to inspect aggregated root cause summaries.
