"""Interactive Textual terminal user interface for ProcTrace."""

from __future__ import annotations

import time
from typing import List, Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from proctrace.core.models import EventCategory, EventResult, SyscallEvent
from proctrace.core.ring_buffer import RingBuffer


class EventDetailModal(ModalScreen):
    """Modal screen displaying detailed inspection for a selected syscall event."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("enter", "dismiss", "Close"),
    ]

    def __init__(self, event: SyscallEvent) -> None:
        super().__init__()
        self.event = event

    def compose(self) -> ComposeResult:
        with Container(classes="modal-dialog"):
            yield Label(f"Syscall Details: {self.event.operation.value} ({self.event.id})", classes="modal-title")

            status_style = "bold red" if self.event.is_error else "bold green"
            details_text = (
                f"Timestamp:    {self.event.timestamp:.6f}\n"
                f"Process:      {self.event.process_name} (PID: {self.event.pid}, PPID: {self.event.ppid})\n"
                f"Category:     {self.event.category.value}\n"
                f"Operation:    {self.event.operation.value}\n"
                f"Target Path:  {self.event.target_path}\n"
                f"Result:       [{status_style}]{self.event.result.value}[/]\n"
                f"Return Code:  {self.event.return_code}\n"
                f"Errno:        {self.event.errno_name or 'None'}\n"
                f"Duration:     {self.event.formatted_duration}\n"
                f"Extra Info:   {self.event.details}\n"
            )
            yield Static(Text.from_markup(details_text), classes="modal-body")
            yield Button("Close (Esc)", variant="primary", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()


class ProcTraceTUI(App):
    """Terminal UI application rendering real-time syscall events and waterfall timeline."""

    CSS = """
    Screen {
        background: #111418;
        color: #e6edf3;
    }

    #top-bar {
        height: 3;
        background: #1b2128;
        padding: 0 1;
        align: left middle;
    }

    .stat-badge {
        margin-right: 2;
        padding: 0 1;
        background: #242c35;
        border-radius: 1;
        color: #58a6ff;
    }

    .stat-badge-err {
        margin-right: 2;
        padding: 0 1;
        background: #3c1e22;
        border-radius: 1;
        color: #f85149;
    }

    #controls-bar {
        height: 3;
        background: #161b22;
        padding: 0 1;
        align: left middle;
    }

    #search-box {
        width: 40;
        margin-right: 2;
    }

    #content-container {
        height: 1fr;
    }

    DataTable {
        height: 1fr;
    }

    #waterfall-pane {
        height: 1fr;
        padding: 1;
        overflow-y: scroll;
        display: none;
    }

    .modal-dialog {
        width: 80;
        height: auto;
        max-height: 80%;
        background: #1b2128;
        border: solid #58a6ff;
        padding: 1 2;
    }

    .modal-title {
        font-weight: bold;
        color: #58a6ff;
        margin-bottom: 1;
    }

    .modal-body {
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("space", "toggle_pause", "Pause/Resume"),
        Binding("e", "toggle_errors", "Errors Only"),
        Binding("w", "toggle_waterfall", "Waterfall"),
        Binding("c", "clear_events", "Clear"),
        Binding("slash", "focus_search", "Search", show=True),
    ]

    def __init__(
        self,
        ring_buffer: RingBuffer,
        title_info: str = "Live Monitor",
    ) -> None:
        super().__init__()
        self.ring_buffer = ring_buffer
        self.title_info = title_info
        self.is_paused = False
        self.errors_only = False
        self.waterfall_mode = False
        self.search_query = ""
        self.displayed_event_ids: set[str] = set()
        self.events_cache: List[SyscallEvent] = []
        self.base_time: float = time.time()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="top-bar"):
            yield Label(f"Target: {self.title_info}", classes="stat-badge")
            yield Label("Events: 0", id="lbl-total-events", classes="stat-badge")
            yield Label("Errors: 0", id="lbl-total-errors", classes="stat-badge-err")
            yield Label("Throughput: 0 evt/s", id="lbl-rate", classes="stat-badge")

        with Horizontal(id="controls-bar"):
            yield Input(placeholder="Search path or syscall (/)...", id="search-box")
            yield Button("Errors Only (E)", id="btn-err", variant="default")
            yield Button("Waterfall Mode (W)", id="btn-waterfall", variant="default")
            yield Button("Pause (Space)", id="btn-pause", variant="default")
            yield Button("Clear (C)", id="btn-clear", variant="default")

        with Container(id="content-container"):
            yield DataTable(id="events-table", zebra_stripes=True, cursor_type="row")
            yield Static(id="waterfall-pane")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#events-table", DataTable)
        table.add_columns("Time", "PID", "Process", "Category", "Operation", "Target Path", "Result", "Duration")

        # Set periodic refresh timer (every 100ms)
        self.set_interval(0.1, self.refresh_view)

    def refresh_view(self) -> None:
        """Poll the ring buffer and update UI tables."""
        if self.is_paused:
            return

        stats = self.ring_buffer.get_stats()

        # Update status labels
        self.query_one("#lbl-total-events", Label).update(f"Events: {stats['total_ingested']:,}")
        self.query_one("#lbl-total-errors", Label).update(f"Errors: {stats['total_errors']:,}")
        self.query_one("#lbl-rate", Label).update(f"Throughput: {int(stats['events_per_sec'])} evt/s")

        # Read latest events from buffer
        all_events = self.ring_buffer.get_all()
        if not all_events:
            return

        if self.base_time == 0.0 or self.base_time > all_events[0].timestamp:
            self.base_time = all_events[0].timestamp

        # Apply filtering
        filtered = []
        for ev in all_events:
            if self.errors_only and not ev.is_error:
                continue
            if self.search_query:
                q = self.search_query.lower()
                if q not in ev.target_path.lower() and q not in ev.operation.value.lower() and q not in ev.process_name.lower():
                    continue
            filtered.append(ev)

        self.events_cache = filtered

        if not self.waterfall_mode:
            table = self.query_one("#events-table", DataTable)
            # Render latest 150 events
            window = filtered[-150:]
            table.clear()
            for ev in window:
                rel_time = f"+{(ev.timestamp - self.base_time):.3f}s"
                res_text = Text(ev.result.value, style="bold red" if ev.is_error else "green")
                cat_color = {
                    EventCategory.FILESYSTEM: "cyan",
                    EventCategory.NETWORK: "blue",
                    EventCategory.PROCESS: "yellow",
                    EventCategory.ENVIRONMENT: "magenta",
                }.get(ev.category, "white")
                cat_text = Text(ev.category.value, style=cat_color)

                table.add_row(
                    rel_time,
                    str(ev.pid),
                    ev.process_name,
                    cat_text,
                    ev.operation.value,
                    ev.target_path,
                    res_text,
                    ev.formatted_duration,
                    key=ev.id,
                )
        else:
            # Render Waterfall ASCII timeline
            pane = self.query_one("#waterfall-pane", Static)
            lines = []
            window = filtered[-40:]
            for ev in window:
                rel_ms = max(0, int((ev.timestamp - self.base_time) * 1000.0))
                dur_ms = max(1, int(ev.duration_us / 1000.0))
                bar_len = min(40, max(1, dur_ms // 2))
                bar_str = "■" * bar_len
                style = "bold red" if ev.is_error else "bold cyan"
                tag = f"[{style}][{bar_str}][/] {ev.operation.value} {ev.target_path[:45]} ({ev.formatted_duration})"
                lines.append(f"T+{rel_ms:6d}ms | {tag}")
            pane.update(Text.from_markup("\n".join(lines) if lines else "No events match active filter."))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-box":
            self.search_query = event.value

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event_id = event.row_key.value
        matched = next((e for e in self.events_cache if e.id == event_id), None)
        if matched:
            self.push_screen(EventDetailModal(matched))

    def action_toggle_pause(self) -> None:
        self.is_paused = not self.is_paused
        btn = self.query_one("#btn-pause", Button)
        btn.label = "Resume (Space)" if self.is_paused else "Pause (Space)"
        btn.variant = "error" if self.is_paused else "default"

    def action_toggle_errors(self) -> None:
        self.errors_only = not self.errors_only
        btn = self.query_one("#btn-err", Button)
        btn.variant = "error" if self.errors_only else "default"

    def action_toggle_waterfall(self) -> None:
        self.waterfall_mode = not self.waterfall_mode
        table = self.query_one("#events-table", DataTable)
        pane = self.query_one("#waterfall-pane", Static)
        btn = self.query_one("#btn-waterfall", Button)

        if self.waterfall_mode:
            table.styles.display = "none"
            pane.styles.display = "block"
            btn.variant = "primary"
        else:
            table.styles.display = "block"
            pane.styles.display = "none"
            btn.variant = "default"

    def action_clear_events(self) -> None:
        self.ring_buffer.clear()
        self.events_cache.clear()
        self.query_one("#events-table", DataTable).clear()
        self.query_one("#waterfall-pane", Static).update("")

    def action_focus_search(self) -> None:
        self.query_one("#search-box", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-pause":
            self.action_toggle_pause()
        elif event.button.id == "btn-err":
            self.action_toggle_errors()
        elif event.button.id == "btn-waterfall":
            self.action_toggle_waterfall()
        elif event.button.id == "btn-clear":
            self.action_clear_events()
