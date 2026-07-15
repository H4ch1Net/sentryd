"""Textual terminal dashboard.

Two modes, same widgets:

- **browse** (default): shows alerts already in the SQLite store and polls
  for new ones — pair it with a live `sentryd sniff` in another terminal.
- **playback** (``--pcap``): replays a capture through the engine in a
  background thread, pacing packets by their timestamps so alerts appear on
  screen as they "happened" — built for screen-recorded demos.

Detection runs exactly as in the headless CLI; the dashboard is only another
consumer of alerts.
"""

from __future__ import annotations

import json
import queue
import time
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from sentryd.core.alerts import Alert
from sentryd.render import SEVERITY_STYLE, fmt_ts_utc
from sentryd.storage.store import AlertStore

COLUMNS = ("id", "time", "severity", "rule", "src", "dst", "count", "title")


class QueueSink:
    """Engine sink bridging the detection thread to the UI thread."""

    def __init__(self, q: queue.Queue) -> None:
        self.q = q

    def emit(self, alert: Alert) -> None:
        self.q.put(("new", alert))

    def update(self, alert: Alert) -> None:
        self.q.put(("update", alert))


class AlertDetail(Screen):
    """Drill-down view: full metadata, raw evidence, AI writeup if present."""

    BINDINGS = [Binding("escape,q", "app.pop_screen", "back")]

    def __init__(self, alert: Alert) -> None:
        super().__init__()
        self.alert = alert

    def compose(self) -> ComposeResult:
        a = self.alert
        style = SEVERITY_STYLE[a.severity]
        meta = Text()
        meta.append(f"{a.severity.value.upper()}  ", style=style)
        meta.append(a.title, style="bold")
        meta.append(
            f"\n\nrule:       {a.rule_id}"
            f"\ntime:       {fmt_ts_utc(a.ts, date=False)} UTC"
            f"\nsource:     {a.src or '-'}"
            f"\ntarget:     {a.dst or '-'}"
            f"\nconfidence: {a.confidence:.2f}"
            f"\noccurrences:{a.count:>2}"
            f"\nstatus:     {a.status.value}"
        )
        yield Header(show_clock=True)
        with VerticalScroll():
            yield Static(meta, classes="detail-block")
            yield Static(
                Text("evidence\n", style="bold underline")
                + Text(json.dumps(a.evidence, indent=2, default=str)),
                classes="detail-block",
            )
            if a.ai_summary:
                yield Static(
                    Text("AI triage\n", style="bold underline") + Text(a.ai_summary),
                    classes="detail-block",
                )
            else:
                yield Static(
                    Text(f"no AI triage yet — run: sentryd triage {a.id}", style="dim"),
                    classes="detail-block",
                )
        yield Footer()


class DashboardApp(App):
    """Live alert table; Enter drills into a detail view."""

    TITLE = "sentryd"
    CSS = """
    .detail-block { padding: 1 2; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("enter", "open_detail", "detail", show=True),
    ]

    def __init__(
        self,
        db_path: Path,
        pcap: Path | None = None,
        config_path: Path | None = None,
        speed: float = 1.0,
        poll_interval: float = 2.0,
    ) -> None:
        super().__init__()
        self.db_path = db_path
        self.pcap = pcap
        self.config_path = config_path
        self.speed = speed
        self.poll_interval = poll_interval
        self._queue: queue.Queue = queue.Queue()
        self._alerts: dict[int, Alert] = {}  # id -> latest view of the alert
        self._replay_done = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for col in COLUMNS:
            table.add_column(col, key=col)
        if self.pcap is not None:
            self.sub_title = f"replaying {self.pcap} (x{self.speed:g})"
            self.run_worker(self._replay_worker, thread=True)
            self.set_interval(0.2, self._drain_queue)
        else:
            self.sub_title = f"browsing {self.db_path}"
            self._load_from_store()
            self.set_interval(self.poll_interval, self._load_from_store)

    # -- playback mode ---------------------------------------------------------

    def _replay_worker(self) -> None:
        """Run detection over the pcap with event-time pacing (worker thread).

        The store is created here because sqlite connections are bound to
        their thread; the UI only ever sees alerts via the queue.
        """
        from sentryd.config import load_config
        from sentryd.core.engine import RuleEngine
        from sentryd.rules.base import build_rules
        from sentryd.sources.pcap import PcapFileSource

        store = AlertStore(self.db_path)
        config = load_config(self.config_path)
        engine = RuleEngine(
            rules=build_rules(config),
            sinks=[store, QueueSink(self._queue)],
            cooldown_seconds=config.get("engine", {}).get("cooldown_seconds", 60),
        )
        try:
            prev_ts: float | None = None
            for event in PcapFileSource(self.pcap).events():
                if prev_ts is not None and self.speed > 0:
                    # Sleep the inter-packet gap (capped: dead air helps nobody).
                    time.sleep(min(max(event.ts - prev_ts, 0.0) / self.speed, 3.0))
                prev_ts = event.ts
                engine.process(event)
            engine.flush()
        finally:
            store.close()
            self._queue.put(("done", None))

    def _drain_queue(self) -> None:
        while True:
            try:
                kind, alert = self._queue.get_nowait()
            except queue.Empty:
                return
            if kind == "done":
                self._replay_done = True
                self.sub_title = f"replay finished — alerts stored in {self.db_path}"
            elif kind == "new":
                self._add_alert(alert)
            elif kind == "update":
                self._update_alert(alert)

    # -- browse mode -------------------------------------------------------------

    def _load_from_store(self) -> None:
        with AlertStore(self.db_path) as store:
            for alert in reversed(store.list(limit=500)):  # oldest first
                if alert.id in self._alerts:
                    self._update_alert(alert)
                else:
                    self._add_alert(alert)

    # -- shared table plumbing -----------------------------------------------------

    def _add_alert(self, alert: Alert) -> None:
        if alert.id is None:
            return
        self._alerts[alert.id] = alert
        table = self.query_one(DataTable)
        style = SEVERITY_STYLE[alert.severity]
        table.add_row(
            str(alert.id),
            fmt_ts_utc(alert.ts, date=False),
            Text(alert.severity.value, style=style),
            alert.rule_id,
            alert.src or "-",
            alert.dst or "-",
            str(alert.count),
            alert.title,
            key=str(alert.id),
        )
        table.scroll_end(animate=False)

    def _update_alert(self, alert: Alert) -> None:
        if alert.id is None or alert.id not in self._alerts:
            return
        self._alerts[alert.id] = alert
        table = self.query_one(DataTable)
        row_key = str(alert.id)
        table.update_cell(row_key, "count", str(alert.count))
        table.update_cell(
            row_key, "severity", Text(alert.severity.value, style=SEVERITY_STYLE[alert.severity])
        )

    def action_open_detail(self) -> None:
        table = self.query_one(DataTable)
        if table.cursor_row is None or table.row_count == 0:
            return
        row_key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
        alert = self._alerts.get(int(row_key.value))
        if alert is not None:
            self.push_screen(AlertDetail(alert))

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        alert = self._alerts.get(int(message.row_key.value))
        if alert is not None:
            self.push_screen(AlertDetail(alert))
