"""sentryd command-line interface."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentryd import __version__
from sentryd.core.alerts import Alert, Severity
from sentryd.core.cases import CaseStatus
from sentryd.core.correlate import correlate, investigation_hint, related_alerts
from sentryd.export import alerts_to_csv, alerts_to_json, case_report_markdown, case_to_json
from sentryd.render import SEVERITY_STYLE, fmt_ts_utc
from sentryd.runner import run_case
from sentryd.sources.base import SourceError
from sentryd.sources.live import LiveCaptureSource
from sentryd.sources.logtail import LogTailSource
from sentryd.sources.pcap import PcapFileSource
from sentryd.storage.store import DEFAULT_DB_PATH, AlertStore
from sentryd.triage.base import TriageProvider, create_provider
from sentryd.triage.review import generate_case_review

app = typer.Typer(
    name="sentryd",
    help="Network anomaly detection: deterministic rules, optional AI triage.",
    no_args_is_help=True,
)
alerts_app = typer.Typer(help="Query stored alerts.", no_args_is_help=True)
app.add_typer(alerts_app, name="alerts")
cases_app = typer.Typer(help="Manage cases (one case per replay/capture run).", no_args_is_help=True)
app.add_typer(cases_app, name="cases")

console = Console()

DbOption = typer.Option(DEFAULT_DB_PATH, "--db", help="SQLite database path.")
ConfigOption = typer.Option(
    None, "--config", help="Config file (defaults to ./config/signatures.yaml if present)."
)


class ConsoleSink:
    """Engine sink that prints each new alert as a severity-colored line."""

    def emit(self, alert: Alert) -> None:
        style = SEVERITY_STYLE[alert.severity]
        console.print(
            f"[{style}]{alert.severity.value.upper():>8}[/{style}] "
            f"[dim]{fmt_ts_utc(alert.ts)}[/dim] "
            f"[bold]{alert.rule_id}[/bold] {alert.title} "
            f"[dim](confidence {alert.confidence:.2f})[/dim]"
        )

    def update(self, alert: Alert) -> None:
        pass  # duplicate merges are reflected in storage, not re-printed


def _triage_alerts(store: AlertStore, alerts: list[Alert]) -> None:
    """Run AI triage over freshly stored alerts; a missing key is a no-op."""
    provider = create_provider()
    if not provider.available:
        console.print(
            "[dim]AI triage skipped — set OPENROUTER_API_KEY in .env to enable it. "
            "All alerts are fully recorded without it.[/dim]"
        )
        return
    for alert in alerts:
        result = provider.triage(alert)
        if result is None:
            console.print(f"[yellow]AI triage failed for alert #{alert.id} (see logs)[/yellow]")
            continue
        store.set_ai_summary(alert.id, result.summary)
        console.print(Panel(result.summary, title=f"AI triage — alert #{alert.id} ({result.model})"))


class CollectorSink:
    """Engine sink that remembers every new alert (for post-run triage)."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def update(self, alert: Alert) -> None:
        pass


def _run_detection(
    source,
    banner: str,
    db: Path,
    config: Optional[Path],
    triage: bool,
    *,
    source_kind: str,
    source_label: str,
    case_name: Optional[str] = None,
) -> None:
    """Shared pipeline runner for replay/sniff/tail.

    Each run becomes a case. Ctrl-C stops endless sources cleanly; AI triage
    (when requested) runs only after detection has finished.
    """
    collector = CollectorSink()
    console.print(f"[bold]sentryd[/bold] v{__version__}, {banner}")
    try:
        result = run_case(
            db,
            source,
            source_kind=source_kind,
            source_label=source_label,
            name=case_name,
            config_path=config,
            extra_sinks=[ConsoleSink(), collector],
        )
    except SourceError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1)
    if result.interrupted:
        console.print("\n[dim]stopped[/dim]")

    if triage and collector.alerts:
        console.print()
        with AlertStore(db) as store:
            _triage_alerts(store, collector.alerts)

    stats = result.stats
    console.print(
        f"\n[bold]done[/bold]: {stats.events_processed} events, "
        f"{stats.alerts_emitted} alerts "
        f"({stats.alerts_deduplicated} duplicates merged)"
    )
    for sev in Severity:
        n = stats.by_severity.get(sev.value)
        if n:
            style = SEVERITY_STYLE[sev]
            console.print(f"  [{style}]{sev.value}[/{style}]: {n}")
    console.print(
        f"case [bold]#{result.case.id}[/bold] ({result.case.name}) stored in "
        f"[cyan]{db}[/cyan]. Inspect with `sentryd cases show {result.case.id}` "
        f"or `sentryd alerts list --case {result.case.id}`"
    )


TriageFlag = typer.Option(
    False, "--triage", help="Generate AI writeups for detected alerts afterwards."
)


CaseNameOption = typer.Option(None, "--case-name", help="Name for the created case.")


@app.command()
def replay(
    pcap: Path = typer.Argument(..., help="pcap/pcapng file to replay."),
    db: Path = DbOption,
    config: Optional[Path] = ConfigOption,
    triage: bool = TriageFlag,
    case_name: Optional[str] = CaseNameOption,
) -> None:
    """Replay a capture file through the detection engine (primary demo mode)."""
    _run_detection(
        PcapFileSource(pcap),
        f"replaying [cyan]{pcap}[/cyan]",
        db,
        config,
        triage,
        source_kind="pcap",
        source_label=str(pcap),
        case_name=case_name,
    )


@app.command()
def sniff(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="Interface to capture on (default: scapy's default)."
    ),
    bpf: Optional[str] = typer.Option(
        None, "--filter", help='BPF capture filter, e.g. "tcp or arp".'
    ),
    db: Path = DbOption,
    config: Optional[Path] = ConfigOption,
    triage: bool = TriageFlag,
    case_name: Optional[str] = CaseNameOption,
) -> None:
    """Live capture (requires root). Ctrl-C stops and prints the summary.

    With --triage, AI writeups are generated after capture stops; triage
    never runs in the packet path.
    """
    source = LiveCaptureSource(interface=interface, bpf_filter=bpf)
    where = interface or "default interface"
    _run_detection(
        source,
        f"sniffing [cyan]{where}[/cyan] (Ctrl-C to stop)",
        db,
        config,
        triage,
        source_kind="live",
        source_label=where,
        case_name=case_name,
    )


@app.command()
def tail(
    logfile: Path = typer.Argument(..., help="JSON-lines traffic log to follow."),
    from_start: bool = typer.Option(
        True,
        "--from-start/--new-only",
        help="Process existing lines first, or only lines appended from now on.",
    ),
    follow: bool = typer.Option(
        True, "--follow/--no-follow", help="Keep watching for new lines (Ctrl-C to stop)."
    ),
    db: Path = DbOption,
    config: Optional[Path] = ConfigOption,
    triage: bool = TriageFlag,
    case_name: Optional[str] = CaseNameOption,
) -> None:
    """Stream a JSON-lines traffic log through the detection engine.

    Line format: one JSON object per line with ts, protocol, src_ip, dst_ip,
    src_port, dst_port, tcp_flags, length (all optional but the more the
    rules can see, the more they can do).
    """
    source = LogTailSource(logfile, follow=follow, from_start=from_start)
    _run_detection(
        source,
        f"tailing [cyan]{logfile}[/cyan]",
        db,
        config,
        triage,
        source_kind="log",
        source_label=str(logfile),
        case_name=case_name,
    )


@alerts_app.command("list")
def alerts_list(
    db: Path = DbOption,
    severity: Optional[str] = typer.Option(None, help="Filter: low|medium|high|critical."),
    rule: Optional[str] = typer.Option(None, help="Filter by rule id."),
    status: Optional[str] = typer.Option(None, help="Filter: new|triaged|dismissed."),
    case: Optional[int] = typer.Option(None, "--case", help="Only alerts from this case."),
    limit: int = typer.Option(50, help="Max rows."),
) -> None:
    """List stored alerts, newest first."""
    with AlertStore(db) as store:
        rows = store.list(severity=severity, rule_id=rule, status=status, case_id=case, limit=limit)

    if not rows:
        console.print("no alerts found")
        return

    table = Table(title=f"alerts ({len(rows)})")
    table.add_column("id", justify="right")
    table.add_column("time")
    table.add_column("severity")
    table.add_column("rule")
    table.add_column("src")
    table.add_column("dst")
    table.add_column("title", overflow="fold")
    table.add_column("count", justify="right")
    table.add_column("status")
    table.add_column("AI", justify="center")
    for a in rows:
        style = SEVERITY_STYLE[a.severity]
        table.add_row(
            str(a.id),
            fmt_ts_utc(a.ts),
            f"[{style}]{a.severity.value}[/{style}]",
            a.rule_id,
            a.src or "-",
            a.dst or "-",
            a.title,
            str(a.count),
            a.status.value,
            "yes" if a.ai_summary else "-",
        )
    console.print(table)


@alerts_app.command("show")
def alerts_show(
    alert_id: int = typer.Argument(..., help="Alert id (see `alerts list`)."),
    db: Path = DbOption,
) -> None:
    """Show one alert in full: what fired, why, evidence, and where to go next."""
    with AlertStore(db) as store:
        alert = store.get(alert_id)
        related = related_alerts(store, alert) if alert else []

    if alert is None:
        console.print(f"[red]error:[/red] no alert with id {alert_id}")
        raise typer.Exit(code=1)

    style = SEVERITY_STYLE[alert.severity]
    ports = ""
    if alert.src_port or alert.dst_port:
        ports = f"ports:      {alert.src_port or '?'} -> {alert.dst_port or '?'}\n"
    header = (
        f"[{style}]{alert.severity.value.upper()}[/{style}] {alert.title}\n\n"
        f"rule:       {alert.rule_id}\n"
        f"case:       {'#' + str(alert.case_id) if alert.case_id else '-'}\n"
        f"first seen: {fmt_ts_utc(alert.ts)} UTC\n"
        f"last seen:  {fmt_ts_utc(alert.last_seen)} UTC\n"
        f"source:     {alert.src or '-'}\n"
        f"target:     {alert.dst or '-'}\n"
        f"protocol:   {alert.protocol or '-'}\n"
        f"{ports}"
        f"confidence: {alert.confidence:.2f}\n"
        f"count:      {alert.count}\n"
        f"status:     {alert.status.value}"
    )
    console.print(Panel(header, title=f"alert #{alert.id}"))
    if alert.reason:
        console.print(Panel(alert.reason, title="why this fired"))
    console.print(Panel(json.dumps(alert.evidence, indent=2), title="evidence"))
    if related:
        lines = [
            f"#{r.id}  [{SEVERITY_STYLE[r.severity]}]{r.severity.value:<8}[/{SEVERITY_STYLE[r.severity]}] {r.rule_id}: {r.title}"
            for r in related[:6]
        ]
        console.print(Panel("\n".join(lines), title="related alerts (same hosts)"))
    console.print(Panel(investigation_hint(alert), title="suggested next step"))
    if alert.ai_summary:
        console.print(Panel(alert.ai_summary, title="AI triage"))
    else:
        console.print(f"[dim]no AI triage yet. Run `sentryd triage {alert.id}`[/dim]")


export_app = typer.Typer(help="Export alerts and case reports.", no_args_is_help=True)
app.add_typer(export_app, name="export")


def _write_export(content: str, output: Optional[Path], what: str) -> None:
    if output is None:
        print(content)
    else:
        output.write_text(content)
        console.print(f"{what} written to [cyan]{output}[/cyan]")


@export_app.command("alerts")
def export_alerts(
    db: Path = DbOption,
    format: str = typer.Option("json", "--format", help="json or csv."),
    case: Optional[int] = typer.Option(None, "--case", help="Only alerts from this case."),
    severity: Optional[str] = typer.Option(None, help="Filter: low|medium|high|critical."),
    rule: Optional[str] = typer.Option(None, help="Filter by rule id."),
    limit: int = typer.Option(1000, help="Max alerts."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write to file."),
) -> None:
    """Export alerts as JSON or CSV (stdout by default)."""
    if format not in ("json", "csv"):
        console.print(f"[red]error:[/red] unsupported format {format!r} (json, csv)")
        raise typer.Exit(code=1)
    with AlertStore(db) as store:
        alerts = store.list(
            severity=severity, rule_id=rule, case_id=case, limit=limit
        )
    content = alerts_to_json(alerts) if format == "json" else alerts_to_csv(alerts)
    _write_export(content, output, f"{len(alerts)} alerts ({format})")


@export_app.command("case")
def export_case(
    case_id: int = typer.Argument(..., help="Case id to export."),
    db: Path = DbOption,
    format: str = typer.Option("md", "--format", help="md (analyst report) or json (bundle)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write to file."),
) -> None:
    """Export one case as a markdown report or a JSON bundle.

    The markdown report is complete without AI; a stored AI review is
    appended as its own labeled section.
    """
    if format not in ("md", "json"):
        console.print(f"[red]error:[/red] unsupported format {format!r} (md, json)")
        raise typer.Exit(code=1)
    with AlertStore(db) as store:
        case = store.get_case(case_id)
        if case is None:
            console.print(f"[red]error:[/red] no case with id {case_id}")
            raise typer.Exit(code=1)
        alerts = store.list(case_id=case_id, limit=1000)
    clusters = correlate(alerts)
    content = (
        case_report_markdown(case, alerts, clusters)
        if format == "md"
        else case_to_json(case, alerts, clusters)
    )
    _write_export(content, output, f"case #{case_id} report ({format})")


CASE_STATUS_STYLE = {
    CaseStatus.RUNNING: "yellow",
    CaseStatus.COMPLETE: "green",
    CaseStatus.FAILED: "red",
    CaseStatus.ARCHIVED: "dim",
}


@cases_app.command("list")
def cases_list(
    db: Path = DbOption,
    all: bool = typer.Option(False, "--all", help="Include archived cases."),
) -> None:
    """List cases, newest first."""
    with AlertStore(db) as store:
        rows = store.list_cases(include_archived=all)
    if not rows:
        console.print("no cases yet. Create one with `sentryd replay <file.pcap>`")
        return
    table = Table(title=f"cases ({len(rows)})")
    for col in ("id", "name", "source", "status", "events", "alerts", "created (UTC)", "AI report"):
        table.add_column(col)
    for c in rows:
        style = CASE_STATUS_STYLE[c.status]
        table.add_row(
            str(c.id),
            c.name,
            f"{c.source_kind}:{c.source}",
            f"[{style}]{c.status.value}[/{style}]",
            str(c.events_processed),
            str(c.alert_count),
            c.created_at,
            "yes" if c.ai_report else "-",
        )
    console.print(table)


@cases_app.command("show")
def cases_show(
    case_id: int = typer.Argument(..., help="Case id (see `cases list`)."),
    db: Path = DbOption,
) -> None:
    """Show one case: metadata, alert summary, notes, and AI report if any."""
    with AlertStore(db) as store:
        case = store.get_case(case_id)
        if case is None:
            console.print(f"[red]error:[/red] no case with id {case_id}")
            raise typer.Exit(code=1)
        alerts = store.list(case_id=case_id, limit=500)
        stats = store.stats(case_id=case_id)

    style = CASE_STATUS_STYLE[case.status]
    span = (
        f"{fmt_ts_utc(case.start_ts)} to {fmt_ts_utc(case.end_ts)} UTC"
        if case.start_ts is not None and case.end_ts is not None
        else "-"
    )
    body = (
        f"[bold]{case.name}[/bold]  [{style}]{case.status.value}[/{style}]\n\n"
        f"source:     {case.source_kind}:{case.source}\n"
        f"created:    {case.created_at} UTC\n"
        f"traffic:    {case.events_processed} events, span {span}\n"
        f"alerts:     {case.alert_count}"
        f" ({', '.join(f'{k}: {v}' for k, v in sorted(stats['by_severity'].items())) or 'none'})\n"
    )
    if case.pcap_sha256:
        size = f"{case.pcap_size:,} bytes" if case.pcap_size is not None else "?"
        body += f"pcap:       sha256 {case.pcap_sha256[:16]}..., {size}\n"
    if case.error:
        body += f"error:      [red]{case.error}[/red]\n"
    if case.notes:
        body += f"notes:      {case.notes}\n"
    console.print(Panel(body.rstrip(), title=f"case #{case.id}"))

    if alerts:
        table = Table(title="alerts in this case")
        for col in ("id", "first seen", "severity", "rule", "src", "dst", "count", "title"):
            table.add_column(col)
        for a in alerts[:30]:
            sev_style = SEVERITY_STYLE[a.severity]
            table.add_row(
                str(a.id),
                fmt_ts_utc(a.ts),
                f"[{sev_style}]{a.severity.value}[/{sev_style}]",
                a.rule_id,
                a.src or "-",
                a.dst or "-",
                str(a.count),
                a.title,
            )
        console.print(table)

    clusters = correlate(alerts)
    if clusters:
        lines = []
        for cluster in clusters[:8]:
            targets = ", ".join(cluster.targets[:3]) or "-"
            if len(cluster.targets) > 3:
                targets += f" (+{len(cluster.targets) - 3} more)"
            sev_style = SEVERITY_STYLE[Severity(cluster.max_severity)]
            lines.append(
                f"[{sev_style}]{cluster.max_severity:<8}[/{sev_style}] "
                f"[bold]{cluster.source}[/bold] -> {targets}\n"
                f"         {cluster.chain}  "
                f"[dim]({len(cluster.alerts)} alerts, "
                f"{fmt_ts_utc(cluster.first_seen, date=False)} to "
                f"{fmt_ts_utc(cluster.last_seen, date=False)} UTC)[/dim]"
            )
        console.print(Panel("\n".join(lines), title="correlated activity"))

    if case.ai_report:
        console.print(Panel(case.ai_report, title=f"AI review ({case.ai_report_at} UTC)"))
    else:
        console.print(f"[dim]no AI review yet. Run `sentryd triage --case {case.id}`[/dim]")


@cases_app.command("archive")
def cases_archive(
    case_id: int = typer.Argument(..., help="Case id to archive."),
    db: Path = DbOption,
) -> None:
    """Archive a case (hidden from default listings, data kept)."""
    with AlertStore(db) as store:
        if store.get_case(case_id) is None:
            console.print(f"[red]error:[/red] no case with id {case_id}")
            raise typer.Exit(code=1)
        store.set_case_status(case_id, CaseStatus.ARCHIVED)
    console.print(f"case #{case_id} archived")


@cases_app.command("delete")
def cases_delete(
    case_id: int = typer.Argument(..., help="Case id to delete."),
    db: Path = DbOption,
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt."),
) -> None:
    """Delete a case and every alert it produced."""
    with AlertStore(db) as store:
        case = store.get_case(case_id)
        if case is None:
            console.print(f"[red]error:[/red] no case with id {case_id}")
            raise typer.Exit(code=1)
        if not yes:
            typer.confirm(
                f"Delete case #{case_id} ({case.name}) and its {case.alert_count} alerts?",
                abort=True,
            )
        n = store.delete_case(case_id)
    console.print(f"deleted case #{case_id} and {n} alerts")


@cases_app.command("clear")
def cases_clear(
    db: Path = DbOption,
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt."),
) -> None:
    """Delete ALL cases and alerts (fresh workspace)."""
    if not yes:
        typer.confirm("Delete every case and alert in this database?", abort=True)
    with AlertStore(db) as store:
        store.clear()
    console.print("workspace cleared")


@cases_app.command("notes")
def cases_notes(
    case_id: int = typer.Argument(..., help="Case id."),
    text: str = typer.Argument(..., help="Notes to attach (replaces existing notes)."),
    db: Path = DbOption,
) -> None:
    """Attach analyst notes to a case."""
    with AlertStore(db) as store:
        if store.get_case(case_id) is None:
            console.print(f"[red]error:[/red] no case with id {case_id}")
            raise typer.Exit(code=1)
        store.set_case_notes(case_id, text)
    console.print(f"notes saved on case #{case_id}")


@app.command()
def dash(
    db: Path = DbOption,
    pcap: Optional[Path] = typer.Option(
        None, "--pcap", help="Replay this capture live in the dashboard (timed playback)."
    ),
    config: Optional[Path] = ConfigOption,
    speed: float = typer.Option(
        1.0, "--speed", help="Playback speed multiplier for --pcap (0 = as fast as possible)."
    ),
) -> None:
    """Terminal dashboard: live alert table with drill-down detail view.

    Without --pcap it browses the alert store (and picks up new alerts as
    they land); with --pcap it replays the capture paced by packet
    timestamps — ideal for a screen-recorded demo.
    """
    from sentryd.dashboard.app import DashboardApp

    DashboardApp(db_path=db, pcap=pcap, config_path=config, speed=speed).run()


@app.command()
def web(
    db: Path = DbOption,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", help="Listen port."),
) -> None:
    """Serve the web UI: filterable alert table, detail view, stats."""
    import uvicorn

    from sentryd.web.api import create_app

    console.print(f"[bold]sentryd[/bold] web UI on [cyan]http://{host}:{port}[/cyan] (db: {db})")
    uvicorn.run(create_app(db), host=host, port=port, log_level="warning")


NO_AI_MESSAGE = (
    "[yellow]AI triage is not configured.[/yellow] Set OPENROUTER_API_KEY "
    "in .env (see .env.example). Detection and evidence are complete without it."
)


def _triage_alert_by_id(store: AlertStore, alert_id: int, force: bool, as_json: bool) -> None:
    alert = store.get(alert_id)
    if alert is None:
        console.print(f"[red]error:[/red] no alert with id {alert_id}")
        raise typer.Exit(code=1)
    if alert.ai_summary and not force:
        if as_json:
            print(json.dumps({"alert": alert.to_dict(), "cached": True}, default=str))
        else:
            console.print(Panel(alert.ai_summary, title=f"AI triage: alert #{alert.id} (cached)"))
            console.print("[dim]use --force to regenerate[/dim]")
        return

    provider: TriageProvider = create_provider()
    if not provider.available:
        console.print(NO_AI_MESSAGE)
        raise typer.Exit(code=2)
    result = provider.triage(alert)
    if result is None:
        console.print("[red]error:[/red] triage request failed, alert left unannotated")
        raise typer.Exit(code=1)
    store.set_ai_summary(alert.id, result.summary)
    if as_json:
        print(json.dumps({"alert": store.get(alert.id).to_dict()}, default=str))
    else:
        console.print(Panel(result.summary, title=f"AI triage: alert #{alert.id} ({result.model})"))


def _review_case(store: AlertStore, case, force: bool, as_json: bool) -> None:
    if case is None:
        console.print("[red]error:[/red] no such case (see `sentryd cases list`)")
        raise typer.Exit(code=1)
    provider = create_provider()
    if not provider.available and not (case.ai_report and not force):
        console.print(NO_AI_MESSAGE)
        raise typer.Exit(code=2)
    cached = bool(case.ai_report) and not force
    report = generate_case_review(store, case, provider, force=force)
    if report is None:
        console.print("[red]error:[/red] review request failed, case left unannotated")
        raise typer.Exit(code=1)
    if as_json:
        print(
            json.dumps(
                {"case": store.get_case(case.id).to_dict(), "cached": cached}, default=str
            )
        )
    else:
        suffix = " (cached)" if cached else ""
        console.print(Panel(report, title=f"AI review: case #{case.id} {case.name}{suffix}"))
        if cached:
            console.print("[dim]use --force to regenerate[/dim]")


@app.command()
def triage(
    target: Optional[str] = typer.Argument(
        None, help="Alert id for a single-alert writeup, or 'latest' for the newest case."
    ),
    case: Optional[int] = typer.Option(None, "--case", help="Overall AI review of this case."),
    pcap: Optional[Path] = typer.Option(
        None, "--pcap", help="Replay this capture into a new case, then review it."
    ),
    db: Path = DbOption,
    config: Optional[Path] = ConfigOption,
    as_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    force: bool = typer.Option(False, "--force", help="Regenerate even if a report is cached."),
) -> None:
    """AI triage: explain one alert, or review a whole case.

    Forms: `triage 12` (alert), `triage latest`, `triage --case 3`,
    `triage --pcap capture.pcap`. Detection never depends on this; without
    an API key everything else keeps working.

    Only structured alert metadata is sent to the AI (a size-capped digest
    for case reviews), never raw packet contents, and only when you run
    this command.
    """
    if sum(x is not None for x in (target, case, pcap)) != 1:
        console.print(
            "[red]error:[/red] pick exactly one of: an alert id, 'latest', --case, --pcap"
        )
        raise typer.Exit(code=1)

    if pcap is not None:
        result = _run_case_quiet(pcap, db, config)
        with AlertStore(db) as store:
            _review_case(store, store.get_case(result.case.id), force, as_json)
        return

    with AlertStore(db) as store:
        if case is not None:
            _review_case(store, store.get_case(case), force, as_json)
        elif target == "latest":
            _review_case(store, store.latest_case(), force, as_json)
        elif target is not None and target.lstrip("-").isdigit():
            _triage_alert_by_id(store, int(target), force, as_json)
        else:
            console.print(f"[red]error:[/red] expected an alert id or 'latest', got {target!r}")
            raise typer.Exit(code=1)


def _run_case_quiet(pcap: Path, db: Path, config: Optional[Path]):
    """Replay for `triage --pcap`: terse output, then hand back the case."""
    try:
        result = run_case(
            db,
            PcapFileSource(pcap),
            source_kind="pcap",
            source_label=str(pcap),
            config_path=config,
        )
    except SourceError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(
        f"[dim]replayed {pcap} into case #{result.case.id}: "
        f"{result.stats.events_processed} events, "
        f"{result.stats.alerts_emitted} alerts[/dim]"
    )
    return result


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)


if __name__ == "__main__":
    app()
