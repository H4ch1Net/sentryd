"""Presentation helpers shared by the CLI and the Textual dashboard.

One source of truth for how severities are colored and timestamps are shown,
so the two terminal interfaces can never drift apart.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentryd.core.alerts import Severity

# rich/Textual style per severity, keep every Severity member covered.
SEVERITY_STYLE: dict[Severity, str] = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


def fmt_ts_utc(ts: float, date: bool = True) -> str:
    fmt = "%Y-%m-%d %H:%M:%S" if date else "%H:%M:%S"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(fmt)
