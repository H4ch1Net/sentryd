"""Exports: alerts as JSON/CSV, cases as markdown reports or JSON bundles.

Everything here is deterministic. The case markdown report is a complete
analyst artifact on its own; when an AI review exists it is appended as its
own section, clearly labeled.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from sentryd.core.alerts import Alert
from sentryd.core.cases import Case
from sentryd.core.correlate import Cluster, investigation_hint

CSV_COLUMNS = [
    "id",
    "case_id",
    "first_seen_utc",
    "last_seen_utc",
    "severity",
    "confidence",
    "rule",
    "src",
    "src_port",
    "dst",
    "dst_port",
    "protocol",
    "count",
    "status",
    "title",
    "reason",
]


def _iso(ts: float | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def alerts_to_json(alerts: list[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2, default=str)


def alerts_to_csv(alerts: list[Alert]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for a in alerts:
        writer.writerow(
            [
                a.id,
                a.case_id,
                _iso(a.ts),
                _iso(a.last_seen),
                a.severity.value,
                a.confidence,
                a.rule_id,
                a.src or "",
                a.src_port or "",
                a.dst or "",
                a.dst_port or "",
                a.protocol or "",
                a.count,
                a.status.value,
                a.title,
                a.reason,
            ]
        )
    return buffer.getvalue()


def case_to_json(case: Case, alerts: list[Alert], clusters: list[Cluster]) -> str:
    return json.dumps(
        {
            "case": case.to_dict(),
            "clusters": [c.to_dict() for c in clusters],
            "alerts": [a.to_dict() for a in alerts],
        },
        indent=2,
        default=str,
    )


def case_report_markdown(case: Case, alerts: list[Alert], clusters: list[Cluster]) -> str:
    """Analyst-ready markdown report for one case."""
    by_severity: dict[str, int] = {}
    for a in alerts:
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1

    lines = [
        f"# sentryd case report: {case.name}",
        "",
        f"- **Case:** #{case.id} ({case.status.value})",
        f"- **Source:** {case.source_kind}:{case.source}",
        f"- **Created:** {case.created_at} UTC",
        f"- **Traffic:** {case.events_processed} events"
        + (
            f", {_iso(case.start_ts)} to {_iso(case.end_ts)} UTC"
            if case.start_ts is not None
            else ""
        ),
        f"- **Alerts:** {len(alerts)}"
        + (
            " (" + ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) + ")"
            if by_severity
            else ""
        ),
    ]
    if case.pcap_sha256:
        size = f"{case.pcap_size:,} bytes" if case.pcap_size is not None else "unknown size"
        lines.append(f"- **PCAP:** sha256 `{case.pcap_sha256}`, {size}")
    if case.notes:
        lines += ["", "## Notes", "", case.notes]

    if clusters:
        lines += ["", "## Correlated activity", ""]
        for cluster in clusters:
            targets = ", ".join(cluster.targets) or "-"
            lines += [
                f"### {cluster.source} ({cluster.max_severity})",
                "",
                f"- **Chain:** {cluster.chain}",
                f"- **Targets:** {targets}",
                f"- **Window:** {_iso(cluster.first_seen)} to {_iso(cluster.last_seen)} UTC",
                f"- **Alerts:** {', '.join(f'#{i}' for i in [a.id for a in cluster.alerts])}",
                "",
            ]

    if alerts:
        lines += ["", "## Alerts", ""]
        for a in sorted(alerts, key=lambda x: (x.severity.rank, x.ts), reverse=True):
            lines += [
                f"### [#{a.id}] {a.title}",
                "",
                f"- **Severity:** {a.severity.value} (confidence {a.confidence:.2f})",
                f"- **Rule:** {a.rule_id}",
                f"- **First seen:** {_iso(a.ts)} UTC, last seen {_iso(a.last_seen)} UTC"
                f" ({a.count} occurrence{'s' if a.count != 1 else ''})",
                f"- **Flow:** {a.src or '?'}"
                + (f":{a.src_port}" if a.src_port else "")
                + f" -> {a.dst or '?'}"
                + (f":{a.dst_port}" if a.dst_port else "")
                + (f" ({a.protocol})" if a.protocol else ""),
            ]
            if a.reason:
                lines.append(f"- **Why it fired:** {a.reason}")
            lines.append(f"- **Next step:** {investigation_hint(a)}")
            evidence = json.dumps(a.evidence, indent=2, default=str)
            lines += ["", "```json", evidence, "```", ""]
    else:
        lines += ["", "## Alerts", "", "No alerts were raised for this case.", ""]

    if case.ai_report:
        lines += [
            "",
            f"## AI review (generated {case.ai_report_at} UTC)",
            "",
            case.ai_report,
            "",
        ]

    return "\n".join(lines).rstrip() + "\n"
