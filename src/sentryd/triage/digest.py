"""Case digest: the bounded, structured summary sent to the AI for an
overall review.

This is the ONLY thing the AI ever sees for a case, and only when the user
explicitly requests a review. It is built from alert metadata (never raw
packet payloads), keeps the most important evidence first (severity, then
recency), and enforces a hard size cap so prompts stay within sane token
limits regardless of how noisy the capture was.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from sentryd.core.alerts import Alert
from sentryd.core.cases import Case
from sentryd.core.correlate import Cluster

MAX_ALERTS = 40
MAX_DIGEST_CHARS = 12_000  # ~3-4k tokens; leaves ample room for the answer
_EVIDENCE_LIST_CAP = 5
_EVIDENCE_STR_CAP = 160


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _trim_evidence(evidence: dict) -> dict:
    """Keep evidence readable and small: cap lists and long strings."""
    trimmed = {}
    for key, value in evidence.items():
        if isinstance(value, list) and len(value) > _EVIDENCE_LIST_CAP:
            trimmed[key] = value[:_EVIDENCE_LIST_CAP] + [f"... {len(value) - _EVIDENCE_LIST_CAP} more"]
        elif isinstance(value, str) and len(value) > _EVIDENCE_STR_CAP:
            trimmed[key] = value[:_EVIDENCE_STR_CAP] + "..."
        else:
            trimmed[key] = value
    return trimmed


def _alert_entry(alert: Alert) -> dict:
    entry = {
        "id": alert.id,
        "rule": alert.rule_id,
        "severity": alert.severity.value,
        "confidence": alert.confidence,
        "first_seen": _iso(alert.ts),
        "last_seen": _iso(alert.last_seen),
        "src": alert.src,
        "dst": alert.dst,
        "protocol": alert.protocol,
        "dst_port": alert.dst_port,
        "occurrences": alert.count,
        "reason": alert.reason[:_EVIDENCE_STR_CAP],
        "evidence": _trim_evidence(alert.evidence),
    }
    return {k: v for k, v in entry.items() if v not in (None, "", {})}


def _timeline(alerts: list[Alert], buckets: int = 12) -> list[dict]:
    if not alerts:
        return []
    lo = min(a.ts for a in alerts)
    hi = max(a.ts for a in alerts)
    width = max((hi - lo) / buckets, 1e-9)
    out = [
        {"start": _iso(lo + i * width), "count": 0, "rules": Counter()}
        for i in range(buckets)
    ]
    for alert in alerts:
        bucket = out[min(int((alert.ts - lo) / width), buckets - 1)]
        bucket["count"] += 1
        bucket["rules"][alert.rule_id] += 1
    return [
        {"start": b["start"], "count": b["count"], "rules": dict(b["rules"])}
        for b in out
        if b["count"]
    ]


def build_case_digest(
    case: Case,
    alerts: list[Alert],
    clusters: list[Cluster],
    max_alerts: int = MAX_ALERTS,
) -> dict:
    """Structured, size-capped summary of a case for the review prompt."""
    ranked = sorted(alerts, key=lambda a: (a.severity.rank, a.ts), reverse=True)

    severity_counts = Counter(a.severity.value for a in alerts)
    rule_counts = Counter(a.rule_id for a in alerts)
    host_counts: Counter = Counter()
    for a in alerts:
        if a.src:
            host_counts[a.src] += 1 + a.severity.rank
        if a.dst:
            host_counts[a.dst] += 1
    port_counts = Counter(a.dst_port for a in alerts if a.dst_port)

    digest = {
        "case": {
            "id": case.id,
            "name": case.name,
            "source": f"{case.source_kind}:{case.source}",
            "events_processed": case.events_processed,
            "traffic_span": [_iso(case.start_ts), _iso(case.end_ts)],
            "notes": case.notes or None,
        },
        "totals": {
            "alerts": len(alerts),
            "by_severity": dict(severity_counts),
            "by_rule": dict(rule_counts),
        },
        "top_hosts": [
            {"host": host, "involvement": score}
            for host, score in host_counts.most_common(10)
        ],
        "top_ports": [
            {"port": port, "alerts": n} for port, n in port_counts.most_common(10)
        ],
        "correlated_clusters": [c.to_dict() for c in clusters[:8]],
        "timeline": _timeline(alerts),
        "alerts": [_alert_entry(a) for a in ranked[:max_alerts]],
    }

    # Hard cap: shrink the alert sample until the digest fits.
    while len(json.dumps(digest, default=str)) > MAX_DIGEST_CHARS and digest["alerts"]:
        digest["alerts"] = digest["alerts"][: max(len(digest["alerts"]) - 5, 0)]
    digest["alerts_included"] = len(digest["alerts"])
    return digest
