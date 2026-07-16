"""Alert correlation: turn isolated alerts into readable activity clusters.

Deterministic, no AI. Alerts sharing an offending source IP within a case
form a cluster; the cluster's chain is the sequence of rules in first-seen
order, labeled with the analyst-facing phase each rule represents. Used by
the CLI case view, the web case page, and the AI review digest.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from sentryd.core.alerts import Alert

# What each rule firing means in attack-chain terms.
RULE_PHASE = {
    "port_scan": "reconnaissance",
    "suspicious_port": "suspicious service access",
    "traffic_spike": "unusual data volume",
    "arp_spoof": "man-in-the-middle positioning",
    "signature": "policy/signature match",
}


@dataclass
class Cluster:
    """Related alerts sharing one offending source."""

    source: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def first_seen(self) -> float:
        return min(a.ts for a in self.alerts)

    @property
    def last_seen(self) -> float:
        return max(a.last_seen for a in self.alerts)

    @property
    def targets(self) -> list[str]:
        return sorted({a.dst for a in self.alerts if a.dst})

    @property
    def rules(self) -> list[str]:
        """Rule ids in order of first appearance."""
        seen: list[str] = []
        for alert in sorted(self.alerts, key=lambda a: a.ts):
            if alert.rule_id not in seen:
                seen.append(alert.rule_id)
        return seen

    @property
    def max_severity(self) -> str:
        return max(self.alerts, key=lambda a: a.severity.rank).severity.value

    @property
    def chain(self) -> str:
        """Human-readable attack-chain label, e.g.
        'reconnaissance -> suspicious service access'."""
        return " -> ".join(RULE_PHASE.get(rule, rule) for rule in self.rules)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "targets": self.targets,
            "rules": self.rules,
            "chain": self.chain,
            "max_severity": self.max_severity,
            "alert_ids": [a.id for a in self.alerts],
            "alert_count": len(self.alerts),
        }


def correlate(alerts: list[Alert]) -> list[Cluster]:
    """Group alerts by offending source, most severe/busiest cluster first.

    Alerts without a source (rare) each form their own cluster so nothing
    disappears from the case view.
    """
    by_source: dict[str, list[Alert]] = defaultdict(list)
    orphans: list[Alert] = []
    for alert in alerts:
        if alert.src:
            by_source[alert.src].append(alert)
        else:
            orphans.append(alert)

    clusters = [Cluster(source=src, alerts=items) for src, items in by_source.items()]
    clusters += [Cluster(source=a.title, alerts=[a]) for a in orphans]
    clusters.sort(
        key=lambda c: (max(a.severity.rank for a in c.alerts), len(c.alerts)),
        reverse=True,
    )
    return clusters


def related_alerts(store, alert: Alert, limit: int = 10) -> list[Alert]:
    """Other alerts in the same case touching the same hosts."""
    candidates: dict[int, Alert] = {}
    for host in filter(None, (alert.src, alert.dst)):
        for other in store.list(host=host, case_id=alert.case_id, limit=50):
            if other.id != alert.id:
                candidates[other.id] = other
    ranked = sorted(candidates.values(), key=lambda a: (a.severity.rank, a.ts), reverse=True)
    return ranked[:limit]


def investigation_hint(alert: Alert) -> str:
    """Deterministic suggested next step for an alert, by rule."""
    src = alert.src or "<src>"
    dst = alert.dst or "<dst>"
    case = f" --case {alert.case_id}" if alert.case_id else ""
    hints = {
        "port_scan": (
            f"Check what {src} touched next: "
            f"sentryd alerts list{case} (look for suspicious_port hits from {src}), "
            f"then confirm scope in the capture: tshark -r <pcap> "
            f"-Y 'ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0'"
        ),
        "suspicious_port": (
            f"Confirm whether {dst} answered on port {alert.dst_port}: "
            f"tshark -r <pcap> -Y 'ip.addr == {dst} && tcp.port == {alert.dst_port}' "
            f"and review other activity from {src}: sentryd alerts list{case}"
        ),
        "traffic_spike": (
            f"Identify where the volume from {src} went: "
            f"tshark -r <pcap> -Y 'ip.src == {src}' -z conv,ip "
            f"and check for exfil-sized flows to unfamiliar destinations"
        ),
        "arp_spoof": (
            f"Verify the legitimate MAC for {src} (switch CAM table/DHCP leases), "
            f"then look for traffic redirected through the new MAC and check "
            f"sentryd alerts list{case} for follow-on activity"
        ),
        "signature": (
            f"Review the matched packet and the signature's note, then widen: "
            f"sentryd alerts list{case} --rule signature"
        ),
    }
    return hints.get(
        alert.rule_id,
        f"Review related activity: sentryd alerts list{case}",
    )
