"""Alert correlation: turn isolated alerts into readable activity clusters.

Deterministic, no AI. Alerts sharing an offending source IP within a case
form a cluster; the cluster's chain is its sequence of attack phases in
first-seen order, labeled with the analyst-facing phase each rule represents.
Used by the CLI case view, the web case page, and the AI review digest.

Two refinements keep the chain honest:

- A watchlisted-port or signature hit that is one of a port scan's own
  probes (same source, a port the scan sampled, inside the scan's window) is
  reconnaissance, not "service access": scanners routinely touch Telnet on
  their way through the port list.
- Phases that start at the same moment are ordered by kill-chain stage.

Each cluster also gets a 0-100 risk score built from named, additive
factors (peak severity, evidence strength, multi-phase escalation, analyst
verdicts) so prioritization is explainable line by line.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from sentryd.core.alerts import Alert, AlertStatus

# What each rule firing means in attack-chain terms, in kill-chain order
# (the order breaks ties between phases that begin simultaneously).
RULE_PHASE = {
    "port_scan": "reconnaissance",
    "arp_spoof": "man-in-the-middle positioning",
    "suspicious_port": "suspicious service access",
    "signature": "policy/signature match",
    "beacon": "command-and-control",
    "traffic_spike": "unusual data volume",
}
_PHASE_STAGE = {phase: i for i, phase in enumerate(RULE_PHASE.values())}

# Rules whose hits can be individual probes of a port scan.
_PROBE_RULES = ("suspicious_port", "signature")

# Verdicts meaning "an analyst looked and this is not a threat".
_BENIGN_VERDICTS = {
    AlertStatus.FALSE_POSITIVE,
    AlertStatus.EXPECTED,
    AlertStatus.IGNORED,
    AlertStatus.DISMISSED,
}

_SEVERITY_POINTS = {"low": 15, "medium": 35, "high": 60, "critical": 80}
# Score bands, highest first.
_RISK_LEVELS = ((85, "critical"), (60, "high"), (35, "medium"), (1, "low"))


def risk_level(score: int) -> str:
    for floor, level in _RISK_LEVELS:
        if score >= floor:
            return level
    return "none"


def _is_scan_probe(alert: Alert, scans: list[Alert]) -> bool:
    if alert.rule_id not in _PROBE_RULES or alert.dst_port is None:
        return False
    for scan in scans:
        evidence = scan.evidence
        if (
            alert.dst_port in evidence.get("sample_ports", ())
            and (scan.dst == alert.dst or alert.dst in evidence.get("sample_hosts", ()))
            and scan.ts - evidence.get("window_seconds", 0) <= alert.ts <= scan.last_seen
        ):
            return True
    return False


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

    def _phased(self) -> list[tuple[Alert, str]]:
        """Each alert paired with the attack phase it represents here."""
        scans = [a for a in self.alerts if a.rule_id == "port_scan"]
        return [
            (
                alert,
                RULE_PHASE["port_scan"]
                if _is_scan_probe(alert, scans)
                else RULE_PHASE.get(alert.rule_id, alert.rule_id),
            )
            for alert in self.alerts
        ]

    @property
    def phases(self) -> list[dict]:
        """Distinct phases in order: first seen, then kill-chain stage."""
        grouped: dict[str, list[Alert]] = defaultdict(list)
        for alert, phase in self._phased():
            grouped[phase].append(alert)
        ordered = sorted(
            grouped.items(),
            key=lambda item: (
                min(a.ts for a in item[1]),
                _PHASE_STAGE.get(item[0], len(_PHASE_STAGE)),
            ),
        )
        return [
            {
                "phase": phase,
                "rules": sorted({a.rule_id for a in items}),
                "first_seen": min(a.ts for a in items),
                "last_seen": max(a.last_seen for a in items),
                "alert_ids": [a.id for a in sorted(items, key=lambda a: a.ts)],
            }
            for phase, items in ordered
        ]

    @property
    def chain(self) -> str:
        """Human-readable attack-chain label, e.g.
        'reconnaissance -> suspicious service access'."""
        return " -> ".join(p["phase"] for p in self.phases)

    @property
    def risk(self) -> dict:
        """0-100 priority score with the factors that produced it. Alerts an
        analyst closed as benign don't count; a confirmed one adds weight."""
        phased = [(a, phase) for a, phase in self._phased() if a.status not in _BENIGN_VERDICTS]
        live = [a for a, _ in phased]
        if not live:
            return {
                "score": 0,
                "level": "none",
                "factors": [{"factor": "every alert closed as benign by an analyst", "points": 0}],
            }
        peak = max(live, key=lambda a: (a.severity.rank, a.confidence))
        factors = [
            {
                "factor": f"peak severity {peak.severity.value}",
                "points": _SEVERITY_POINTS[peak.severity.value],
            },
            {
                "factor": f"evidence confidence {peak.confidence:.2f}",
                "points": round(10 * peak.confidence),
            },
        ]
        phases = len({phase for _, phase in phased})
        if phases > 1:
            factors.append(
                {
                    "factor": f"multi-stage activity ({phases} phases)",
                    "points": min(20, 10 * (phases - 1)),
                }
            )
        if any(a.status == AlertStatus.CONFIRMED for a in live):
            factors.append({"factor": "analyst-confirmed alert", "points": 10})
        score = min(100, sum(f["points"] for f in factors))
        return {"score": score, "level": risk_level(score), "factors": factors}

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "targets": self.targets,
            "rules": self.rules,
            "chain": self.chain,
            "phases": self.phases,
            "risk": self.risk,
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


def case_risk(clusters: list[Cluster]) -> dict:
    """A case is as risky as its riskiest cluster; reported with that
    cluster's source and factors so the number is never unexplained."""
    if not clusters:
        return {"score": 0, "level": "none", "source": None, "factors": []}
    top = max(clusters, key=lambda c: c.risk["score"])
    return {**top.risk, "source": top.source}


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
        "beacon": (
            f"Pull the periodic flow and its payload sizes: tshark -r <pcap> "
            f"-Y 'ip.addr == {dst} && {(alert.protocol or 'tcp')}.port == {alert.dst_port}' "
            f"-z conv,ip; check {dst}'s reputation and which process on {src} owns "
            f"the connection (update checkers and monitoring agents also beacon)"
        ),
    }
    return hints.get(
        alert.rule_id,
        f"Review related activity: sentryd alerts list{case}",
    )
