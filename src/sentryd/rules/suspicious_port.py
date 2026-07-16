"""Suspicious port usage: connection attempts to known-bad/unexpected ports.

Entirely config-driven, the watchlist lives in signatures.yaml, each entry
carrying its own label, severity, and optional analyst note.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register


@dataclass(frozen=True)
class PortWatch:
    port: int
    label: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.6
    note: str = ""


@register
class SuspiciousPortRule(Rule):
    rule_id = "suspicious_port"

    def __init__(self, watchlist: list[PortWatch]) -> None:
        self.watchlist = {w.port: w for w in watchlist}

    @classmethod
    def from_config(cls, config: dict) -> "SuspiciousPortRule":
        watchlist = [
            PortWatch(
                port=int(entry["port"]),
                label=str(entry["label"]),
                severity=Severity(entry.get("severity", "medium")),
                confidence=float(entry.get("confidence", 0.6)),
                note=str(entry.get("note", "")),
            )
            for entry in config.get("ports", [])
        ]
        return cls(watchlist)

    def process(self, event: Event) -> list[Alert]:
        if event.dst_port is None:
            return []
        # TCP: only flag actual connection attempts, not every mid-stream
        # packet. UDP has no handshake, so any datagram counts.
        if event.protocol == "tcp" and not event.is_syn_only:
            return []
        if event.protocol not in ("tcp", "udp"):
            return []

        watch = self.watchlist.get(event.dst_port)
        if watch is None:
            return []

        return [
            Alert(
                rule_id=self.rule_id,
                severity=watch.severity,
                confidence=watch.confidence,
                title=(
                    f"Connection to suspicious port {watch.port} ({watch.label}): "
                    f"{event.src_ip} -> {event.dst_ip}"
                ),
                ts=event.ts,
                src=event.src_ip,
                dst=event.dst_ip,
                key=str(watch.port),
                protocol=event.protocol,
                src_port=event.src_port,
                dst_port=watch.port,
                packet_count=1,
                byte_count=event.length or None,
                reason=(
                    f"connection attempt to port {watch.port}, watchlisted as "
                    f"{watch.label}" + (f" ({watch.note})" if watch.note else "")
                ),
                evidence={
                    "port": watch.port,
                    "label": watch.label,
                    "note": watch.note,
                    "protocol": event.protocol,
                    "tcp_flags": event.tcp_flags,
                    "src_port": event.src_port,
                },
            )
        ]
