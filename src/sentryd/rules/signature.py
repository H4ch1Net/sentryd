"""Generic config-driven signature matching.

The stateful rules (port_scan, traffic_spike, arp_spoof) live in code because
they need sliding windows and baselines. Everything stateless, "flag TCP
SYNs from this CIDR to that port range", belongs here instead: signatures
are declared under the top-level ``signatures:`` key in the config file and
never require code changes.

Signature fields (all match criteria optional; omitted criteria match all):

    - id: sig-rdp-from-guest-vlan       # required, unique
      title: RDP attempt from guest VLAN
      severity: high                    # default medium
      confidence: 0.7                   # default 0.6
      note: free-text analyst context
      match:
        protocol: tcp                   # tcp|udp|icmp|arp|other
        src_cidr: 10.20.0.0/16
        dst_cidr: 10.0.5.0/24
        src_ports: [40000]              # ints and "lo-hi" ranges
        dst_ports: [3389, "5900-5910"]
        tcp_flags: S                    # every listed flag letter must be set
        tcp_flags_not: A                # none of these may be set
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule


def _parse_ports(spec: list) -> frozenset[int]:
    ports: set[int] = set()
    for item in spec:
        if isinstance(item, int):
            ports.add(item)
        else:
            lo, _, hi = str(item).partition("-")
            if hi:
                ports.update(range(int(lo), int(hi) + 1))
            else:
                ports.add(int(lo))
    return frozenset(ports)


@dataclass(frozen=True)
class Signature:
    sig_id: str
    title: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.6
    note: str = ""
    protocol: str | None = None
    src_net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    dst_net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    src_ports: frozenset[int] | None = None
    dst_ports: frozenset[int] | None = None
    tcp_flags: str = ""  # every letter must be present
    tcp_flags_not: str = ""  # no letter may be present

    @classmethod
    def from_dict(cls, spec: dict) -> "Signature":
        if "id" not in spec or "title" not in spec:
            raise ValueError(f"signature needs 'id' and 'title': {spec!r}")
        match = spec.get("match", {}) or {}
        return cls(
            sig_id=str(spec["id"]),
            title=str(spec["title"]),
            severity=Severity(spec.get("severity", "medium")),
            confidence=float(spec.get("confidence", 0.6)),
            note=str(spec.get("note", "")),
            protocol=match.get("protocol"),
            src_net=ipaddress.ip_network(match["src_cidr"]) if "src_cidr" in match else None,
            dst_net=ipaddress.ip_network(match["dst_cidr"]) if "dst_cidr" in match else None,
            src_ports=_parse_ports(match["src_ports"]) if "src_ports" in match else None,
            dst_ports=_parse_ports(match["dst_ports"]) if "dst_ports" in match else None,
            tcp_flags=str(match.get("tcp_flags", "")),
            tcp_flags_not=str(match.get("tcp_flags_not", "")),
        )

    def matches(self, event: Event) -> bool:
        if self.protocol is not None and event.protocol != self.protocol:
            return False
        if self.src_net is not None and not _ip_in(event.src_ip, self.src_net):
            return False
        if self.dst_net is not None and not _ip_in(event.dst_ip, self.dst_net):
            return False
        if self.src_ports is not None and event.src_port not in self.src_ports:
            return False
        if self.dst_ports is not None and event.dst_port not in self.dst_ports:
            return False
        if any(flag not in event.tcp_flags for flag in self.tcp_flags):
            return False
        if any(flag in event.tcp_flags for flag in self.tcp_flags_not):
            return False
        return True


def _ip_in(ip: str | None, net) -> bool:
    if ip is None:
        return False
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


class SignatureRule(Rule):
    """Evaluates every configured signature against every event.

    Not in the rule registry: build_rules() constructs it from the top-level
    ``signatures:`` config section, not from ``rules:``.
    """

    rule_id = "signature"

    def __init__(self, signatures: list[Signature]) -> None:
        seen: set[str] = set()
        for sig in signatures:
            if sig.sig_id in seen:
                raise ValueError(f"duplicate signature id: {sig.sig_id}")
            seen.add(sig.sig_id)
        self.signatures = list(signatures)

    @classmethod
    def from_config(cls, config: dict) -> "SignatureRule":
        return cls([Signature.from_dict(spec) for spec in config.get("signatures", [])])

    def process(self, event: Event) -> list[Alert]:
        alerts = []
        for sig in self.signatures:
            if not sig.matches(event):
                continue
            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    severity=sig.severity,
                    confidence=sig.confidence,
                    title=f"{sig.title}: {event.src_ip} -> {event.dst_ip}",
                    ts=event.ts,
                    src=event.src_ip,
                    dst=event.dst_ip,
                    key=sig.sig_id,
                    protocol=event.protocol,
                    src_port=event.src_port,
                    dst_port=event.dst_port,
                    packet_count=1,
                    byte_count=event.length or None,
                    reason=(
                        f"packet matched custom signature {sig.sig_id}"
                        + (f": {sig.note}" if sig.note else "")
                    ),
                    evidence={
                        "signature_id": sig.sig_id,
                        "note": sig.note,
                        "protocol": event.protocol,
                        "src_port": event.src_port,
                        "dst_port": event.dst_port,
                        "tcp_flags": event.tcp_flags,
                        "packet": event.summary,
                    },
                )
            )
        return alerts
