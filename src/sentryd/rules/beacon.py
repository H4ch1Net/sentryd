"""Beaconing detection: a host contacting the same service on a clock.

Command-and-control implants check in with their server at a fixed interval,
often with a little random jitter, producing contacts far more regular than
anything a person or most applications generate. Per (source, destination,
port, protocol) flow the rule keeps the start times of recent contacts and
alerts once enough of them agree: the coefficient of variation of the
intervals (stdev / mean) must be at most ``max_jitter`` and the mean interval
must lie between ``min_interval_seconds`` and ``max_interval_seconds``.

A contact is a TCP connection attempt (bare SYN) or a UDP burst. Packets
within ``burst_seconds`` of the flow's previous packet, and SYN
retransmissions from the same source port, fold into the contact they belong
to, so retries and multi-datagram check-ins don't break the rhythm. The
interval floor keeps streaming media (RTP's 20 ms cadence is perfectly
regular) out.

Legitimate pollers (update checks, monitoring agents) beacon too. Chatty
infrastructure ports are ignored by default; the rest is what verdicts are
for. One alert per established rhythm: the rule re-arms only once the
pattern clearly breaks (variation above twice the threshold), so a beacon
hovering at the threshold can't flap into a stream of duplicate alerts.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from itertools import pairwise
from statistics import fmean, pstdev

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register

# DNS, DHCP, NTP, NetBIOS, SNMP, syslog, SSDP, mDNS, LLMNR: periodic by design.
DEFAULT_IGNORE_PORTS = (53, 67, 68, 123, 137, 138, 161, 162, 514, 1900, 5353, 5355)


@dataclass
class _Flow:
    contacts: deque[float]  # start times of recent contacts
    last_ts: float = 0.0  # last packet of any kind in this flow
    last_src_port: int | None = None
    fired: bool = False
    first_contact: float | None = None


@register
class BeaconRule(Rule):
    rule_id = "beacon"

    def __init__(
        self,
        min_contacts: int = 6,
        max_jitter: float = 0.15,
        min_interval_seconds: float = 5.0,
        max_interval_seconds: float = 3600.0,
        burst_seconds: float = 1.0,
        history: int = 20,
        ignore_ports: list[int] | tuple[int, ...] = DEFAULT_IGNORE_PORTS,
        max_tracked_flows: int = 50_000,
    ) -> None:
        self.min_contacts = max(3, int(min_contacts))  # need at least 2 intervals
        self.max_jitter = float(max_jitter)
        self.min_interval_seconds = float(min_interval_seconds)
        self.max_interval_seconds = float(max_interval_seconds)
        self.burst_seconds = float(burst_seconds)
        self.history = max(self.min_contacts, int(history))
        self.ignore_ports = frozenset(int(p) for p in ignore_ports)
        self.max_tracked_flows = int(max_tracked_flows)
        # Least recently active first, so eviction and idle sweeps pop from
        # the front in O(expired) instead of scanning every flow.
        self._flows: OrderedDict[tuple, _Flow] = OrderedDict()
        self._last_sweep: float | None = None

    def process(self, event: Event) -> list[Alert]:
        if event.src_ip is None or event.dst_ip is None or event.dst_port is None:
            return []
        if event.protocol == "tcp":
            if not event.is_syn_only:
                return []
        elif event.protocol != "udp":
            return []
        if event.dst_port in self.ignore_ports or event.src_port in self.ignore_ports:
            return []

        self._maybe_sweep(event.ts)
        key = (event.src_ip, event.dst_ip, event.dst_port, event.protocol)
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = _Flow(contacts=deque(maxlen=self.history))
            if len(self._flows) > self.max_tracked_flows:
                self._flows.popitem(last=False)
        else:
            self._flows.move_to_end(key)
            gap = event.ts - flow.last_ts
            retransmit = (
                event.protocol == "tcp"
                and event.src_port == flow.last_src_port
                and gap < self.min_interval_seconds
            )
            if gap <= self.burst_seconds or retransmit:
                flow.last_ts = event.ts  # same contact, still in progress
                return []
            if gap > self.max_interval_seconds:
                flow.contacts.clear()  # too long a silence to be one rhythm
                flow.fired = False

        if not flow.contacts:
            flow.first_contact = event.ts
        flow.contacts.append(event.ts)
        flow.last_ts = event.ts
        flow.last_src_port = event.src_port
        if len(flow.contacts) < self.min_contacts:
            return []

        intervals = [b - a for a, b in pairwise(flow.contacts)]
        mean = fmean(intervals)
        jitter = pstdev(intervals) / mean if mean > 0 else float("inf")
        in_range = self.min_interval_seconds <= mean <= self.max_interval_seconds
        if not in_range or jitter > 2 * self.max_jitter:
            flow.fired = False  # rhythm clearly broken: re-arm for the next one
            return []
        if jitter > self.max_jitter or flow.fired:
            return []
        flow.fired = True
        return [self._alert(event, flow, intervals, mean, jitter)]

    def _alert(
        self, event: Event, flow: _Flow, intervals: list[float], mean: float, jitter: float
    ) -> Alert:
        contacts = len(flow.contacts)
        # Tighter rhythm and a longer run of check-ins both raise confidence.
        regularity = 1.0 - jitter / self.max_jitter if self.max_jitter else 1.0
        run = min(contacts - self.min_contacts, 10) / 100
        confidence = round(min(0.9, 0.5 + 0.3 * regularity + run), 2)
        service = f"{event.dst_ip}:{event.dst_port}/{event.protocol}"
        return Alert(
            rule_id=self.rule_id,
            severity=Severity.MEDIUM,
            confidence=confidence,
            title=(
                f"Beaconing: {event.src_ip} contacts {service} every "
                f"~{mean:.0f}s ({contacts} contacts, {jitter:.1%} jitter)"
            ),
            ts=event.ts,
            src=event.src_ip,
            dst=event.dst_ip,
            key=f"{event.protocol}/{event.dst_port}",
            protocol=event.protocol,
            src_port=event.src_port,
            dst_port=event.dst_port,
            packet_count=contacts,
            reason=(
                f"{contacts} contacts to {service} at a mean interval of {mean:.1f}s "
                f"with {jitter:.1%} variation (coefficient of variation; threshold "
                f"{self.max_jitter:.0%}), a machine-timed check-in pattern"
            ),
            evidence={
                "contacts": contacts,
                "mean_interval_seconds": round(mean, 2),
                "stdev_seconds": round(pstdev(intervals), 3),
                "jitter_cv": round(jitter, 4),
                "recent_intervals": [round(i, 2) for i in intervals[-10:]],
                "first_contact": flow.first_contact,
                "protocol": event.protocol,
                "dst_port": event.dst_port,
                "max_jitter": self.max_jitter,
                "min_contacts": self.min_contacts,
            },
        )

    def _maybe_sweep(self, now: float) -> None:
        """Drop flows idle longer than any interval we would accept: their
        next contact would restart the rhythm anyway (event-time paced)."""
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < min(self.max_interval_seconds, 300.0):
            return
        self._last_sweep = now
        cutoff = now - self.max_interval_seconds
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if flow.last_ts >= cutoff:
                break
            del self._flows[key]
