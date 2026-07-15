"""Port scan detection: many distinct target ports from one source, fast.

Tracks bare connection attempts (TCP SYN without ACK) per source IP in a
sliding time window. Both SYN (half-open) scans and full connect scans open
with a lone SYN, so counting distinct (host, port) targets catches both; the
alert distinguishes vertical scans (one host, many ports) from horizontal
sweeps (one port, many hosts).
"""

from __future__ import annotations

from collections import defaultdict, deque

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register


@register
class PortScanRule(Rule):
    rule_id = "port_scan"

    def __init__(
        self,
        window_seconds: float = 10.0,
        min_distinct_targets: int = 15,
    ) -> None:
        self.window_seconds = float(window_seconds)
        self.min_distinct_targets = int(min_distinct_targets)
        # src ip -> deque of (ts, dst_ip, dst_port)
        self._attempts: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        # src ip -> ts of last alert, to avoid re-firing on every packet
        self._last_fired: dict[str, float] = {}

    def process(self, event: Event) -> list[Alert]:
        if (
            event.protocol != "tcp"
            or not event.is_syn_only
            or event.src_ip is None
            or event.dst_ip is None
            or event.dst_port is None
        ):
            return []

        window = self._attempts[event.src_ip]
        window.append((event.ts, event.dst_ip, event.dst_port))
        cutoff = event.ts - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        targets = {(dst, port) for _, dst, port in window}
        if len(targets) < self.min_distinct_targets:
            return []

        # Once tripped, stay quiet for a full window so an ongoing scan
        # produces one alert per window (the engine merges those further).
        last = self._last_fired.get(event.src_ip)
        if last is not None and event.ts - last < self.window_seconds:
            return []
        self._last_fired[event.src_ip] = event.ts

        hosts = {dst for dst, _ in targets}
        ports = sorted({port for _, port in targets})
        span = round(window[-1][0] - window[0][0], 3)

        if len(hosts) == 1:
            kind = "vertical"
            title = f"Port scan: {event.src_ip} probed {len(ports)} ports on {next(iter(hosts))}"
        elif len(ports) <= 3:
            kind = "horizontal"
            title = (
                f"Port sweep: {event.src_ip} probed port(s) "
                f"{', '.join(map(str, ports))} across {len(hosts)} hosts"
            )
        else:
            kind = "mixed"
            title = (
                f"Port scan: {event.src_ip} probed {len(targets)} host/port "
                f"combinations across {len(hosts)} hosts"
            )

        # Confidence grows with how far past the threshold the burst is.
        overshoot = len(targets) / self.min_distinct_targets
        confidence = round(min(0.95, 0.70 + 0.10 * (overshoot - 1.0)), 2)

        return [
            Alert(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                confidence=confidence,
                title=title,
                ts=event.ts,
                src=event.src_ip,
                dst=next(iter(hosts)) if len(hosts) == 1 else None,
                evidence={
                    "scan_type": kind,
                    "distinct_targets": len(targets),
                    "distinct_ports": len(ports),
                    "distinct_hosts": len(hosts),
                    "window_seconds": self.window_seconds,
                    "observed_span_seconds": span,
                    "sample_ports": ports[:25],
                    "sample_hosts": sorted(hosts)[:10],
                    "syn_only_attempts": len(window),
                },
            )
        ]
