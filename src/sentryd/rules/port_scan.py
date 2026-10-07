"""Port scan detection: many distinct target ports from one source, fast.

Tracks scan probes per source IP in a sliding time window and alerts on the
number of distinct (host, port) targets. Both SYN (half-open) scans and full
connect scans open with a lone SYN; stealth FIN and XMAS scans (nmap -sF /
-sX) send segments that cannot belong to any connection, since after the
handshake every segment carries ACK. All of them count, and the alert names
the technique and distinguishes vertical scans (one host, many ports) from
horizontal sweeps (one port, many hosts).
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register


def probe_technique(flags: str) -> str | None:
    """Classify a TCP segment as a scan probe by its flags, or None.

    Flagless (NULL) probes are deliberately not counted: log sources that
    omit tcp_flags would be indistinguishable from them.
    """
    if "A" in flags:
        return None
    if "S" in flags:
        return "syn"
    if "R" in flags or "F" not in flags:
        return None
    return "xmas" if "P" in flags and "U" in flags else "fin"


@dataclass
class _SourceWindow:
    """Sliding window of one source's scan probes.

    Distinct-target and per-technique counts are maintained incrementally
    (Counters updated on append/expiry) so processing stays O(1) per packet
    instead of rebuilding a set from the whole window on every probe.
    """

    attempts: deque[tuple[float, str, int, str]] = field(default_factory=deque)
    targets: Counter = field(default_factory=Counter)  # (dst_ip, dst_port) -> hits
    techniques: Counter = field(default_factory=Counter)  # "syn" | "fin" | "xmas" -> hits

    def add(self, ts: float, dst: str, port: int, technique: str) -> None:
        self.attempts.append((ts, dst, port, technique))
        self.targets[(dst, port)] += 1
        self.techniques[technique] += 1

    def expire_before(self, cutoff: float) -> None:
        while self.attempts and self.attempts[0][0] < cutoff:
            _, dst, port, technique = self.attempts.popleft()
            _decrement(self.targets, (dst, port))
            _decrement(self.techniques, technique)

    @property
    def newest_ts(self) -> float | None:
        return self.attempts[-1][0] if self.attempts else None


def _decrement(counter: Counter, key) -> None:
    remaining = counter[key] - 1
    if remaining:
        counter[key] = remaining
    else:
        del counter[key]


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
        self._windows: dict[str, _SourceWindow] = {}
        # Refire suppression, keyed exactly like the alert identity
        # (src, single-victim-or-None) so a scan of a NEW host is never
        # swallowed by the suppression for a previous host's alert.
        self._last_fired: dict[tuple[str, str | None], float] = {}
        self._last_sweep: float | None = None

    def process(self, event: Event) -> list[Alert]:
        if (
            event.protocol != "tcp"
            or event.src_ip is None
            or event.dst_ip is None
            or event.dst_port is None
        ):
            return []
        technique = probe_technique(event.tcp_flags)
        if technique is None:
            return []

        self._maybe_sweep(event.ts)

        window = self._windows.get(event.src_ip)
        if window is None:
            window = self._windows[event.src_ip] = _SourceWindow()
        window.add(event.ts, event.dst_ip, event.dst_port, technique)
        window.expire_before(event.ts - self.window_seconds)

        if len(window.targets) < self.min_distinct_targets:
            return []

        hosts = {dst for dst, _ in window.targets}
        victim = next(iter(hosts)) if len(hosts) == 1 else None

        # Once tripped, stay quiet for a full window so an ongoing scan
        # produces one alert per window (the engine merges those further).
        fired_key = (event.src_ip, victim)
        last = self._last_fired.get(fired_key)
        if last is not None and event.ts - last < self.window_seconds:
            return []
        self._last_fired[fired_key] = event.ts

        ports = sorted({port for _, port in window.targets})
        span = round(window.attempts[-1][0] - window.attempts[0][0], 3)
        distinct = len(window.targets)
        techniques = dict(sorted(window.techniques.items()))
        stealth = sorted(t for t in techniques if t != "syn")
        if stealth:
            label = stealth[0].upper() if len(stealth) == 1 else "mixed"
            scan_noun, sweep_noun = f"Stealth {label} port scan", f"Stealth {label} port sweep"
            probes = "stealth probes (" + ", ".join(
                f"{n} {t.upper()}" for t, n in techniques.items()
            ) + ")"
        else:
            scan_noun, sweep_noun = "Port scan", "Port sweep"
            probes = "bare SYNs"

        if victim is not None:
            kind = "vertical"
            title = f"{scan_noun}: {event.src_ip} probed {len(ports)} ports on {victim}"
        elif len(ports) <= 3:
            kind = "horizontal"
            title = (
                f"{sweep_noun}: {event.src_ip} probed port(s) "
                f"{', '.join(map(str, ports))} across {len(hosts)} hosts"
            )
        else:
            kind = "mixed"
            title = (
                f"{scan_noun}: {event.src_ip} probed {distinct} host/port "
                f"combinations across {len(hosts)} hosts"
            )

        # Confidence grows with how far past the threshold the burst is;
        # stealth probes have no benign explanation, so they start higher.
        overshoot = distinct / self.min_distinct_targets
        confidence = min(0.95, 0.70 + 0.10 * (overshoot - 1.0))
        if stealth:
            confidence = max(confidence, 0.85)
        confidence = round(confidence, 2)

        return [
            Alert(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                confidence=confidence,
                title=title,
                ts=event.ts,
                src=event.src_ip,
                dst=victim,
                protocol="tcp",
                packet_count=len(window.attempts),
                reason=(
                    f"{distinct} distinct host/port targets probed with {probes} "
                    f"within {span:g}s (threshold: {self.min_distinct_targets} "
                    f"in {self.window_seconds:g}s)"
                ),
                evidence={
                    "scan_type": kind,
                    "distinct_targets": distinct,
                    "distinct_ports": len(ports),
                    "distinct_hosts": len(hosts),
                    "window_seconds": self.window_seconds,
                    "observed_span_seconds": span,
                    "sample_ports": ports[:25],
                    "sample_hosts": sorted(hosts)[:10],
                    "techniques": techniques,
                    "syn_only_attempts": techniques.get("syn", 0),
                    "probe_attempts": len(window.attempts),
                },
            )
        ]

    def _maybe_sweep(self, now: float) -> None:
        """Evict sources whose whole window has expired (event-time paced).

        Without this, one dict entry per distinct source IP lives forever -
        unbounded growth under spoofed-source floods on a live capture.
        """
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = now
        cutoff = now - self.window_seconds
        for src in [
            src
            for src, window in self._windows.items()
            if window.newest_ts is None or window.newest_ts < cutoff
        ]:
            del self._windows[src]
        for key in [key for key, ts in self._last_fired.items() if ts < cutoff]:
            del self._last_fired[key]
