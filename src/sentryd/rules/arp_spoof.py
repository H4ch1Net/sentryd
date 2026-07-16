"""ARP spoofing detection.

Primary signal: an IP address announcing itself (ARP reply or gratuitous
ARP) with a different MAC than previously recorded — the classic
cache-poisoning pattern. Secondary signal: a burst of gratuitous ARP
announcements from one MAC, the noisy way poisoning tools keep caches primed.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register

_IGNORED_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
_IGNORED_IPS = {"0.0.0.0"}


@dataclass
class _Mapping:
    mac: str
    first_seen: float
    last_seen: float


@register
class ArpSpoofRule(Rule):
    rule_id = "arp_spoof"

    def __init__(
        self,
        gratuitous_window_seconds: float = 10.0,
        gratuitous_threshold: int = 8,
        mapping_ttl_seconds: float = 3600.0,
    ) -> None:
        self.gratuitous_window_seconds = float(gratuitous_window_seconds)
        self.gratuitous_threshold = int(gratuitous_threshold)
        # Like a real ARP cache, mappings expire: a MAC change after the TTL
        # is a fresh observation, not a conflict — and expiry also bounds
        # state growth when an attacker floods forged sender IPs.
        self.mapping_ttl_seconds = float(mapping_ttl_seconds)
        self._mappings: dict[str, _Mapping] = {}  # ip -> authoritative MAC
        self._gratuitous: dict[str, deque[float]] = defaultdict(deque)  # mac -> ts
        self._grat_last_fired: dict[str, float] = {}
        self._last_sweep: float | None = None

    def process(self, event: Event) -> list[Alert]:
        arp = event.arp
        if event.protocol != "arp" or arp is None:
            return []
        self._maybe_sweep(event.ts)
        mac, ip = arp.sender_mac.lower(), arp.sender_ip
        if mac in _IGNORED_MACS or ip in _IGNORED_IPS:
            return []

        is_gratuitous = arp.sender_ip == arp.target_ip
        is_announcement = arp.op == 2 or is_gratuitous
        if not is_announcement:
            return []

        alerts: list[Alert] = []
        alerts += self._check_conflict(event, ip, mac, is_gratuitous)
        if is_gratuitous:
            alerts += self._check_gratuitous_burst(event, mac)
        return alerts

    def _check_conflict(
        self, event: Event, ip: str, mac: str, is_gratuitous: bool
    ) -> list[Alert]:
        known = self._mappings.get(ip)
        if known is not None and event.ts - known.last_seen > self.mapping_ttl_seconds:
            known = None  # stale mapping: treat like an ARP cache expiry
        if known is None:
            self._mappings[ip] = _Mapping(mac=mac, first_seen=event.ts, last_seen=event.ts)
            return []
        if known.mac == mac:
            known.last_seen = event.ts
            return []

        alert = Alert(
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            confidence=0.85,
            title=(
                f"ARP spoofing suspected: {ip} now claimed by {mac} "
                f"(previously {known.mac})"
            ),
            ts=event.ts,
            src=ip,
            dst=None,
            key=ip,
            protocol="arp",
            reason=(
                f"{ip} was announced by {known.mac} since {known.first_seen:.0f} "
                f"and is now claimed by {mac}; conflicting MACs for one IP is the "
                f"ARP cache poisoning pattern"
            ),
            evidence={
                "ip": ip,
                "previous_mac": known.mac,
                "new_mac": mac,
                "previous_first_seen": known.first_seen,
                "previous_last_seen": known.last_seen,
                "announcement": "gratuitous" if is_gratuitous else "reply",
            },
        )
        # Record the takeover: if the mapping flips back, that alerts too
        # (flip-flopping is itself strong evidence of a MITM in progress).
        self._mappings[ip] = _Mapping(mac=mac, first_seen=event.ts, last_seen=event.ts)
        return [alert]

    def _check_gratuitous_burst(self, event: Event, mac: str) -> list[Alert]:
        window = self._gratuitous[mac]
        window.append(event.ts)
        cutoff = event.ts - self.gratuitous_window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) < self.gratuitous_threshold:
            return []

        last = self._grat_last_fired.get(mac)
        if last is not None and event.ts - last < self.gratuitous_window_seconds:
            return []
        self._grat_last_fired[mac] = event.ts

        return [
            Alert(
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                confidence=0.6,
                title=(
                    f"Gratuitous ARP flood: {mac} sent {len(window)} announcements "
                    f"in {self.gratuitous_window_seconds:g}s"
                ),
                ts=event.ts,
                src=event.src_ip,
                dst=None,
                key=f"gratuitous:{mac}",
                protocol="arp",
                reason=(
                    f"{len(window)} gratuitous ARP announcements from {mac} in "
                    f"{self.gratuitous_window_seconds:g}s (threshold "
                    f"{self.gratuitous_threshold}); poisoning tools re-announce "
                    f"aggressively to keep victim caches primed"
                ),
                evidence={
                    "mac": mac,
                    "announcements_in_window": len(window),
                    "window_seconds": self.gratuitous_window_seconds,
                    "threshold": self.gratuitous_threshold,
                },
            )
        ]

    def _maybe_sweep(self, now: float) -> None:
        """Evict expired state (event-time paced) to stay bounded under
        forged-ARP floods that cycle fresh MAC/IP pairs."""
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self.mapping_ttl_seconds:
            return
        self._last_sweep = now
        for ip in [
            ip
            for ip, mapping in self._mappings.items()
            if now - mapping.last_seen > self.mapping_ttl_seconds
        ]:
            del self._mappings[ip]
        grat_cutoff = now - self.gratuitous_window_seconds
        for mac in [
            mac
            for mac, window in self._gratuitous.items()
            if not window or window[-1] < grat_cutoff
        ]:
            del self._gratuitous[mac]
        for mac in [
            mac for mac, ts in self._grat_last_fired.items() if ts < grat_cutoff
        ]:
            del self._grat_last_fired[mac]
