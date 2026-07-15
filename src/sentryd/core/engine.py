"""RuleEngine: feeds Events to rules, dedups alerts, dispatches to sinks."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from sentryd.core.alerts import Alert
from sentryd.core.events import Event
from sentryd.rules.base import Rule

log = logging.getLogger(__name__)


class AlertSink(Protocol):
    """Consumer of alerts produced by the engine."""

    def emit(self, alert: Alert) -> None:
        """Called once when a new (non-duplicate) alert is created."""
        ...

    def update(self, alert: Alert) -> None:
        """Called when an existing alert absorbs duplicates (count changed)."""
        ...


@dataclass
class EngineStats:
    events_processed: int = 0
    alerts_emitted: int = 0
    alerts_deduplicated: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)


class RuleEngine:
    """Runs every registered rule over each event and routes alerts to sinks.

    Deduplication: alerts sharing ``(rule_id, src, dst)`` within
    ``cooldown_seconds`` (event time, not wall clock — so pcap replay behaves
    identically to live capture) are merged into the original alert by
    incrementing its ``count`` instead of emitting again.
    """

    def __init__(
        self,
        rules: Iterable[Rule],
        sinks: Iterable[AlertSink] = (),
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.rules = list(rules)
        self.sinks = list(sinks)
        self.cooldown_seconds = cooldown_seconds
        self.stats = EngineStats()
        # dedup_key -> (last event ts seen for this key, the open alert)
        self._open_alerts: dict[tuple, tuple[float, Alert]] = {}
        self._dirty: set[tuple] = set()  # open alerts with unpersisted count bumps
        self._last_maintenance: float | None = None

    def process(self, event: Event) -> list[Alert]:
        """Run one event through all rules; returns newly created alerts."""
        self.stats.events_processed += 1
        self._maintain(event.ts)
        new_alerts: list[Alert] = []
        for rule in self.rules:
            try:
                produced = rule.process(event)
            except Exception:
                log.exception("rule %s failed on event %s", rule.rule_id, event.summary)
                continue
            for alert in produced:
                if self._absorb_duplicate(alert):
                    continue
                self._open_alerts[alert.dedup_key] = (alert.ts, alert)
                self.stats.alerts_emitted += 1
                sev = alert.severity.value
                self.stats.by_severity[sev] = self.stats.by_severity.get(sev, 0) + 1
                for sink in self.sinks:
                    sink.emit(alert)
                new_alerts.append(alert)
        return new_alerts

    def run(self, events: Iterator[Event]) -> EngineStats:
        """Drain an event source, then flush pending dedup updates."""
        for event in events:
            self.process(event)
        self.flush()
        return self.stats

    def flush(self) -> None:
        """Push accumulated count updates for merged duplicates to sinks."""
        for key in self._dirty:
            entry = self._open_alerts.get(key)
            if entry is None:
                continue
            for sink in self.sinks:
                sink.update(entry[1])
        self._dirty.clear()

    def _maintain(self, now: float) -> None:
        """Periodic upkeep, paced by event time (once per cooldown window).

        Two jobs: persist pending count updates mid-run — an endless live
        source never reaches the end-of-run flush, and stored alerts would
        otherwise show stale counts until Ctrl-C — and evict expired dedup
        entries so the map doesn't grow unboundedly over a long capture
        (one entry per distinct src/dst pair would otherwise live forever).
        """
        if self._last_maintenance is None:
            self._last_maintenance = now
            return
        if now - self._last_maintenance < self.cooldown_seconds:
            return
        self._last_maintenance = now
        self.flush()
        expired = [
            key
            for key, (last_ts, _) in self._open_alerts.items()
            if now - last_ts > self.cooldown_seconds
        ]
        for key in expired:
            del self._open_alerts[key]

    def _flush_one(self, key: tuple, alert: Alert) -> None:
        if key not in self._dirty:
            return
        for sink in self.sinks:
            sink.update(alert)
        self._dirty.discard(key)

    def _absorb_duplicate(self, alert: Alert) -> bool:
        entry = self._open_alerts.get(alert.dedup_key)
        if entry is None:
            return False
        last_ts, existing = entry
        if alert.ts - last_ts > self.cooldown_seconds:
            # Cooldown expired: persist the old alert's final count, then
            # treat this occurrence as a fresh alert.
            self._flush_one(alert.dedup_key, existing)
            del self._open_alerts[alert.dedup_key]
            return False
        existing.count += 1
        # Keep the most severe/most confident view of the ongoing activity;
        # evidence stays as the rule wrote it at first firing (its aggregate
        # view when the threshold tripped), which dedup must not clobber.
        if alert.severity.rank > existing.severity.rank:
            existing.severity = alert.severity
        existing.confidence = max(existing.confidence, alert.confidence)
        self._open_alerts[alert.dedup_key] = (alert.ts, existing)
        self._dirty.add(alert.dedup_key)
        self.stats.alerts_deduplicated += 1
        return True
