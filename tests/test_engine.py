from conftest import make_event

from sentryd.core.alerts import Alert, Severity
from sentryd.core.engine import RuleEngine
from sentryd.core.events import Event
from sentryd.rules.base import Rule


class AlwaysFireRule(Rule):
    """Fires a fixed alert for every TCP event — exercises engine dedup."""

    rule_id = "always_fire"

    def process(self, event: Event) -> list[Alert]:
        if event.protocol != "tcp":
            return []
        return [
            Alert(
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                confidence=0.5,
                title="test alert",
                ts=event.ts,
                src=event.src_ip,
                dst=event.dst_ip,
                evidence={"first_ts": event.ts},
            )
        ]


class BrokenRule(Rule):
    rule_id = "broken"

    def process(self, event: Event) -> list[Alert]:
        raise RuntimeError("boom")


class RecordingSink:
    def __init__(self):
        self.emitted: list[Alert] = []
        self.updated: list[Alert] = []

    def emit(self, alert):
        self.emitted.append(alert)

    def update(self, alert):
        self.updated.append(alert)


def test_duplicates_merged_within_cooldown():
    sink = RecordingSink()
    engine = RuleEngine([AlwaysFireRule()], sinks=[sink], cooldown_seconds=60)

    for i in range(5):
        engine.process(make_event(ts=100.0 + i))
    engine.flush()

    assert len(sink.emitted) == 1
    assert sink.emitted[0].count == 5
    assert engine.stats.alerts_emitted == 1
    assert engine.stats.alerts_deduplicated == 4
    # flush pushed the final count to sinks exactly once
    assert len(sink.updated) == 1
    assert sink.updated[0].count == 5


def test_new_alert_after_cooldown_expires():
    sink = RecordingSink()
    engine = RuleEngine([AlwaysFireRule()], sinks=[sink], cooldown_seconds=60)

    engine.process(make_event(ts=100.0))
    engine.process(make_event(ts=300.0))  # 200s later — past cooldown

    assert len(sink.emitted) == 2
    assert all(a.count == 1 for a in sink.emitted)


class KeyedRule(Rule):
    """Emits alerts keyed by dst port, like suspicious_port does."""

    rule_id = "keyed"

    def process(self, event: Event) -> list[Alert]:
        return [
            Alert(
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                confidence=0.5,
                title=f"hit on port {event.dst_port}",
                ts=event.ts,
                src=event.src_ip,
                dst=event.dst_ip,
                key=str(event.dst_port),
                evidence={"port": event.dst_port},
            )
        ]


def test_distinct_findings_same_src_dst_not_merged():
    # Regression: two different watched ports between the same pair of hosts
    # must stay two alerts — only true repeats of the same finding merge.
    sink = RecordingSink()
    engine = RuleEngine([KeyedRule()], sinks=[sink], cooldown_seconds=60)

    engine.process(make_event(ts=100.0, dst_port=23))
    engine.process(make_event(ts=101.0, dst_port=4444))
    engine.process(make_event(ts=102.0, dst_port=23))  # repeat -> merges

    assert len(sink.emitted) == 2
    by_title = {a.title: a for a in sink.emitted}
    assert by_title["hit on port 23"].count == 2
    assert by_title["hit on port 4444"].count == 1


def test_different_src_dst_not_merged():
    sink = RecordingSink()
    engine = RuleEngine([AlwaysFireRule()], sinks=[sink], cooldown_seconds=60)

    engine.process(make_event(ts=100.0, src_ip="10.0.0.1"))
    engine.process(make_event(ts=101.0, src_ip="10.0.0.2"))

    assert len(sink.emitted) == 2


def test_failing_rule_does_not_stop_the_run():
    sink = RecordingSink()
    engine = RuleEngine([BrokenRule(), AlwaysFireRule()], sinks=[sink])

    engine.process(make_event(ts=100.0))

    assert len(sink.emitted) == 1  # AlwaysFireRule still ran


def test_merge_keeps_rule_written_evidence():
    # Dedup must never clobber the evidence the rule wrote at first firing —
    # that's the aggregate view an analyst verifies the finding with.
    sink = RecordingSink()
    engine = RuleEngine([AlwaysFireRule()], sinks=[sink], cooldown_seconds=60)

    engine.process(make_event(ts=100.0))
    engine.process(make_event(ts=105.0))

    assert sink.emitted[0].count == 2
    assert sink.emitted[0].evidence == {"first_ts": 100.0}


def test_counts_persisted_mid_run_by_maintenance():
    # An endless live source never reaches the end-of-run flush; pending
    # count updates must still land in sinks as event time advances.
    sink = RecordingSink()
    engine = RuleEngine([AlwaysFireRule()], sinks=[sink], cooldown_seconds=10)

    engine.process(make_event(ts=100.0))
    engine.process(make_event(ts=105.0))  # merged -> pending update
    assert sink.updated == []  # not yet persisted

    # unrelated traffic a cooldown later triggers maintenance
    engine.process(make_event(ts=120.0, src_ip="10.9.9.9"))

    assert len(sink.updated) == 1
    assert sink.updated[0].count == 2


def test_maintenance_evicts_expired_dedup_state():
    engine = RuleEngine([AlwaysFireRule()], cooldown_seconds=10)

    for i in range(20):
        engine.process(make_event(ts=100.0, src_ip=f"10.0.{i}.1"))
    assert len(engine._open_alerts) == 20

    engine.process(make_event(ts=200.0, src_ip="10.9.9.9"))  # all 20 long expired

    assert len(engine._open_alerts) == 1  # only the fresh alert remains


def test_run_drains_source_and_reports_stats():
    engine = RuleEngine([AlwaysFireRule()], cooldown_seconds=0.5)
    events = [make_event(ts=100.0 + i * 10) for i in range(3)]

    stats = engine.run(iter(events))

    assert stats.events_processed == 3
    assert stats.alerts_emitted == 3  # each 10s apart, cooldown 0.5s
    assert stats.by_severity == {"medium": 3}
