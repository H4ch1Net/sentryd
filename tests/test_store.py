import pytest

from sentryd.core.alerts import Alert, AlertStatus, Severity
from sentryd.storage.store import AlertStore


@pytest.fixture
def store(tmp_path):
    s = AlertStore(tmp_path / "test.db")
    yield s
    s.close()


def sample_alert(**overrides) -> Alert:
    defaults = dict(
        rule_id="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        title="test scan",
        ts=1000.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        evidence={"distinct_targets": 20, "sample_ports": [22, 80]},
    )
    return Alert(**{**defaults, **overrides})


def test_insert_get_roundtrip(store):
    inserted = store.insert(sample_alert())
    assert inserted.id is not None

    fetched = store.get(inserted.id)
    assert fetched is not None
    assert fetched.rule_id == "port_scan"
    assert fetched.severity == Severity.HIGH
    assert fetched.evidence == {"distinct_targets": 20, "sample_ports": [22, 80]}
    assert fetched.status == AlertStatus.NEW
    assert fetched.ai_summary is None


def test_get_missing_returns_none(store):
    assert store.get(999) is None


def test_list_filters(store):
    store.insert(sample_alert(rule_id="port_scan", severity=Severity.HIGH, ts=1.0))
    store.insert(sample_alert(rule_id="suspicious_port", severity=Severity.MEDIUM, ts=2.0))
    store.insert(sample_alert(rule_id="port_scan", severity=Severity.HIGH, ts=3.0))

    assert len(store.list()) == 3
    assert len(store.list(rule_id="port_scan")) == 2
    assert len(store.list(severity="medium")) == 1
    assert len(store.list(limit=1)) == 1
    # newest first
    assert [a.ts for a in store.list()] == [3.0, 2.0, 1.0]


def test_update_reflects_dedup_count(store):
    alert = store.insert(sample_alert())
    alert.count = 7
    alert.confidence = 0.95
    store.update(alert)

    assert store.get(alert.id).count == 7
    assert store.get(alert.id).confidence == 0.95


def test_set_ai_summary_does_not_change_verdict(store):
    # AI presence is tracked by ai_summary; it must not touch the verdict.
    alert = store.insert(sample_alert())
    store.set_ai_summary(alert.id, "Analyst writeup here.")

    fetched = store.get(alert.id)
    assert fetched.ai_summary == "Analyst writeup here."
    assert fetched.status == AlertStatus.NEW


def test_set_status(store):
    alert = store.insert(sample_alert())
    store.set_status(alert.id, AlertStatus.FALSE_POSITIVE)
    assert store.get(alert.id).status == AlertStatus.FALSE_POSITIVE


def test_stats(store):
    store.insert(sample_alert(severity=Severity.HIGH, rule_id="port_scan"))
    store.insert(sample_alert(severity=Severity.HIGH, rule_id="port_scan"))
    store.insert(sample_alert(severity=Severity.MEDIUM, rule_id="suspicious_port"))

    stats = store.stats()
    assert stats["total"] == 3
    assert stats["by_severity"] == {"high": 2, "medium": 1}
    assert stats["by_rule"] == {"port_scan": 2, "suspicious_port": 1}
