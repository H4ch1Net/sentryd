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


def test_revision_moves_on_every_alert_and_case_write(store):
    from sentryd.core.cases import Case, CaseStatus

    seen = [store.revision()]

    def changed() -> bool:
        seen.append(store.revision())
        return seen[-1] > seen[-2]

    case = store.create_case(Case(id=None, name="c", source_kind="pcap", source="x"))
    assert changed()
    alert = store.insert(sample_alert(case_id=case.id))
    assert changed()
    alert.count = 3
    store.update(alert)
    assert changed()
    store.set_status(alert.id, AlertStatus.CONFIRMED)
    assert changed()
    store.set_case_status(case.id, CaseStatus.ARCHIVED)
    assert changed()
    store.delete_case(case.id)
    assert changed()
    store.get(alert.id)
    store.stats()
    assert not changed()  # reads never move it


def test_revision_is_shared_across_connections(tmp_path):
    with AlertStore(tmp_path / "t.db") as reader, AlertStore(tmp_path / "t.db") as writer:
        before = reader.revision()
        writer.insert(sample_alert())
        assert reader.revision() == before + 1


def test_database_runs_in_wal_mode_and_skips_schema_pass_on_reopen(tmp_path):
    from sentryd.storage.store import SCHEMA_VERSION

    with AlertStore(tmp_path / "t.db") as first:
        first.insert(sample_alert())
        assert first._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert first._conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    with AlertStore(tmp_path / "t.db") as again:
        assert len(again.list()) == 1


def test_set_status_many(store):
    ids = [store.insert(sample_alert()).id for _ in range(3)]

    assert store.set_status_many([*ids[:2], 999], AlertStatus.FALSE_POSITIVE) == 2

    assert [store.get(i).status for i in ids] == [
        AlertStatus.FALSE_POSITIVE, AlertStatus.FALSE_POSITIVE, AlertStatus.NEW,
    ]


def test_stats_report_verdicts_and_target_involvement(store):
    first = store.insert(sample_alert(src="10.0.0.1", dst="10.0.0.2"))
    store.insert(sample_alert(src="10.0.0.3", dst="10.0.0.2", severity=Severity.LOW))
    store.set_status(first.id, AlertStatus.CONFIRMED)

    stats = store.stats()

    assert stats["by_status"] == {"confirmed": 1, "new": 1}
    assert stats["open"] == 1
    hosts = {h["host"]: h for h in stats["top_hosts"]}
    assert hosts["10.0.0.1"] == {"host": "10.0.0.1", "score": 4, "alerts": 1, "targeted": 0}
    assert hosts["10.0.0.2"] == {"host": "10.0.0.2", "score": 2, "alerts": 0, "targeted": 2}
    assert stats["top_hosts"][0]["host"] == "10.0.0.1"


def test_timeline_buckets_match_event_times(store):
    for ts, severity in [(0.0, Severity.HIGH), (4.9, Severity.LOW), (5.0, Severity.LOW),
                         (10.0, Severity.MEDIUM)]:
        store.insert(sample_alert(ts=ts, severity=severity))

    data = store.timeline(buckets=2)

    assert (data["start"], data["end"]) == (0.0, 10.0)
    assert [b["count"] for b in data["buckets"]] == [2, 2]
    assert data["buckets"][0]["by_severity"] == {"high": 1, "low": 1}
    assert data["buckets"][1]["by_severity"] == {"low": 1, "medium": 1}  # last edge clamps in


def test_case_listing_carries_alert_counts(store):
    from sentryd.core.cases import Case

    one = store.create_case(Case(id=None, name="one", source_kind="pcap", source="a"))
    two = store.create_case(Case(id=None, name="two", source_kind="pcap", source="b"))
    for _ in range(3):
        store.insert(sample_alert(case_id=one.id))

    counts = {c.name: c.alert_count for c in store.list_cases()}
    assert counts == {"one": 3, "two": 0}
    assert store.get_case(two.id).alert_count == 0
    assert store.latest_case().name == "two"
