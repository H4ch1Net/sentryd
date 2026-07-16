"""Case model: storage CRUD, schema migration, and the case runner."""

import hashlib
import sqlite3
from pathlib import Path

import pytest

from sentryd.core.alerts import Alert, Severity
from sentryd.core.cases import Case, CaseStatus
from sentryd.runner import run_case
from sentryd.sources.base import SourceError
from sentryd.sources.pcap import PcapFileSource
from sentryd.storage.store import AlertStore

FIXTURES = Path(__file__).parent / "fixtures"


def make_case(**overrides) -> Case:
    defaults = dict(id=None, name="test case", source_kind="pcap", source="x.pcap")
    return Case(**{**defaults, **overrides})


def alert_for_case(case_id, **overrides) -> Alert:
    defaults = dict(
        rule_id="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        title="scan",
        ts=1000.0,
        src="10.0.0.1",
        dst="10.0.0.2",
        evidence={},
        case_id=case_id,
    )
    return Alert(**{**defaults, **overrides})


# -- storage ---------------------------------------------------------------


def test_case_crud_roundtrip(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        case = store.create_case(make_case())
        assert case.id is not None
        assert case.created_at

        fetched = store.get_case(case.id)
        assert fetched.name == "test case"
        assert fetched.status == CaseStatus.RUNNING
        assert fetched.alert_count == 0

        store.insert(alert_for_case(case.id))
        store.finalize_case(
            case.id, CaseStatus.COMPLETE, events_processed=71,
            packet_count=71, start_ts=100.0, end_ts=160.0,
        )
        fetched = store.get_case(case.id)
        assert fetched.status == CaseStatus.COMPLETE
        assert fetched.events_processed == 71
        assert fetched.alert_count == 1
        assert (fetched.start_ts, fetched.end_ts) == (100.0, 160.0)


def test_case_listing_and_archive(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        a = store.create_case(make_case(name="a"))
        b = store.create_case(make_case(name="b"))
        assert [c.name for c in store.list_cases()] == ["b", "a"]
        assert store.latest_case().id == b.id

        store.set_case_status(a.id, CaseStatus.ARCHIVED)
        assert [c.name for c in store.list_cases(include_archived=False)] == ["b"]
        assert len(store.list_cases()) == 2


def test_delete_case_removes_its_alerts_only(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        a = store.create_case(make_case(name="a"))
        b = store.create_case(make_case(name="b"))
        store.insert(alert_for_case(a.id))
        store.insert(alert_for_case(b.id))

        deleted = store.delete_case(a.id)

        assert deleted == 1
        assert store.get_case(a.id) is None
        assert len(store.list()) == 1
        assert store.list()[0].case_id == b.id


def test_clear_wipes_workspace(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        case = store.create_case(make_case())
        store.insert(alert_for_case(case.id))
        store.clear()
        assert store.list() == []
        assert store.list_cases() == []


def test_notes_and_report(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        case = store.create_case(make_case())
        store.set_case_notes(case.id, "checked with netops")
        store.set_case_report(case.id, "## Executive summary\nfine")
        fetched = store.get_case(case.id)
        assert fetched.notes == "checked with netops"
        assert fetched.ai_report.startswith("## Executive")
        assert fetched.ai_report_at


def test_alert_case_filter_and_new_fields(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        case = store.create_case(make_case())
        store.insert(
            alert_for_case(
                case.id,
                protocol="tcp",
                src_port=40123,
                dst_port=4444,
                reason="watchlisted port",
                last_ts=1050.0,
            )
        )
        store.insert(alert_for_case(None))

        rows = store.list(case_id=case.id)
        assert len(rows) == 1
        a = rows[0]
        assert (a.protocol, a.src_port, a.dst_port) == ("tcp", 40123, 4444)
        assert a.reason == "watchlisted port"
        assert a.last_seen == 1050.0
        assert len(store.list()) == 2


# -- migration -------------------------------------------------------------

V1_SCHEMA = """
CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    rule_id     TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    title       TEXT    NOT NULL,
    src         TEXT,
    dst         TEXT,
    evidence    TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    status      TEXT    NOT NULL DEFAULT 'new',
    ai_summary  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def test_v1_database_is_migrated_in_place(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(V1_SCHEMA)
    conn.execute(
        "INSERT INTO alerts (ts, rule_id, severity, confidence, title, evidence)"
        " VALUES (1.0, 'port_scan', 'high', 0.9, 'old alert', '{}')"
    )
    conn.commit()
    conn.close()

    with AlertStore(db) as store:
        old = store.list()[0]  # old rows read back with defaults
        assert old.title == "old alert"
        assert old.case_id is None
        assert old.reason == ""

        case = store.create_case(make_case())  # new features work
        store.insert(alert_for_case(case.id, reason="r"))
        assert store.get_case(case.id).alert_count == 1


# -- runner ------------------------------------------------------------------


def test_run_case_replays_pcap_into_a_case(tmp_path):
    pcap = FIXTURES / "portscan.pcap"
    result = run_case(
        tmp_path / "t.db",
        PcapFileSource(pcap),
        source_kind="pcap",
        source_label=str(pcap),
    )

    case = result.case
    assert case.status == CaseStatus.COMPLETE
    assert case.name == "portscan.pcap"
    assert case.events_processed == 71
    assert case.packet_count == 71
    assert case.alert_count == 3
    assert case.start_ts < case.end_ts
    assert case.pcap_sha256 == hashlib.sha256(pcap.read_bytes()).hexdigest()
    assert case.pcap_size == pcap.stat().st_size

    with AlertStore(tmp_path / "t.db") as store:
        alerts = store.list(case_id=case.id)
        assert len(alerts) == 3
        assert all(a.case_id == case.id for a in alerts)
        assert all(a.reason for a in alerts)  # every rule states why it fired


def test_run_case_marks_failure_and_reraises(tmp_path):
    with pytest.raises(SourceError):
        run_case(
            tmp_path / "t.db",
            PcapFileSource(tmp_path / "missing.pcap"),
            source_kind="pcap",
            source_label=str(tmp_path / "missing.pcap"),
        )
    with AlertStore(tmp_path / "t.db") as store:
        case = store.latest_case()
        assert case.status == CaseStatus.FAILED
        assert "not found" in case.error


def test_run_case_custom_name(tmp_path):
    pcap = FIXTURES / "benign.pcap"
    result = run_case(
        tmp_path / "t.db",
        PcapFileSource(pcap),
        source_kind="pcap",
        source_label=str(pcap),
        name="baseline traffic",
    )
    assert result.case.name == "baseline traffic"
    assert result.case.alert_count == 0
