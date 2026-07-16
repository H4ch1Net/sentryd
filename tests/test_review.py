"""Overall AI review: digest bounds, orchestration, CLI flows."""

import json
from pathlib import Path

from typer.testing import CliRunner

from sentryd.cli import app
from sentryd.core.alerts import Alert, Severity
from sentryd.core.cases import Case
from sentryd.core.correlate import correlate
from sentryd.storage.store import AlertStore
from sentryd.triage.base import API_KEY_ENV
from sentryd.triage.digest import MAX_ALERTS, MAX_DIGEST_CHARS, build_case_digest
from sentryd.triage.prompts import CASE_SYSTEM_PROMPT, build_case_messages
from sentryd.triage.review import generate_case_review

runner = CliRunner(env={"COLUMNS": "200"})
FIXTURES = Path(__file__).parent / "fixtures"

FAKE_REPORT = "## Executive summary\nA port scan followed by a Metasploit-port probe."


class FakeProvider:
    name = "fake"
    available = True

    def __init__(self, report=FAKE_REPORT):
        self.report = report
        self.calls: list[list[dict]] = []

    def triage(self, alert):
        return None

    def generate(self, messages):
        self.calls.append(messages)
        return self.report


def make_case(**overrides) -> Case:
    defaults = dict(id=None, name="c", source_kind="pcap", source="x.pcap")
    return Case(**{**defaults, **overrides})


def make_alert(i: int, **overrides) -> Alert:
    defaults = dict(
        id=i,
        rule_id="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        title=f"alert {i}",
        ts=1000.0 + i,
        src=f"10.0.{i % 50}.{i % 200}",
        dst="10.0.0.9",
        dst_port=1000 + i,
        reason="r" * 50,
        evidence={"sample_ports": list(range(100)), "note": "x" * 500},
    )
    return Alert(**{**defaults, **overrides})


# -- digest ------------------------------------------------------------------


def test_digest_is_bounded_for_noisy_cases():
    alerts = [make_alert(i) for i in range(500)]
    digest = build_case_digest(make_case(id=1), alerts, correlate(alerts))

    assert len(json.dumps(digest, default=str)) <= MAX_DIGEST_CHARS
    assert digest["alerts_included"] <= MAX_ALERTS
    assert digest["totals"]["alerts"] == 500  # totals still reflect everything
    # long evidence got trimmed, not shipped wholesale
    sample = digest["alerts"][0]["evidence"]
    assert len(sample["sample_ports"]) == 6
    assert sample["note"].endswith("...")


def test_digest_prioritizes_severity():
    alerts = [make_alert(i, severity=Severity.LOW) for i in range(60)]
    alerts.append(make_alert(999, severity=Severity.CRITICAL))
    digest = build_case_digest(make_case(id=1), alerts, correlate(alerts))
    assert digest["alerts"][0]["id"] == 999


def test_digest_content_shapes():
    alerts = [
        make_alert(1, rule_id="port_scan"),
        make_alert(2, rule_id="suspicious_port", severity=Severity.MEDIUM, dst_port=4444),
    ]
    digest = build_case_digest(make_case(id=7, name="demo"), alerts, correlate(alerts))

    assert digest["case"]["id"] == 7
    assert digest["totals"]["by_rule"] == {"port_scan": 1, "suspicious_port": 1}
    assert any(p["port"] == 4444 for p in digest["top_ports"])
    assert digest["correlated_clusters"]
    assert digest["timeline"]
    messages = build_case_messages(digest)
    assert messages[0]["content"] == CASE_SYSTEM_PROMPT
    assert "4444" in messages[1]["content"]


# -- orchestration -----------------------------------------------------------


def seeded_store(tmp_path) -> tuple[AlertStore, Case]:
    store = AlertStore(tmp_path / "t.db")
    case = store.create_case(make_case())
    store.insert(make_alert(1, id=None, case_id=case.id))
    return store, store.get_case(case.id)


def test_review_generates_and_persists(tmp_path):
    store, case = seeded_store(tmp_path)
    provider = FakeProvider()

    report = generate_case_review(store, case, provider)

    assert report == FAKE_REPORT
    saved = store.get_case(case.id)
    assert saved.ai_report == FAKE_REPORT
    assert saved.ai_report_at
    assert len(provider.calls) == 1
    store.close()


def test_review_uses_cache_unless_forced(tmp_path):
    store, case = seeded_store(tmp_path)
    provider = FakeProvider()
    generate_case_review(store, case, provider)

    case = store.get_case(case.id)
    assert generate_case_review(store, case, provider) == FAKE_REPORT
    assert len(provider.calls) == 1  # cached, no second call

    provider.report = "## Executive summary\nregenerated"
    assert "regenerated" in generate_case_review(store, case, provider, force=True)
    store.close()


def test_review_unavailable_provider_returns_none(tmp_path):
    from sentryd.triage.base import NullTriage

    store, case = seeded_store(tmp_path)
    assert generate_case_review(store, case, NullTriage()) is None
    assert store.get_case(case.id).ai_report is None
    store.close()


# -- CLI ------------------------------------------------------------------------


def test_cli_triage_latest_without_key_exits_2(tmp_path, monkeypatch):
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    result = runner.invoke(app, ["triage", "latest", "--db", str(db)])

    assert result.exit_code == 2
    assert "not configured" in result.output


def test_cli_triage_latest_with_provider(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])
    monkeypatch.setattr("sentryd.cli.create_provider", lambda: FakeProvider())

    result = runner.invoke(app, ["triage", "latest", "--db", str(db)])

    assert result.exit_code == 0
    assert "Executive summary" in result.output
    with AlertStore(db) as store:
        assert store.latest_case().ai_report == FAKE_REPORT

    # cached on the second run, and surfaced in cases show
    again = runner.invoke(app, ["triage", "latest", "--db", str(db)])
    assert "cached" in again.output
    shown = runner.invoke(app, ["cases", "show", "1", "--db", str(db)])
    assert "Executive summary" in shown.output


def test_cli_triage_pcap_creates_case_and_reviews(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setattr("sentryd.cli.create_provider", lambda: FakeProvider())

    result = runner.invoke(
        app,
        ["triage", "--pcap", str(FIXTURES / "portscan.pcap"), "--db", str(db), "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output[result.output.index("{"):])
    assert payload["case"]["ai_report"] == FAKE_REPORT
    assert payload["case"]["alert_count"] == 3


def test_cli_triage_alert_id_still_works(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    class AlertProvider(FakeProvider):
        def triage(self, alert):
            from sentryd.triage.base import TriageResult

            return TriageResult(summary="WHAT HAPPENED: scan.", model="fake/model")

    monkeypatch.setattr("sentryd.cli.create_provider", lambda: AlertProvider())
    result = runner.invoke(app, ["triage", "2", "--db", str(db)])

    assert result.exit_code == 0
    assert "WHAT HAPPENED" in result.output


def test_cli_triage_rejects_ambiguous_usage(tmp_path):
    result = runner.invoke(
        app, ["triage", "latest", "--case", "1", "--db", str(tmp_path / "t.db")]
    )
    assert result.exit_code == 1
    assert "exactly one" in result.output
