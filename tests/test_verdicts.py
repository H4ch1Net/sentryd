"""Alert verdicts (analyst status) and packet/byte counts."""

from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentryd.cli import app
from sentryd.core.alerts import AlertStatus
from sentryd.storage.store import AlertStore
from sentryd.web.api import create_app

runner = CliRunner(env={"COLUMNS": "220"})
FIXTURES = Path(__file__).parent / "fixtures"


def seeded(tmp_path) -> Path:
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])
    return db


# -- counts populated by rules -------------------------------------------------


def test_rules_populate_packet_and_byte_counts(tmp_path):
    db = seeded(tmp_path)
    with AlertStore(db) as store:
        by_rule = {a.rule_id: a for a in store.list()}
        assert by_rule["port_scan"].packet_count >= 15  # syn attempts
        sp = by_rule["suspicious_port"]
        assert sp.packet_count == 1
        assert sp.byte_count and sp.byte_count > 0


def test_counts_survive_json_and_csv(tmp_path):
    db = seeded(tmp_path)
    out = runner.invoke(app, ["export", "alerts", "--db", str(db), "--format", "csv"])
    assert "packet_count" in out.output
    assert "byte_count" in out.output


# -- CLI verdict ---------------------------------------------------------------


def test_cli_set_verdict(tmp_path):
    db = seeded(tmp_path)
    result = runner.invoke(app, ["alerts", "status", "1", "false_positive", "--db", str(db)])
    assert result.exit_code == 0
    with AlertStore(db) as store:
        assert store.get(1).status == AlertStatus.FALSE_POSITIVE

    shown = runner.invoke(app, ["alerts", "show", "1", "--db", str(db)])
    assert "false_positive" in shown.output


def test_cli_rejects_bad_verdict(tmp_path):
    db = seeded(tmp_path)
    result = runner.invoke(app, ["alerts", "status", "1", "banana", "--db", str(db)])
    assert result.exit_code == 1
    assert "invalid verdict" in result.output


def test_cli_verdict_missing_alert(tmp_path):
    db = seeded(tmp_path)
    result = runner.invoke(app, ["alerts", "status", "999", "confirmed", "--db", str(db)])
    assert result.exit_code == 1


def test_cli_filter_by_verdict(tmp_path):
    db = seeded(tmp_path)
    runner.invoke(app, ["alerts", "status", "1", "ignored", "--db", str(db)])
    listed = runner.invoke(app, ["alerts", "list", "--status", "ignored", "--db", str(db)])
    assert "1" in listed.output


# -- API verdict ---------------------------------------------------------------


def test_api_set_verdict(tmp_path):
    db = seeded(tmp_path)
    client = TestClient(create_app(db))

    resp = client.post("/api/alerts/1/status", json={"status": "confirmed"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "confirmed"

    assert client.get("/api/alerts?status=confirmed").json()["alerts"][0]["id"] == 1

    bad = client.post("/api/alerts/1/status", json={"status": "nope"})
    assert bad.status_code == 422

    missing = client.post("/api/alerts/999/status", json={"status": "confirmed"})
    assert missing.status_code == 404


def test_api_alert_detail_includes_counts(tmp_path):
    db = seeded(tmp_path)
    client = TestClient(create_app(db))
    alerts = client.get("/api/alerts?rule=suspicious_port").json()["alerts"]
    detail = client.get(f"/api/alerts/{alerts[0]['id']}").json()
    assert detail["packet_count"] == 1
    assert detail["byte_count"] > 0


def test_explain_does_not_change_verdict(tmp_path):
    db = seeded(tmp_path)

    class FakeProvider:
        name = "fake"
        available = True

        def triage(self, alert):
            from sentryd.triage.base import TriageResult

            return TriageResult(summary="WHAT HAPPENED: scan.", model="fake")

        def generate(self, messages):
            return None

    import sentryd.web.api as api_mod

    client = TestClient(create_app(db))
    original = api_mod.create_provider
    api_mod.create_provider = lambda: FakeProvider()
    try:
        client.post("/api/alerts/1/status", json={"status": "confirmed"})
        explained = client.post("/api/alerts/1/explain").json()
    finally:
        api_mod.create_provider = original

    assert explained["ai_summary"].startswith("WHAT HAPPENED")
    assert explained["status"] == "confirmed"  # verdict preserved
