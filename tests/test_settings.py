"""Rule enable/disable, the settings store, and the status endpoint."""

from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentryd.cli import app
from sentryd.config import load_default_config
from sentryd.rules.base import build_rules
from sentryd.runner import run_case
from sentryd.sources.pcap import PcapFileSource
from sentryd.storage.store import AlertStore
from sentryd.web.api import create_app

runner = CliRunner(env={"COLUMNS": "220"})
FIXTURES = Path(__file__).parent / "fixtures"


# -- settings store ------------------------------------------------------------


def test_settings_roundtrip(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        assert store.get_setting("missing", "fallback") == "fallback"
        store.set_setting("k", {"a": 1})
        assert store.get_setting("k") == {"a": 1}
        store.set_setting("k", [1, 2])  # upsert
        assert store.get_setting("k") == [1, 2]


def test_rule_disable_set(tmp_path):
    with AlertStore(tmp_path / "t.db") as store:
        assert store.disabled_rules() == set()
        store.set_rule_disabled("arp_spoof", True)
        assert store.disabled_rules() == {"arp_spoof"}
        store.set_rule_disabled("port_scan", True)
        assert store.disabled_rules() == {"arp_spoof", "port_scan"}
        store.set_rule_disabled("arp_spoof", False)
        assert store.disabled_rules() == {"port_scan"}


# -- build_rules honors disabled ----------------------------------------------


def test_build_rules_skips_disabled():
    config = load_default_config()
    full = {r.rule_id for r in build_rules(config)}
    assert "port_scan" in full

    reduced = {r.rule_id for r in build_rules(config, disabled={"port_scan"})}
    assert "port_scan" not in reduced
    assert reduced == full - {"port_scan"}


# -- runner honors disabled ----------------------------------------------------


def test_disabled_rule_produces_no_alerts(tmp_path):
    db = tmp_path / "t.db"
    with AlertStore(db) as store:
        store.set_rule_disabled("port_scan", True)

    result = run_case(
        db,
        PcapFileSource(FIXTURES / "portscan.pcap"),
        source_kind="pcap",
        source_label=str(FIXTURES / "portscan.pcap"),
    )
    with AlertStore(db) as store:
        rules = {a.rule_id for a in store.list(case_id=result.case.id)}
    assert "port_scan" not in rules  # disabled
    assert "suspicious_port" in rules  # others still fire


# -- CLI -----------------------------------------------------------------------


def test_cli_enable_disable(tmp_path):
    db = tmp_path / "t.db"
    disabled = runner.invoke(app, ["rules", "disable", "arp_spoof", "--db", str(db)])
    assert disabled.exit_code == 0

    listed = runner.invoke(app, ["rules", "list", "--db", str(db)])
    assert "off (toggled)" in listed.output

    with AlertStore(db) as store:
        assert store.disabled_rules() == {"arp_spoof"}

    runner.invoke(app, ["rules", "enable", "arp_spoof", "--db", str(db)])
    with AlertStore(db) as store:
        assert store.disabled_rules() == set()


def test_cli_toggle_unknown_rule(tmp_path):
    result = runner.invoke(app, ["rules", "disable", "nope", "--db", str(tmp_path / "t.db")])
    assert result.exit_code == 1
    assert "unknown rule" in result.output


# -- API -----------------------------------------------------------------------


def test_api_rules_and_toggle(tmp_path):
    client = TestClient(create_app(tmp_path / "t.db"))

    rules = client.get("/api/rules").json()
    assert rules["disabled"] == []
    port_scan = next(r for r in rules["rules"] if r["rule_id"] == "port_scan")
    assert port_scan["effective_enabled"] is True

    toggled = client.post("/api/rules/port_scan/toggle?disabled=true").json()
    assert toggled["disabled"] is True
    assert client.get("/api/rules").json()["disabled"] == ["port_scan"]

    client.post("/api/rules/port_scan/toggle?disabled=false")
    assert client.get("/api/rules").json()["disabled"] == []

    assert client.post("/api/rules/nope/toggle").status_code == 404


def test_api_status(tmp_path):
    db = tmp_path / "t.db"
    with AlertStore(db) as store:
        store.set_rule_disabled("arp_spoof", True)
    client = TestClient(create_app(db))

    status = client.get("/api/status").json()
    assert "version" in status
    assert status["ai"]["available"] in (True, False)
    assert status["disabled_rules"] == ["arp_spoof"]
    assert status["cases"] == 0
