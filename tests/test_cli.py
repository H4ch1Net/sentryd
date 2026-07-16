"""CLI-level tests via Typer's runner, the same paths a demo exercises."""

from pathlib import Path

from typer.testing import CliRunner

from sentryd.cli import app
from sentryd.storage.store import AlertStore
from sentryd.triage.base import API_KEY_ENV

# Wide terminal so rich doesn't truncate table cells the assertions look for.
runner = CliRunner(env={"COLUMNS": "200"})
FIXTURES = Path(__file__).parent / "fixtures"


def test_replay_detects_and_stores(tmp_path):
    db = tmp_path / "cli.db"
    result = runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    assert result.exit_code == 0
    assert "Port scan" in result.output

    store = AlertStore(db)
    try:
        assert len(store.list()) == 3
    finally:
        store.close()


def test_replay_missing_file_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["replay", str(tmp_path / "nope.pcap"), "--db", str(tmp_path / "x.db")])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_replay_without_api_key_still_works_with_triage_flag(tmp_path, monkeypatch):
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    db = tmp_path / "cli.db"

    result = runner.invoke(
        app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db), "--triage"]
    )

    assert result.exit_code == 0
    assert "AI triage skipped" in result.output
    store = AlertStore(db)
    try:
        alerts = store.list()
        assert len(alerts) == 3  # detection unaffected by missing key
        assert all(a.ai_summary is None for a in alerts)
    finally:
        store.close()


def test_triage_command_without_key_explains_and_exits(tmp_path, monkeypatch):
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    db = tmp_path / "cli.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    result = runner.invoke(app, ["triage", "1", "--db", str(db)])

    assert result.exit_code == 2
    assert "not configured" in result.output


def test_alerts_list_and_show(tmp_path):
    db = tmp_path / "cli.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    listed = runner.invoke(app, ["alerts", "list", "--db", str(db)])
    assert listed.exit_code == 0
    assert "port_scan" in listed.output

    shown = runner.invoke(app, ["alerts", "show", "1", "--db", str(db)])
    assert shown.exit_code == 0
    assert "evidence" in shown.output

    missing = runner.invoke(app, ["alerts", "show", "999", "--db", str(db)])
    assert missing.exit_code == 1
