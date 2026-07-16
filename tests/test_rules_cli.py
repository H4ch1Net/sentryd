from pathlib import Path

import yaml
from typer.testing import CliRunner

from sentryd.cli import app

runner = CliRunner(env={"COLUMNS": "220"})
FIXTURES = Path(__file__).parent / "fixtures"


def test_rules_list_shows_all_rules():
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == 0
    for rule in ("port_scan", "suspicious_port", "traffic_spike", "arp_spoof", "signature"):
        assert rule in result.output
    assert "min_distinct_targets=15" in result.output


def test_rules_explain_known_and_unknown():
    good = runner.invoke(app, ["rules", "explain", "suspicious_port"])
    assert good.exit_code == 0
    assert "watchlist" in good.output.lower()
    assert "effective settings" in good.output

    bad = runner.invoke(app, ["rules", "explain", "nope"])
    assert bad.exit_code == 1
    assert "unknown rule" in bad.output


def test_rules_lint_ok_and_failing(tmp_path):
    ok = runner.invoke(app, ["rules", "lint"])
    assert ok.exit_code == 0
    assert "OK" in ok.output

    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump({"rules": {"made_up_rule": {}}}))
    fail = runner.invoke(app, ["rules", "lint", "--config", str(broken)])
    assert fail.exit_code == 1
    assert "FAIL" in fail.output
    assert "made_up_rule" in fail.output

    bad_sig = tmp_path / "sig.yaml"
    bad_sig.write_text(yaml.safe_dump({"signatures": [{"title": "missing id"}]}))
    fail2 = runner.invoke(app, ["rules", "lint", "--config", str(bad_sig)])
    assert fail2.exit_code == 1


def test_rules_test_dry_runs_one_rule(tmp_path):
    result = runner.invoke(
        app,
        ["rules", "test", "--rule", "port_scan", "--pcap", str(FIXTURES / "portscan.pcap")],
    )
    assert result.exit_code == 0
    assert "1 alert(s)" in result.output
    assert "nothing stored" in result.output

    quiet = runner.invoke(
        app,
        ["rules", "test", "--rule", "arp_spoof", "--pcap", str(FIXTURES / "portscan.pcap")],
    )
    assert "0 alert(s)" in quiet.output

    unknown = runner.invoke(
        app, ["rules", "test", "--rule", "nope", "--pcap", str(FIXTURES / "portscan.pcap")]
    )
    assert unknown.exit_code == 1
