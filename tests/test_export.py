import csv
import io
import json
from pathlib import Path

from typer.testing import CliRunner

from sentryd.cli import app
from sentryd.core.alerts import Alert, AlertStatus, Severity
from sentryd.core.cases import Case, CaseStatus
from sentryd.core.correlate import correlate
from sentryd.export import alerts_to_csv, alerts_to_json, case_report_markdown, case_to_json

runner = CliRunner(env={"COLUMNS": "200"})
FIXTURES = Path(__file__).parent / "fixtures"


def sample_alerts() -> list[Alert]:
    return [
        Alert(
            id=1,
            rule_id="port_scan",
            severity=Severity.HIGH,
            confidence=0.9,
            title="Port scan: 10.0.0.66",
            ts=1000.0,
            last_ts=1010.0,
            src="10.0.0.66",
            dst="10.0.0.9",
            protocol="tcp",
            evidence={"distinct_targets": 20},
            reason="20 targets in 2s",
            case_id=1,
            count=3,
        ),
        Alert(
            id=2,
            rule_id="suspicious_port",
            severity=Severity.MEDIUM,
            confidence=0.6,
            title='Telnet, with "quotes", and, commas',
            ts=1005.0,
            src="10.0.0.66",
            dst="10.0.0.9",
            dst_port=23,
            src_port=40123,
            protocol="tcp",
            evidence={"port": 23},
            reason="watchlisted",
            case_id=1,
            status=AlertStatus.TRIAGED,
        ),
    ]


def sample_case(**overrides) -> Case:
    defaults = dict(
        id=1,
        name="demo.pcap",
        source_kind="pcap",
        source="demo.pcap",
        status=CaseStatus.COMPLETE,
        created_at="2026-01-01 00:00:00",
        events_processed=71,
        start_ts=1000.0,
        end_ts=1060.0,
        pcap_sha256="ab" * 32,
        pcap_size=4922,
    )
    return Case(**{**defaults, **overrides})


def test_json_export_roundtrips():
    data = json.loads(alerts_to_json(sample_alerts()))
    assert len(data) == 2
    assert data[0]["rule_id"] == "port_scan"
    assert data[0]["last_ts"] == 1010.0
    assert data[1]["dst_port"] == 23


def test_csv_export_is_parseable_with_quoting():
    rows = list(csv.DictReader(io.StringIO(alerts_to_csv(sample_alerts()))))
    assert len(rows) == 2
    assert rows[0]["rule"] == "port_scan"
    assert rows[0]["count"] == "3"
    assert rows[1]["title"] == 'Telnet, with "quotes", and, commas'
    assert rows[1]["dst_port"] == "23"


def test_markdown_report_is_complete_without_ai():
    alerts = sample_alerts()
    report = case_report_markdown(sample_case(), alerts, correlate(alerts))

    assert "# sentryd case report: demo.pcap" in report
    assert "sha256" in report
    assert "## Correlated activity" in report
    assert "reconnaissance" in report
    assert "[#1] Port scan" in report
    assert "Why it fired" in report
    assert "Next step" in report
    assert "AI review" not in report  # no AI section unless one exists


def test_markdown_report_appends_ai_section():
    case = sample_case(ai_report="## Executive summary\nbad scan", ai_report_at="2026-01-02")
    report = case_report_markdown(case, [], [])
    assert "## AI review (generated 2026-01-02 UTC)" in report
    assert "bad scan" in report
    assert "No alerts were raised" in report


def test_case_json_bundle():
    alerts = sample_alerts()
    bundle = json.loads(case_to_json(sample_case(), alerts, correlate(alerts)))
    assert bundle["case"]["name"] == "demo.pcap"
    assert len(bundle["alerts"]) == 2
    assert bundle["clusters"][0]["chain"]


def test_cli_export_alerts_csv(tmp_path):
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])
    out = tmp_path / "alerts.csv"

    result = runner.invoke(
        app, ["export", "alerts", "--db", str(db), "--format", "csv", "-o", str(out)]
    )

    assert result.exit_code == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text())))
    assert len(rows) == 3
    assert {r["rule"] for r in rows} == {"port_scan", "suspicious_port"}


def test_cli_export_case_markdown(tmp_path):
    db = tmp_path / "t.db"
    runner.invoke(app, ["replay", str(FIXTURES / "portscan.pcap"), "--db", str(db)])

    result = runner.invoke(app, ["export", "case", "1", "--db", str(db), "--format", "md"])

    assert result.exit_code == 0
    assert "# sentryd case report: portscan.pcap" in result.output
    assert "Correlated activity" in result.output


def test_cli_export_rejects_unknown_format(tmp_path):
    result = runner.invoke(
        app, ["export", "alerts", "--db", str(tmp_path / "t.db"), "--format", "xml"]
    )
    assert result.exit_code == 1
    assert "unsupported format" in result.output
