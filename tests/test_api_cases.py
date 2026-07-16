"""REST API: pcap intake, cases, triage, rules, hosts, exports."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentryd.web.api import create_app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path / "web.db", uploads_dir=tmp_path / "uploads"))


def wait_complete(client, case_id, timeout=15.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/cases/{case_id}/status").json()
        if status["status"] in ("complete", "failed"):
            return status
        time.sleep(0.05)
    raise AssertionError("replay did not finish in time")


def upload_fixture(client, name="portscan.pcap") -> dict:
    with (FIXTURES / name).open("rb") as fh:
        response = client.post(
            "/api/pcaps/upload", files={"file": (name, fh, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 202, response.text
    return response.json()["case"]


def test_upload_creates_case_and_replays(client, tmp_path):
    case = upload_fixture(client)
    assert case["source_kind"] == "pcap"
    assert case["name"] == "portscan.pcap"

    status = wait_complete(client, case["id"])
    assert status["status"] == "complete"
    assert status["alert_count"] == 3
    assert status["events_processed"] == 71

    # uploaded file landed in the uploads dir and alerts are case-scoped
    assert list((tmp_path / "uploads").glob("*portscan.pcap"))
    alerts = client.get(f"/api/alerts?case={case['id']}").json()["alerts"]
    assert len(alerts) == 3
    assert all(a["case_id"] == case["id"] for a in alerts)


def test_upload_rejects_wrong_type_and_empty(client):
    bad = client.post("/api/pcaps/upload", files={"file": ("notes.txt", b"hi", "text/plain")})
    assert bad.status_code == 422
    assert "unsupported file type" in bad.json()["detail"]

    empty = client.post(
        "/api/pcaps/upload", files={"file": ("x.pcap", b"", "application/octet-stream")}
    )
    assert empty.status_code == 422


def test_server_side_replay_path(client, monkeypatch):
    # Allow replay from the fixtures dir for this test (default sandbox is the
    # uploads dir; the dedicated sandbox tests live in test_security.py).
    monkeypatch.setenv("SENTRYD_PCAP_DIR", str(FIXTURES))

    response = client.post(
        "/api/replay", json={"path": str(FIXTURES / "arpspoof.pcap"), "name": "arp run"}
    )
    assert response.status_code == 202
    case = response.json()["case"]
    assert case["name"] == "arp run"
    assert wait_complete(client, case["id"])["alert_count"] == 1

    missing = client.post("/api/replay", json={"path": str(FIXTURES / "missing.pcap")})
    assert missing.status_code == 404


def test_case_detail_and_lifecycle(client):
    case = upload_fixture(client)
    wait_complete(client, case["id"])

    detail = client.get(f"/api/cases/{case['id']}").json()
    assert detail["case"]["pcap_sha256"]
    assert detail["stats"]["total"] == 3
    assert detail["clusters"][0]["chain"]

    assert client.get("/api/cases").json()["cases"][0]["id"] == case["id"]

    archived = client.post(f"/api/cases/{case['id']}/archive").json()
    assert archived["status"] == "archived"
    assert client.get("/api/cases?include_archived=false").json()["cases"] == []

    noted = client.post(f"/api/cases/{case['id']}/notes", json={"notes": "checked"}).json()
    assert noted["notes"] == "checked"

    deleted = client.delete(f"/api/cases/{case['id']}").json()
    assert deleted["deleted_alerts"] == 3
    assert client.get(f"/api/cases/{case['id']}").status_code == 404


def test_alert_detail_includes_investigation_context(client):
    case = upload_fixture(client)
    wait_complete(client, case["id"])
    alerts = client.get(f"/api/alerts?case={case['id']}").json()["alerts"]

    detail = client.get(f"/api/alerts/{alerts[0]['id']}").json()

    assert detail["reason"]
    assert detail["investigation_hint"]
    assert isinstance(detail["related"], list) and detail["related"]


def test_triage_endpoints_without_ai_fail_clearly(client, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    case = upload_fixture(client)
    wait_complete(client, case["id"])
    alert_id = client.get("/api/alerts").json()["alerts"][0]["id"]

    for response in (
        client.post(f"/api/cases/{case['id']}/triage"),
        client.post(f"/api/alerts/{alert_id}/explain"),
    ):
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"]


def test_case_triage_with_fake_provider(client, monkeypatch):
    class FakeProvider:
        name = "fake"
        available = True

        def triage(self, alert):
            return None

        def generate(self, messages):
            return "## Executive summary\nscan then metasploit port"

    monkeypatch.setattr("sentryd.web.api.create_provider", lambda: FakeProvider())
    case = upload_fixture(client)
    wait_complete(client, case["id"])

    reviewed = client.post(f"/api/cases/{case['id']}/triage").json()
    assert "Executive summary" in reviewed["ai_report"]

    # cached: second call returns without regenerating
    assert client.post(f"/api/cases/{case['id']}/triage").json()["ai_report"] == reviewed["ai_report"]

    report = client.get(f"/api/cases/{case['id']}/report")
    assert report.headers["content-type"].startswith("text/markdown")
    assert "## AI review" in report.text


def test_export_endpoints(client):
    case = upload_fixture(client)
    wait_complete(client, case["id"])

    csv_out = client.get(f"/api/export/alerts?format=csv&case={case['id']}")
    assert csv_out.status_code == 200
    assert csv_out.text.count("\n") == 4  # header + 3 alerts
    assert "attachment" in csv_out.headers["content-disposition"]

    json_out = client.get("/api/export/alerts?format=json")
    assert json_out.status_code == 200

    bundle = client.get(f"/api/cases/{case['id']}/report?format=json")
    assert bundle.status_code == 200
    assert "clusters" in bundle.json()


def test_rules_and_hosts_endpoints(client):
    rules = client.get("/api/rules").json()["rules"]
    ids = {r["rule_id"] for r in rules}
    assert {"port_scan", "suspicious_port", "traffic_spike", "arp_spoof"} <= ids
    assert all("config" in r and "effective_enabled" in r for r in rules)

    case = upload_fixture(client)
    wait_complete(client, case["id"])
    host = client.get(f"/api/hosts/192.168.1.66?case={case['id']}").json()
    assert host["alerts_as_source"] == 3
    assert "port_scan" in host["rules"]
