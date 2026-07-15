import pytest
from fastapi.testclient import TestClient

from sentryd.core.alerts import Alert, Severity
from sentryd.storage.store import AlertStore
from sentryd.web.api import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "web.db"
    store = AlertStore(db)
    try:
        store.insert(
            Alert(
                rule_id="port_scan",
                severity=Severity.HIGH,
                confidence=0.9,
                title="scan A",
                ts=1000.0,
                src="10.0.0.66",
                dst="10.0.0.9",
                evidence={"distinct_targets": 20},
            )
        )
        store.insert(
            Alert(
                rule_id="suspicious_port",
                severity=Severity.MEDIUM,
                confidence=0.6,
                title="telnet B",
                ts=2000.0,
                src="10.0.0.7",
                dst="10.0.0.8",
                evidence={"port": 23},
                ai_summary="WHAT HAPPENED: telnet.",
            )
        )
    finally:
        store.close()
    return TestClient(create_app(db))


def test_list_alerts(client):
    data = client.get("/api/alerts").json()
    assert len(data["alerts"]) == 2
    assert data["alerts"][0]["title"] == "telnet B"  # newest first


def test_filters(client):
    assert len(client.get("/api/alerts?severity=high").json()["alerts"]) == 1
    assert len(client.get("/api/alerts?rule=port_scan").json()["alerts"]) == 1
    assert len(client.get("/api/alerts?severity=low").json()["alerts"]) == 0
    assert client.get("/api/alerts?severity=bogus").status_code == 422


def test_alert_detail(client):
    alert = client.get("/api/alerts/1").json()
    assert alert["rule_id"] == "port_scan"
    assert alert["evidence"] == {"distinct_targets": 20}
    assert alert["ai_summary"] is None

    triaged = client.get("/api/alerts/2").json()
    assert triaged["ai_summary"].startswith("WHAT HAPPENED")


def test_missing_alert_404(client):
    assert client.get("/api/alerts/999").status_code == 404


def test_stats(client):
    stats = client.get("/api/stats").json()
    assert stats["total"] == 2
    assert stats["by_severity"] == {"high": 1, "medium": 1}
    assert stats["by_rule"] == {"port_scan": 1, "suspicious_port": 1}


def test_frontend_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "sentryd" in page.text
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200
