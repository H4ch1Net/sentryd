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
    assert stats["sources"] == 2  # 10.0.0.66 and 10.0.0.7
    assert stats["triaged"] == 1  # only "telnet B" has an ai_summary


def test_timeline(client):
    data = client.get("/api/timeline?buckets=10").json()
    assert data["start"] == 1000.0
    assert data["end"] == 2000.0
    assert len(data["buckets"]) == 10
    assert sum(b["count"] for b in data["buckets"]) == 2
    # first alert (high) lands in the first bucket, second (medium) in the last
    assert data["buckets"][0]["by_severity"] == {"high": 1}
    assert data["buckets"][-1]["by_severity"] == {"medium": 1}


def test_timeline_empty_store(tmp_path):
    empty = TestClient(create_app(tmp_path / "empty.db"))
    data = empty.get("/api/timeline").json()
    assert data == {"start": None, "end": None, "buckets": []}


def test_timeline_bucket_bounds_validated(client):
    assert client.get("/api/timeline?buckets=0").status_code == 422
    assert client.get("/api/timeline?buckets=9999").status_code == 422


def test_frontend_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "sentryd" in page.text
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200


# -- change detection ------------------------------------------------------------


def test_revision_endpoint_tracks_writes(client):
    before = client.get("/api/revision").json()["revision"]
    client.post("/api/alerts/1/status", json={"status": "confirmed"})
    assert client.get("/api/revision").json()["revision"] > before


def test_data_gets_revalidate_with_etag(client):
    first = client.get("/api/stats")
    etag = first.headers["etag"]
    assert first.headers["cache-control"] == "no-cache"

    unchanged = client.get("/api/stats", headers={"If-None-Match": etag})
    assert unchanged.status_code == 304
    assert unchanged.content == b""

    client.post("/api/alerts/1/status", json={"status": "confirmed"})
    changed = client.get("/api/stats", headers={"If-None-Match": etag})
    assert changed.status_code == 200
    assert changed.headers["etag"] != etag
    assert changed.json()["by_status"]["confirmed"] == 1


def test_non_data_endpoints_are_not_etagged(client):
    assert "etag" not in client.get("/api/status").headers
    assert "etag" not in client.get("/api/rules").headers


def test_revalidation_sits_behind_the_token_gate(tmp_path):
    gated = TestClient(create_app(tmp_path / "t.db", api_token="s3cret"))
    auth = {"Authorization": "Bearer s3cret"}
    etag = gated.get("/api/stats", headers=auth).headers["etag"]
    # a cached validator must not let an unauthenticated client past the gate
    assert gated.get("/api/stats", headers={"If-None-Match": etag}).status_code == 401


def test_dashboard_bundles_stats_timeline_and_cases(client):
    data = client.get("/api/dashboard?buckets=8").json()

    assert data["revision"] == client.get("/api/revision").json()["revision"]
    assert data["stats"]["total"] == 2
    assert len(data["timeline"]["buckets"]) == 8
    assert data["cases"] == []
    assert client.get("/api/dashboard?buckets=2").status_code == 422


def test_bulk_verdicts(client):
    def bulk(ids, status):
        return client.post("/api/alerts/bulk-status", json={"ids": ids, "status": status})

    assert bulk([1, 2, 99], "expected").json() == {"updated": 2, "status": "expected"}
    assert {a["status"] for a in client.get("/api/alerts").json()["alerts"]} == {"expected"}

    assert bulk([1], "triaged").status_code == 422  # legacy value, not a verdict
    assert bulk([], "new").status_code == 422


def test_rules_endpoint_includes_summaries(client):
    rules = {r["rule_id"]: r for r in client.get("/api/rules").json()["rules"]}
    assert "beacon" in rules
    assert rules["port_scan"]["summary"].startswith("Port scan detection")


def test_case_detail_reports_risk_and_phases(tmp_path):
    from sentryd.core.cases import Case

    db = tmp_path / "case.db"
    with AlertStore(db) as store:
        case = store.create_case(Case(id=None, name="demo", source_kind="pcap", source="x"))
        store.insert(Alert(rule_id="port_scan", severity=Severity.HIGH, confidence=0.7,
                           title="scan", ts=100.0, src="10.0.0.66", dst="10.0.0.9",
                           evidence={}, case_id=case.id))
        store.insert(Alert(rule_id="beacon", severity=Severity.MEDIUM, confidence=0.8,
                           title="beacon", ts=200.0, src="10.0.0.66", dst="198.51.100.7",
                           evidence={}, case_id=case.id, dst_port=443))

    detail = TestClient(create_app(db)).get(f"/api/cases/{case.id}").json()

    cluster = detail["clusters"][0]
    assert [p["phase"] for p in cluster["phases"]] == ["reconnaissance", "command-and-control"]
    assert detail["risk"]["source"] == "10.0.0.66"
    assert detail["risk"]["score"] == cluster["risk"]["score"] == 60 + 7 + 10


def test_alerts_filter_by_event_time_window(client):
    def titles(query):
        return [a["title"] for a in client.get(f"/api/alerts?{query}").json()["alerts"]]

    assert titles("since=1500") == ["telnet B"]
    assert titles("until=1500") == ["scan A"]
    assert titles("since=1000&until=2000") == ["telnet B", "scan A"]  # inclusive bounds
    assert titles("since=2000.5") == []

    csv_out = client.get("/api/export/alerts?format=csv&until=1500&status=new").text
    assert "scan A" in csv_out and "telnet B" not in csv_out
