"""Security hardening: optional API token, server-side replay path sandbox."""

from pathlib import Path

from fastapi.testclient import TestClient

from sentryd.web.api import create_app

FIXTURES = Path(__file__).parent / "fixtures"


# -- token gate ----------------------------------------------------------------


def test_no_token_by_default(tmp_path):
    client = TestClient(create_app(tmp_path / "t.db"))
    assert client.get("/api/cases").status_code == 200


def test_token_required_when_configured(tmp_path):
    client = TestClient(create_app(tmp_path / "t.db", api_token="s3cret"))

    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers={"Authorization": "Bearer wrong"}).status_code == 401

    ok = client.get("/api/cases", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200


def test_token_does_not_block_static_ui(tmp_path):
    client = TestClient(create_app(tmp_path / "t.db", api_token="s3cret"))
    # The SPA itself is served without a token; only /api/* is gated.
    assert client.get("/").status_code == 200


def test_token_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRYD_API_TOKEN", "envtok")
    client = TestClient(create_app(tmp_path / "t.db"))
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers={"Authorization": "Bearer envtok"}).status_code == 200


# -- replay path sandbox -------------------------------------------------------


def test_replay_rejects_path_outside_sandbox(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTRYD_PCAP_DIR", raising=False)
    uploads = tmp_path / "uploads"
    client = TestClient(create_app(tmp_path / "t.db", uploads_dir=uploads))

    # A real file that is NOT under the uploads dir must be refused.
    resp = client.post("/api/replay", json={"path": str(FIXTURES / "portscan.pcap")})
    assert resp.status_code == 403
    assert "must be inside" in resp.json()["detail"]

    traversal = client.post("/api/replay", json={"path": "../../etc/passwd"})
    assert traversal.status_code in (403, 404)


def test_replay_allows_path_inside_sandbox(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    dest = uploads / "sample.pcap"
    dest.write_bytes((FIXTURES / "portscan.pcap").read_bytes())
    client = TestClient(create_app(tmp_path / "t.db", uploads_dir=uploads))

    resp = client.post("/api/replay", json={"path": str(dest)})
    assert resp.status_code == 202


def test_replay_honors_configured_pcap_dir(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    dest = samples / "sample.pcap"
    dest.write_bytes((FIXTURES / "portscan.pcap").read_bytes())
    monkeypatch.setenv("SENTRYD_PCAP_DIR", str(samples))
    client = TestClient(create_app(tmp_path / "t.db", uploads_dir=tmp_path / "uploads"))

    assert client.post("/api/replay", json={"path": str(dest)}).status_code == 202
    outside = client.post("/api/replay", json={"path": str(FIXTURES / "benign.pcap")})
    assert outside.status_code == 403
