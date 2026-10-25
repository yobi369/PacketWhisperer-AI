from fastapi.testclient import TestClient
from packetwhisperer.api import app

client = TestClient(app)

def test_health_and_ready():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["status"] == "ready"

def test_rejects_non_csv():
    response = client.post("/v1/analyze/flows", files={"file": ("capture.exe", b"x", "application/octet-stream")})
    assert response.status_code == 415

def test_upload_returns_hash_and_report():
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    response = client.post("/v1/analyze/flows", files={"file": ("flows.csv", csv, "text/csv")})
    assert response.status_code == 200
    body = response.json()
    assert len(body["evidence"]["sha256"]) == 64
    assert body["flow_count"] == 1


def test_production_readiness_fails_without_authentication(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("PACKETWHISPERER_API_TOKEN", raising=False)
    assert client.get("/ready").status_code == 503
    response = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", b"data", "text/csv")},
    )
    assert response.status_code == 503


def test_configured_bearer_token_protects_analysis(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PACKETWHISPERER_API_TOKEN", "test-secret-token")
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    denied = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", csv, "text/csv")},
    )
    assert denied.status_code == 401
    allowed = client.post(
        "/v1/analyze/flows",
        headers={"Authorization": "Bearer test-secret-token"},
        files={"file": ("flows.csv", csv, "text/csv")},
    )
    assert allowed.status_code == 200


def test_dashboard_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "PacketWhisperer AI" in response.text
    assert "Evidence integrity" in response.text


def test_security_headers_and_no_store_for_analysis(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("PACKETWHISPERER_API_TOKEN", raising=False)
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    report = client.post("/v1/analyze/flows", files={"file": ("flows.csv", csv, "text/csv")})
    assert report.status_code == 200
    assert report.headers["cache-control"] == "no-store"
