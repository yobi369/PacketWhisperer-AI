from fastapi.testclient import TestClient

from packetwhisperer.api import app

client = TestClient(app)
VALID_TOKEN = "test-secret-token-that-is-at-least-32-bytes"


def test_health_and_ready():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["status"] == "ready"


def test_rejects_non_csv():
    response = client.post(
        "/v1/analyze/flows",
        files={"file": ("capture.exe", b"x", "application/octet-stream")},
    )
    assert response.status_code == 415


def test_upload_returns_hash_and_report(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("PACKETWHISPERER_API_TOKEN", raising=False)
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    response = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", csv, "text/csv")},
    )
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

def test_authentication_rejects_before_multipart_parsing(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PACKETWHISPERER_API_TOKEN", VALID_TOKEN)
    # Deliberately malformed multipart body: auth must reject it before the
    # request parser is invoked, regardless of the submitted body contents.
    response = client.post(
        "/v1/analyze/flows",
        headers={"Content-Type": "multipart/form-data; boundary=broken"},
        content=b"not-a-valid-multipart-body",
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_production_rejects_weak_token(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PACKETWHISPERER_API_TOKEN", "short")
    assert client.get("/ready").status_code == 503
    response = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", b"data", "text/csv")},
    )
    assert response.status_code == 503


def test_configured_bearer_token_protects_analysis(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PACKETWHISPERER_API_TOKEN", VALID_TOKEN)
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    denied = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", csv, "text/csv")},
    )
    assert denied.status_code == 401
    allowed = client.post(
        "/v1/analyze/flows",
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
        files={"file": ("flows.csv", csv, "text/csv")},
    )
    assert allowed.status_code == 200


def test_dashboard_is_served(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("PACKETWHISPERER_API_TOKEN", raising=False)
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
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    csv = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    report = client.post(
        "/v1/analyze/flows",
        files={"file": ("flows.csv", csv, "text/csv")},
    )
    assert report.status_code == 200
    assert report.headers["cache-control"] == "no-store"


def test_rejects_declared_oversized_request_before_parsing():
    response = client.post(
        "/v1/analyze/flows",
        headers={"Content-Length": str(11 * 1024 * 1024)},
        content=b"x",
    )
    assert response.status_code == 413


def test_invalid_content_length_is_rejected():
    response = client.post(
        "/v1/analyze/flows",
        headers={"Content-Length": "not-a-number"},
        content=b"x",
    )
    assert response.status_code == 400


def test_streaming_upload_without_content_length_is_bounded():
    # An iterable body has no known length, so HTTPX sends it as a stream.
    # The middleware must enforce the cap before multipart parsing regardless
    # of whether Content-Length is supplied by the client.
    chunk = b"x" * (1024 * 1024)
    response = client.post(
        "/v1/analyze/flows",
        headers={"Content-Type": "multipart/form-data; boundary=streamed"},
        content=iter([chunk] * 11),
    )
    assert response.status_code == 413
