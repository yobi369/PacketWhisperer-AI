import pytest
from fastapi.testclient import TestClient

from packetwhisperer import security_store as store
from packetwhisperer.api import app

client = TestClient(app)


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "packetwhisperer-test.sqlite3"))
    store.init_store()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PACKETWHISPERER_API_TOKEN", "service-compatibility-token-32-bytes")
    monkeypatch.setenv("PACKETWHISPERER_SESSION_SECRET", "session-signing-secret-that-is-very-long-32")
    monkeypatch.setenv("PACKETWHISPERER_BOOTSTRAP_TOKEN", "one-time-bootstrap-secret-is-32-bytes")
    yield


def _login(username, password):
    response = client.post("/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_bootstrap_is_one_time_and_login_issues_signed_session(isolated_store):
    payload = {
        "username": "admin",
        "password": "correct horse battery staple 2026",
        "bootstrap_token": "one-time-bootstrap-secret-is-32-bytes",
    }
    first = client.post("/v1/auth/bootstrap", json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["user"]["role"] == "admin"
    second = client.post("/v1/auth/bootstrap", json=payload)
    assert second.status_code == 409
    token = _login("admin", payload["password"])
    assert len(token.split(".")) == 2


def test_role_boundaries_case_storage_and_audit(isolated_store):
    bootstrap = client.post("/v1/auth/bootstrap", json={
        "username": "rootadmin", "password": "secure-admin-password-2026",
        "bootstrap_token": "one-time-bootstrap-secret-is-32-bytes",
    })
    assert bootstrap.status_code == 200, bootstrap.text
    admin_token = _login("rootadmin", "secure-admin-password-2026")
    admin = {"Authorization": f"Bearer {admin_token}"}

    created = client.post("/v1/admin/users", headers=admin, json={
        "username": "readonly", "password": "secure-viewer-password-2026", "role": "viewer"
    })
    assert created.status_code == 200, created.text
    viewer_token = _login("readonly", "secure-viewer-password-2026")
    viewer = {"Authorization": f"Bearer {viewer_token}"}
    csv_body = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n10.0.0.1,10.0.0.2,50000,443,TCP,100,2,1.0\n"
    denied_analysis = client.post("/v1/analyze/flows", headers=viewer, files={"file": ("flows.csv", csv_body, "text/csv")})
    assert denied_analysis.status_code == 403
    assert client.post("/v1/cases", headers=viewer, json={"title": "Investigate scan"}).status_code == 403
    assert client.get("/v1/cases", headers=viewer).status_code == 200

    analyst = client.post("/v1/admin/users", headers=admin, json={
        "username": "analyst1", "password": "secure-analyst-password-2026", "role": "analyst"
    })
    assert analyst.status_code == 200, analyst.text
    analyst_token = _login("analyst1", "secure-analyst-password-2026")
    case = client.post("/v1/cases", headers={"Authorization": f"Bearer {analyst_token}"}, json={
        "title": "Suspicious outbound fan-out", "severity": "high",
        "summary": {"finding_count": 2}, "evidence_sha256": "a" * 64,
    })
    assert case.status_code == 200, case.text
    case_id = case.json()["case"]["id"]
    assert client.patch(f"/v1/cases/{case_id}", headers=viewer, json={"status": "closed"}).status_code == 403
    assert client.get("/v1/audit", headers=viewer).status_code == 403
    audit = client.get("/v1/audit", headers=admin)
    assert audit.status_code == 200, audit.text
    assert any(item["action"] == "case.create" for item in audit.json()["items"])


def test_rate_limit_counter_is_atomic_and_fixed_window(isolated_store):
    assert store.allow_request("test-bucket", 2, 60, now=120)
    assert store.allow_request("test-bucket", 2, 60, now=121)
    assert not store.allow_request("test-bucket", 2, 60, now=122)
    assert store.allow_request("test-bucket", 2, 60, now=180)
