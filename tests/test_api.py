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
