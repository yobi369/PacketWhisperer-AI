import pytest
from scapy.all import Ether, IP, TCP, wrpcap
from scapy.utils import PcapNgWriter
from fastapi.testclient import TestClient

from packetwhisperer.api import app
from packetwhisperer.pcap_analyzer import CaptureValidationError, analyze_pcap

client = TestClient(app)


def make_capture(path, packets):
    wrpcap(str(path), packets)
    return path.read_bytes()


def test_pcap_analyzer_detects_syn_port_diversity(tmp_path):
    packets = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") /
        TCP(sport=45000 + port, dport=port, flags="S")
        for port in range(20, 31)
    ]
    raw = make_capture(tmp_path / "scan.pcap", packets)
    report = analyze_pcap(raw)
    assert report["capture"]["packets_analyzed"] == 11
    finding = next(x for x in report["findings"] if x["rule_id"] == "PCAP-TCP-SYN-PORT-DIVERSITY")
    assert finding["observed_unique_destination_ports"] == 11
    assert "not proof" in " ".join(report["limitations"])


def test_pcap_rejects_invalid_bytes():
    with pytest.raises(CaptureValidationError, match="Invalid or unsupported"):
        analyze_pcap(b"not a pcap file")


def test_pcap_rejects_empty_input():
    with pytest.raises(CaptureValidationError, match="empty"):
        analyze_pcap(b"")


def test_api_accepts_pcap_and_returns_evidence_hash(tmp_path):
    raw = make_capture(
        tmp_path / "normal.pcap",
        [Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=51515, dport=443, flags="PA")],
    )
    response = client.post(
        "/v1/analyze/pcap",
        files={"file": ("normal.pcap", raw, "application/octet-stream")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["capture"]["packets_analyzed"] == 1
    assert len(body["evidence"]["sha256"]) == 64


def test_pcap_endpoint_rejects_wrong_extension():
    response = client.post(
        "/v1/analyze/pcap",
        files={"file": ("capture.txt", b"anything", "application/octet-stream")},
    )
    assert response.status_code == 415


def test_pcapng_capture_is_supported(tmp_path):
    path = tmp_path / "sample.pcapng"
    writer = PcapNgWriter(str(path))
    writer.write(Ether() / IP(src="192.0.2.3", dst="198.51.100.7") / TCP(sport=50000, dport=443, flags="PA"))
    writer.close()
    report = analyze_pcap(path.read_bytes())
    assert report["capture"]["packets_analyzed"] == 1
    assert report["capture"]["format"] == "pcap-or-pcapng"
