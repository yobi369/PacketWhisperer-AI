import pytest
from packetwhisperer.analyzer import FlowValidationError, analyze_flows, parse_flows

HEADER = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n"

def row(src="10.0.0.1", dst="10.0.0.2", sp=50000, dp=443, proto="TCP", size=120, packets=2, duration=1.5):
    return f"{src},{dst},{sp},{dp},{proto},{size},{packets},{duration}\n".encode()

def test_parses_valid_flow_and_normalizes_protocol():
    flows = parse_flows(HEADER + row(proto="tcp"))
    assert len(flows) == 1
    assert flows[0].protocol == "TCP"

def test_rejects_missing_columns():
    with pytest.raises(FlowValidationError, match="Missing required columns"):
        parse_flows(b"src_ip,dst_ip\n10.0.0.1,10.0.0.2\n")

def test_rejects_invalid_ip_and_negative_bytes():
    with pytest.raises(FlowValidationError, match="Invalid flow at CSV line 2"):
        parse_flows(HEADER + row(src="not-an-ip"))
    with pytest.raises(FlowValidationError, match="negative counters"):
        parse_flows(HEADER + row(size=-1))

def test_detects_high_fanout_with_evidence():
    raw = HEADER + b"".join(row(dst=f"10.0.1.{i}") for i in range(1, 22))
    result = analyze_flows(parse_flows(raw), fanout_threshold=20)
    finding = next(f for f in result["findings"] if f["rule_id"] == "FLOW-HIGH-FANOUT")
    assert finding["observed"] == 21
    assert "distinct destination IPs" in finding["evidence"]

def test_large_flow_detection_is_deterministic():
    result = analyze_flows(parse_flows(HEADER + row(size=50_000_000)))
    assert any(f["rule_id"] == "FLOW-LARGE-TRANSFER" for f in result["findings"])

def test_rejects_empty_input():
    with pytest.raises(FlowValidationError, match="empty"):
        parse_flows(b"")
