"""Deterministic, explainable network-flow heuristics."""
from __future__ import annotations

import csv
import io
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any

REQUIRED_COLUMNS = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "packets", "duration")
MAX_ROWS = 100_000


class FlowValidationError(ValueError):
    """Raised when uploaded flow data is malformed or exceeds limits."""


@dataclass(frozen=True)
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes: int
    packets: int
    duration: float

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_flows(raw: bytes) -> list[Flow]:
    """Parse a UTF-8 CSV document, validating each field without guessing."""
    if not raw:
        raise FlowValidationError("CSV upload is empty")
    if len(raw) > 10 * 1024 * 1024:
        raise FlowValidationError("CSV exceeds the 10 MiB upload limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FlowValidationError("CSV must be UTF-8 encoded") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise FlowValidationError("CSV header is missing")
    missing = sorted(set(REQUIRED_COLUMNS) - set(reader.fieldnames))
    if missing:
        raise FlowValidationError("Missing required columns: " + ", ".join(missing))
    flows: list[Flow] = []
    for line, row in enumerate(reader, start=2):
        if line > MAX_ROWS + 1:
            raise FlowValidationError(f"CSV exceeds the {MAX_ROWS} row limit")
        try:
            src = str(ipaddress.ip_address((row.get("src_ip") or "").strip()))
            dst = str(ipaddress.ip_address((row.get("dst_ip") or "").strip()))
            src_port = int(row["src_port"])
            dst_port = int(row["dst_port"])
            byte_count = int(row["bytes"])
            packet_count = int(row["packets"])
            duration = float(row["duration"])
            protocol = (row["protocol"] or "").strip().upper()
            if not protocol or len(protocol) > 16 or not protocol.replace("-", "").isalnum():
                raise ValueError("invalid protocol")
            if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                raise ValueError("port outside 0..65535")
            if byte_count < 0 or packet_count < 0 or duration < 0:
                raise ValueError("negative counters or duration")
        except (ValueError, TypeError, KeyError) as exc:
            raise FlowValidationError(f"Invalid flow at CSV line {line}: {exc}") from exc
        flows.append(Flow(src, dst, src_port, dst_port, protocol, byte_count, packet_count, duration))
    if not flows:
        raise FlowValidationError("CSV contains no flow records")
    return flows


def analyze_flows(flows: list[Flow], *, fanout_threshold: int = 20, large_flow_bytes: int = 50_000_000) -> dict[str, Any]:
    """Return summary and heuristic alerts with concrete, reproducible evidence."""
    if fanout_threshold < 2 or large_flow_bytes < 1:
        raise ValueError("thresholds must be positive (fanout_threshold >= 2)")
    destinations: dict[str, set[str]] = defaultdict(set)
    source_dest_ports: dict[str, set[int]] = defaultdict(set)
    for f in flows:
        destinations[f.src_ip].add(f.dst_ip)
        source_dest_ports[f.src_ip].add(f.dst_port)
    findings: list[dict[str, Any]] = []
    for src, dests in sorted(destinations.items()):
        if len(dests) >= fanout_threshold:
            findings.append({"rule_id": "FLOW-HIGH-FANOUT", "severity": "medium", "title": "High destination fan-out", "source_ip": src, "observed": len(dests), "threshold": fanout_threshold, "evidence": f"Source contacted {len(dests)} distinct destination IPs in this dataset.", "interpretation": "May reflect scanning, discovery, monitoring, or normal high-volume client behavior; investigate context."})
        ports = source_dest_ports[src]
        if len(ports) >= fanout_threshold:
            findings.append({"rule_id": "FLOW-PORT-DIVERSITY", "severity": "low", "title": "High destination-port diversity", "source_ip": src, "observed": len(ports), "threshold": fanout_threshold, "evidence": f"Source contacted {len(ports)} distinct destination ports in this dataset.", "interpretation": "Could indicate service discovery or normal multi-service use; flow data alone does not prove a scan."})
    for idx, f in enumerate(flows, start=1):
        if f.bytes >= large_flow_bytes:
            findings.append({"rule_id": "FLOW-LARGE-TRANSFER", "severity": "low", "title": "Large single-flow transfer", "flow_index": idx, "source_ip": f.src_ip, "destination_ip": f.dst_ip, "observed_bytes": f.bytes, "threshold_bytes": large_flow_bytes, "evidence": f"Flow record {idx} reports {f.bytes} bytes over {f.duration:g} seconds.", "interpretation": "Large transfers may be expected; validate destination, application, authorization, and baseline before escalation."})
    return {"flow_count": len(flows), "unique_sources": len({f.src_ip for f in flows}), "unique_destinations": len({f.dst_ip for f in flows}), "total_bytes": sum(f.bytes for f in flows), "total_packets": sum(f.packets for f in flows), "findings_count": len(findings), "findings": findings, "limitations": ["Heuristic alerts are leads, not proof of compromise.", "Results depend on the uploaded dataset and the selected thresholds.", "Encrypted payloads and packet-level details are not available from flow CSV records."]}
