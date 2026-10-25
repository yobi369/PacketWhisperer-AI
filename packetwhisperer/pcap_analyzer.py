"""Bounded offline packet-capture analysis; payload bytes are never returned."""
from __future__ import annotations

import io
from collections import Counter, defaultdict
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, DNS, PcapReader
from scapy.error import Scapy_Exception

MAX_CAPTURE_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 100_000
PORT_SCAN_THRESHOLD = 10
FANOUT_THRESHOLD = 20


class CaptureValidationError(ValueError):
    """Raised for invalid or resource-excessive packet captures."""


def analyze_pcap(raw: bytes) -> dict[str, Any]:
    """Analyze packet metadata from PCAP/PCAPNG without retaining payloads."""
    if not raw:
        raise CaptureValidationError("Capture is empty")
    if len(raw) > MAX_CAPTURE_BYTES:
        raise CaptureValidationError("Capture exceeds the 20 MiB upload limit")

    packet_count = 0
    ipv4_count = 0
    ipv6_count = 0
    protocol_counts: Counter[str] = Counter()
    bytes_total = 0
    source_ports: dict[str, set[int]] = defaultdict(set)
    source_destinations: dict[str, set[str]] = defaultdict(set)
    syn_targets: dict[str, set[tuple[str, int]]] = defaultdict(set)
    flow_counts: Counter[tuple[str, str, str, int, int]] = Counter()

    try:
        reader = PcapReader(io.BytesIO(raw))
        try:
            for packet in reader:
                if packet_count >= MAX_PACKETS:
                    raise CaptureValidationError(f"Capture exceeds the {MAX_PACKETS} packet limit")
                packet_count += 1
                bytes_total += len(packet)
                if IP in packet:
                    ip = packet[IP]
                    src, dst = ip.src, ip.dst
                    ipv4_count += 1
                    transport = "IP"
                elif IPv6 in packet:
                    ip = packet[IPv6]
                    src, dst = ip.src, ip.dst
                    ipv6_count += 1
                    transport = "IPv6"
                else:
                    protocol_counts["NON_IP"] += 1
                    continue

                sport = dport = 0
                if TCP in packet:
                    tcp = packet[TCP]
                    sport, dport = int(tcp.sport), int(tcp.dport)
                    transport = "TCP"
                    source_ports[src].add(dport)
                    source_destinations[src].add(dst)
                    if (int(tcp.flags) & 0x02) and not (int(tcp.flags) & 0x10):
                        syn_targets[src].add((dst, dport))
                elif UDP in packet:
                    udp = packet[UDP]
                    sport, dport = int(udp.sport), int(udp.dport)
                    transport = "UDP"
                    source_ports[src].add(dport)
                    source_destinations[src].add(dst)
                protocol_counts[transport] += 1
                flow_counts[(src, dst, transport, sport, dport)] += 1
        finally:
            reader.close()
    except CaptureValidationError:
        raise
    except (Scapy_Exception, ValueError, TypeError, OSError, EOFError) as exc:
        raise CaptureValidationError("Invalid or unsupported PCAP/PCAPNG capture") from exc

    if packet_count == 0:
        raise CaptureValidationError("Capture contains no readable packets")

    findings: list[dict[str, Any]] = []
    for src, targets in sorted(syn_targets.items()):
        unique_ports = {port for _, port in targets}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "rule_id": "PCAP-TCP-SYN-PORT-DIVERSITY",
                "severity": "medium",
                "title": "Possible TCP SYN port scan",
                "source_ip": src,
                "observed_unique_destination_ports": len(unique_ports),
                "threshold": PORT_SCAN_THRESHOLD,
                "evidence": f"Capture contains SYN packets without ACK from {src} to {len(unique_ports)} distinct destination ports.",
                "interpretation": "This is a scan-like pattern, not proof of malicious activity; verify capture scope and expected scanner behavior.",
            })

    for src, destinations in sorted(source_destinations.items()):
        if len(destinations) >= FANOUT_THRESHOLD:
            findings.append({
                "rule_id": "PCAP-IP-DESTINATION-FANOUT",
                "severity": "low",
                "title": "High destination fan-out",
                "source_ip": src,
                "observed_unique_destinations": len(destinations),
                "threshold": FANOUT_THRESHOLD,
                "evidence": f"Source {src} contacted {len(destinations)} distinct destination IPs in this capture.",
                "interpretation": "May indicate discovery, scanning, monitoring, or ordinary client activity.",
            })

    return {
        "capture": {"format": "pcap-or-pcapng", "bytes_received": len(raw), "packets_analyzed": packet_count},
        "summary": {
            "ipv4_packets": ipv4_count,
            "ipv6_packets": ipv6_count,
            "non_ip_packets": protocol_counts["NON_IP"],
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "captured_packet_bytes": bytes_total,
            "unique_observed_flows": len(flow_counts),
        },
        "findings_count": len(findings),
        "findings": findings,
        "limitations": [
            "This endpoint analyzes packet metadata; it does not return or persist packet payloads.",
            "Only captured packets are analyzed; missing capture traffic can hide activity.",
            "Encrypted application content is not decrypted or interpreted.",
            "Heuristic findings are investigation leads, not proof of compromise.",
        ],
    }
