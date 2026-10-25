# Demo Walkthrough

This demo uses only synthetic RFC1918 IP addresses and fabricated flow counters. It does not represent a real network incident.

## 1. Start the service locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
uvicorn packetwhisperer.api:app --host 127.0.0.1 --port 8000
```

Open the analyst dashboard at `http://127.0.0.1:8000/`. The API explorer is available at `http://127.0.0.1:8000/docs`.

## 2. Submit the sample

Use `POST /v1/analyze/flows` and upload `examples/sample_flows.csv`. The response includes flow totals, findings, and a SHA-256 evidence fingerprint.

For packet-level metadata, upload a `.pcap` or `.pcapng` file to `POST /v1/analyze/pcap`. For a safe synthetic demonstration, create a small capture with Scapy:

```python
from scapy.all import Ether, IP, TCP, wrpcap
packets = [Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=45000+p, dport=p, flags="S") for p in range(20, 31)]
wrpcap("synthetic-syn-pattern.pcap", packets)
```

Upload `synthetic-syn-pattern.pcap` to the PCAP endpoint. It should produce a medium-severity SYN port-diversity investigation lead.

## 3. Explain the results

- High destination fan-out is a heuristic signal, not proof of malicious scanning.
- The large-flow rule flags a record whose byte count reaches the configured threshold.
- The fingerprint identifies the exact uploaded bytes and can be recomputed independently.
- Findings explicitly include the measured evidence and interpretive caveats.

## 4. Show engineering discipline

Run `pytest -q` and open the GitHub Actions workflow. The CI matrix tests Python 3.11 and 3.12. Discuss the threat model and known gaps rather than claiming that unimplemented controls already exist.

## Presentation caveat

This is an API and analysis-core demonstration. Offline PCAP/PCAPNG metadata ingestion is implemented with file and packet-count limits. A polished interactive analyst dashboard, live capture, authentication, case storage, and calibrated ML detection remain separate roadmap items.
