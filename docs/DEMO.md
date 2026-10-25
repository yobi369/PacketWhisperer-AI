# Demo Walkthrough

This demo uses only synthetic RFC1918 IP addresses and fabricated flow counters. It does not represent a real network incident.

## 1. Start the service locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
uvicorn packetwhisperer.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`.

## 2. Submit the sample

Use the `POST /v1/analyze/flows` endpoint and upload `examples/sample_flows.csv`. The JSON response should include a flow count, aggregate counters, findings, and an evidence object with a SHA-256 fingerprint.

## 3. Explain the results

- High destination fan-out is a heuristic signal, not proof of malicious scanning.
- The large-flow rule flags a record whose byte count reaches the configured threshold.
- The fingerprint identifies the exact uploaded bytes and can be recomputed independently.
- Findings explicitly include the measured evidence and interpretive caveats.

## 4. Show engineering discipline

Run `pytest -q` and open the GitHub Actions workflow. The CI matrix tests Python 3.11 and 3.12. Discuss the threat model and known gaps rather than claiming that unimplemented controls already exist.

## Presentation caveat

This is an API and analysis-core demonstration. A polished interactive analyst dashboard, raw PCAP ingestion, live capture, authentication, case storage, and calibrated ML detection are separate roadmap items.
