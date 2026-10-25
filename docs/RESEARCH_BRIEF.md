# PacketWhisperer AI — Technical Research Brief

## Problem statement

Network investigations often combine raw packet observations, aggregate flow records, rule-based alerts, and analyst interpretation. PacketWhisperer explores a practical design principle: every automated finding should be reproducible, tied to observable evidence, and explicit about uncertainty.

## Research question

Can a small, deterministic network-analysis service produce interpretable investigation leads from flow CSV and offline packet captures while preserving evidence integrity and placing clear limits on what the output establishes?

This repository is a prototype for that question, not a claim that the problem has been solved at production scale.

## System design

- **Input boundary:** bounded CSV and PCAP/PCAPNG uploads; no live capture.
- **Validation:** explicit schemas, IP and port validation, numeric bounds, file-size and packet-count limits.
- **Analysis:** deterministic flow heuristics and packet-metadata rules.
- **Evidence:** SHA-256 fingerprint of the exact uploaded bytes.
- **Output:** aggregate counts, rule IDs, measured observations, interpretive caveats, and limitations.
- **Interface:** browser dashboard that displays reports without storing capture history or writing bearer tokens to browser storage.
- **Operational controls:** production-mode shared bearer-token gate, fail-closed readiness when missing, security response headers, container health check, CI, dependency audit, and static security scan.

## Detection examples

- High flow destination fan-out can suggest scanning or discovery.
- High diversity of TCP SYN destination ports can indicate a scan-like pattern.
- A large single-flow byte count can merit review against expected transfer baselines.

These patterns are not unique to malicious behavior. Monitoring, asset discovery, service checks, software distribution, backups, and normal client behavior can produce similar signals.

## Evaluation methodology

The included synthetic benchmark generates three deterministic cases: a low-fan-out client, a destination sweep, and a large transfer. It checks whether configured rules match expected synthetic labels and reports simple rule-level precision/recall metrics over those cases.

This benchmark is a regression sanity check only. Its small, deliberately constructed scenarios do not estimate real-world precision, recall, false-positive rate, detection coverage, or generalization.

A defensible research evaluation should add:
1. Public and properly licensed labeled traffic datasets.
2. Train/validation/test separation where learning is introduced.
3. Per-rule confusion matrices and precision/recall with confidence intervals.
4. False positives per hour or per host on benign enterprise traffic.
5. Throughput, memory, and latency measurements across capture sizes.
6. Ablations comparing flow-only and packet-metadata signals.
7. Reproducible dataset versions, scripts, and environment metadata.

## Security boundaries

The API's shared bearer token is a baseline deployment gate, not identity management or role-based authorization. Before handling real customer traffic, add managed identity, per-user permissions, durable audit records, retention/deletion controls, gateway rate limiting, secret rotation, operational monitoring, and a documented incident response process.

Packet payloads are not returned by the PCAP analysis endpoint. That does not mean the input file is free of sensitive information; capture handling still requires authorization and appropriate privacy controls.

## Current limitations

- No live packet capture or network sensor.
- No decryption of encrypted application traffic.
- No full application-layer protocol investigation workflow.
- No persistent case management or multi-user identity model.
- Heuristic thresholds are not calibrated against a representative production dataset.
- No independent security review, penetration test, or production load test has been completed.

## Suggested presentation thesis

**PacketWhisperer AI is an evidence-first, explainable network-analysis prototype whose engineering value is in reproducibility, bounded ingestion, explicit uncertainty, and testable security boundaries—not in claiming that a few heuristics can replace a mature network detection and response platform.**
