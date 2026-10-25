# Initial Threat Model

## Scope

This service accepts user-supplied network-flow CSV and returns heuristic findings. It does not execute uploaded content, capture live traffic, or parse raw PCAP files in this initial version.

## Assets

- Integrity of uploaded evidence and its SHA-256 fingerprint.
- Availability of the analysis service.
- Confidentiality of uploaded network metadata.
- Correctness and explainability of findings.

## Threats and mitigations

| Threat | Initial mitigation | Remaining work |
|---|---|---|
| Oversized upload / resource exhaustion | 10 MiB byte limit and 100,000 row limit | Reverse-proxy limits, concurrency budgets, load testing |
| Malformed CSV / invalid values | Strict UTF-8, required columns, IP and numeric validation | Fuzzing and property-based tests |
| Filename path tricks | Filename reduced to basename; never used as a filesystem path | Add upload storage only with random IDs and isolated storage |
| False positives / overclaiming | Findings include rule IDs, thresholds, evidence, and limitations | Labeled evaluation dataset, precision/recall calibration |
| Sensitive traffic metadata | No intentional persistence of uploaded file | Authentication, retention policy, deployment privacy review |
| Unauthorized API access | Optional shared bearer token; production mode fails closed if missing | Managed identity, per-user authorization, TLS, rate limits, network controls |
| Tampered evidence | SHA-256 fingerprint returned for uploaded bytes | Signed manifests, immutable audit storage, access logging |

## Trust boundaries

Uploaded bytes are untrusted. The optional bearer token is a shared-secret gate, not user identity or role-based authorization. Do not expose the service to untrusted networks until managed identity, authorization, rate limiting, and deployment controls are implemented and tested.

## Operational guidance

Run only on traffic you are authorized to inspect. Avoid uploading personal or sensitive traffic to third-party environments without approval. Heuristic alerts are investigation leads, not attribution or proof of compromise.
