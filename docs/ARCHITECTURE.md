# Architecture

```text
Client / Analyst
      |
      | multipart CSV (10 MiB maximum)
      v
FastAPI transport layer
  - extension/content-type checks
  - bounded read
  - safe error responses
      |
      v
Flow validation and normalization
  - required schema
  - IP/port/counter validation
  - row-count bound
      |
      v
Deterministic heuristic engine
  - source destination fan-out
  - destination-port diversity
  - large-flow thresholds
      |
      v
JSON report
  - summary statistics
  - rule IDs, severity, evidence and caveats
  - SHA-256 fingerprint of uploaded bytes
```

## Design boundaries

The analysis core is pure Python and can be tested independently of the HTTP layer. Findings are deterministic for the same flow records and thresholds. No LLM is required for baseline detections. No uploaded dataset is deliberately persisted by the initial API.

## Known gaps before production deployment

Authentication and authorization, persistent case management, structured audit storage, rate limiting, privacy/retention controls, load testing, dependency vulnerability policy, and a labeled benchmark dataset remain necessary. Raw PCAP parsing and live capture are not part of this initial implementation.
