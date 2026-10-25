# Architecture

```text
Client / Analyst
      |
      +-- multipart CSV (10 MiB maximum) ---> FastAPI ---> strict flow validation
      |                                                     |
      |                                                     v
      |                                            deterministic flow rules
      |
      +-- offline PCAP/PCAPNG (20 MiB max) ---> bounded reader (100k packets)
                                                        |
                                                        v
                                              packet metadata + SYN heuristics
                                                        |
                                                        v
JSON report: summary, rule evidence, limitations, SHA-256 fingerprint
```

## Design boundaries

The analysis core is pure Python and can be tested independently of the HTTP layer. Findings are deterministic for the same flow records and thresholds. No LLM is required for baseline detections. No uploaded dataset is deliberately persisted by the initial API.

## Known gaps before production deployment

Authentication and authorization, persistent case management, structured audit storage, rate limiting, privacy/retention controls, load testing, dependency vulnerability policy, and a labeled benchmark dataset remain necessary. Offline PCAP/PCAPNG metadata parsing is implemented with bounded file and packet counts. Live capture, full application-layer dissection, authentication, rate limiting, and durable audit storage remain out of scope.
