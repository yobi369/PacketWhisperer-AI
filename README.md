# PacketWhisperer AI

![CI](https://github.com/yobi369/PacketWhisperer-AI/actions/workflows/ci.yml/badge.svg)
![Security checks](https://github.com/yobi369/PacketWhisperer-AI/actions/workflows/security.yml/badge.svg)

**Explainable network-traffic analysis for security investigations.**

PacketWhisperer AI is an early-stage network security research platform focused on reproducible traffic analysis, evidence-backed findings, and transparent detection logic. It supports validated network-flow CSV and bounded offline PCAP/PCAPNG metadata analysis. It does not perform live capture or claim to be a certified IDS.

## Engineering principles

- **Evidence before claims:** findings identify the records and measurable signals that triggered them.
- **Deterministic baseline:** core heuristics operate without an external AI service.
- **Safe-by-default:** analyze only traffic you own or are authorized to inspect.
- **Reproducible:** fixtures and automated tests accompany detection logic.
- **Honest scope:** flow-CSV analysis is not equivalent to full PCAP parsing, endpoint detection, or a validated production IDS.

## Current foundation

The service provides a versioned FastAPI API, validated CSV flow ingestion, bounded offline PCAP/PCAPNG parsing, SHA-256 evidence fingerprints, explainable heuristic findings, and health/readiness endpoints. Packet payloads are not returned or deliberately persisted by the analysis endpoint.

### Expected CSV columns

`src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration`

Ports must be in the range 0–65535. Byte/packet counts and duration must be non-negative. The service rejects malformed records rather than silently fabricating values.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
uvicorn packetwhisperer.api:app --host 127.0.0.1 --port 8000
```

Open the analyst dashboard at `http://127.0.0.1:8000/` and interactive API documentation at `http://127.0.0.1:8000/docs`. The dashboard supports CSV and offline PCAP/PCAPNG uploads, findings review, and evidence-hash display; bearer tokens are held in page memory only.

For a production-mode run, configure a strong secret outside source control before starting the service:

```bash
export APP_ENV=production
export PACKETWHISPERER_API_TOKEN='use-a-long-random-secret-from-your-secret-manager'
uvicorn packetwhisperer.api:app --host 127.0.0.1 --port 8000
```

Analysis endpoints require `Authorization: Bearer <token>` when a token is configured. Requests are authenticated in middleware before multipart upload parsing, and production mode fails readiness and rejects analysis requests if the token is missing or too short. Do not commit secrets or expose the service directly to the public internet.

## Individual accounts, roles, cases and audit

The API includes individual accounts with PBKDF2-HMAC-SHA256 password hashes, one-hour signed bearer sessions, admin/analyst/viewer roles, login throttling, a fixed-window API rate limiter, case records, and an application audit-event table. The first administrator is created once through `POST /v1/auth/bootstrap` using `PACKETWHISPERER_BOOTSTRAP_TOKEN`; remove that bootstrap secret immediately after use. Log in at `POST /v1/auth/login`, then send the returned token as `Authorization: Bearer <access_token>`. Only administrators can create users (`POST /v1/admin/users`) and read audit events (`GET /v1/audit`); analysts and administrators can create/update cases, while viewers are read-only.

Set `PACKETWHISPERER_SESSION_SECRET` to a separate random secret of at least 32 bytes and `PACKETWHISPERER_API_TOKEN` to a separate service-compatibility token. The code supports PostgreSQL for accounts, cases, audit events, and rate-limit windows, and Redis for atomic shared rate limiting. **These are optional backends, not evidence that the deployed infrastructure is configured.**

### No-cost deployment: explicit limitations

This project is currently kept on a no-cost hosting setup; no paid database or other paid resource should be provisioned for this deployment.

- **Durability is not guaranteed.** If `DATABASE_URL` is unset, SQLite is used. On an ephemeral host filesystem, its file may be lost on restart, redeploy, or instance replacement. Accounts, cases, audit events, and local rate-limit windows may disappear. There is no verified durable backup/restore path in the current no-cost profile. Do not treat deployed case/audit history as a reliable archive.
- **Rate limits are not distributed.** If `REDIS_URL` is unset, rate limiting is process-local; counters can reset and separate instances do not share them. Keep gateway/proxy-level controls enabled and do not rely on application-local limits as the only abuse defense.
- Do not reuse the ShuleLedger database. If suitable persistent/shared services become available later, configure a dedicated database via `DATABASE_URL` and Redis-compatible service via `REDIS_URL`, then test persistence across redeploys, backup restoration, and cross-instance throttling before claiming these properties are operational.

## Run tests and synthetic benchmark

```bash
pytest -q
python benchmarks/evaluate_synthetic.py
```

The synthetic benchmark reports per-rule metrics for generated sanity scenarios only. It is not a real-world detection-quality estimate.

## API

- `GET /health` — liveness.
- `GET /ready` — readiness.
- `POST /v1/analyze/flows` — multipart CSV upload; returns a SHA-256 fingerprint, summary, and explainable findings.
- `POST /v1/analyze/pcap` — multipart `.pcap`, `.pcapng`, or `.cap` upload; analyzes packet metadata with 20 MiB and 100,000-packet limits.

## Detection behavior and validation status

The baseline engine uses transparent heuristics such as destination-port fan-out, repeated destination-port concentration, and unusually large flow byte counts. These are investigation leads, not proof of compromise. Thresholds should be calibrated against representative benign and malicious datasets.

**Real-world detection accuracy has not been established.** Run `benchmarks/evaluate_labeled_flows.py` with an authorized, representative labeled dataset and record the dataset source, collection/authorization basis, labeling method, limitations, and actual measured metrics. Do not invent benchmark results or present synthetic test scores as field accuracy.

## Security and production status

This is a research foundation, not a certified or independently validated production intrusion-detection system. Offline packet metadata parsing is implemented; deep protocol dissection, live packet capture, and validated production detection are not claimed. An external security-review checklist is available in `docs/EXTERNAL_SECURITY_REVIEW.md`, but an independent review is **not** claimed complete. Before operational use, verify durable storage, backups/restores, distributed rate limiting, retention controls, and independent security review.

See [`docs/RESEARCH_BRIEF.md`](docs/RESEARCH_BRIEF.md), [`docs/DEMO.md`](docs/DEMO.md), and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Responsible use

Use only on networks and traffic you own or are explicitly authorized to analyze. Follow applicable privacy, data-protection, and organizational policies.
