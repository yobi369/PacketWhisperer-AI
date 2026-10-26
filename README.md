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

### Individual accounts, roles, cases and audit

The API now includes individual accounts with PBKDF2-HMAC-SHA256 password hashes, one-hour signed bearer sessions, admin/analyst/viewer roles, login throttling, a fixed-window API rate limiter, case records, and an append-only application audit-event table. The first administrator is created once through `POST /v1/auth/bootstrap` using `PACKETWHISPERER_BOOTSTRAP_TOKEN`; remove that bootstrap secret immediately after use. Log in at `POST /v1/auth/login`, then send the returned token as `Authorization: Bearer <access_token>`. Only administrators can create users (`POST /v1/admin/users`) and read audit events (`GET /v1/audit`); analysts and administrators can create/update cases, while viewers are read-only.

Set `PACKETWHISPERER_SESSION_SECRET` to a separate random secret of at least 32 bytes and `PACKETWHISPERER_API_TOKEN` to a separate service-compatibility token. For durable production storage, set `DATABASE_URL` to the private connection URL of a dedicated managed PostgreSQL database. The code now supports PostgreSQL for accounts, cases, audit events, and rate-limit windows; SQLite remains a development fallback and the default temporary path is ephemeral. Use a non-expiring database plan with access restrictions and tested backups/restores. Do not reuse the ShuleLedger database. Set `REDIS_URL` to the private connection URL of the dedicated Render Key Value resource to activate atomic distributed rate limiting across instances; without it, rate limiting falls back to database-local counters. Configure HTTPS and trusted proxy behavior at the deployment edge. Never log passwords, session tokens, packet payloads, or secrets.

Run tests:

```bash
pytest -q
```

Run the deterministic synthetic rule benchmark:

```bash
python benchmarks/evaluate_synthetic.py
```

The benchmark reports per-rule precision/recall on three generated sanity scenarios. These scores validate only expected rule behavior; they are not real-world detection-quality estimates.

## API

- `GET /health` — liveness.
- `GET /ready` — readiness.
- `POST /v1/analyze/flows` — multipart CSV upload; returns a SHA-256 fingerprint, summary, and explainable findings.
- `POST /v1/analyze/pcap` — multipart `.pcap`, `.pcapng`, or `.cap` upload; analyzes packet metadata with 20 MiB and 100,000-packet limits.

## Detection behavior

The baseline engine uses transparent heuristics such as destination-port fan-out, repeated destination-port concentration, and unusually large flow byte counts. These are investigation leads, not proof of compromise. Thresholds are configurable in code and should be calibrated against representative benign and malicious datasets before operational use.

## Security and production status

Do not expose this service directly to the public internet or upload sensitive captures until authentication, authorization, deployment hardening, retention policy, and organizational privacy requirements have been reviewed. The service is a research foundation, not a certified or independently validated production intrusion-detection system. Offline packet metadata parsing is implemented; deep protocol dissection, live packet capture, persistent case management, and external LLM integrations are not claimed as implemented.

## Technical brief

See [`docs/RESEARCH_BRIEF.md`](docs/RESEARCH_BRIEF.md) for the research question, evaluation methodology, security boundaries, and an honest summary of limitations. For a live walkthrough, use [`docs/DEMO.md`](docs/DEMO.md) and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Roadmap

1. Hardened, tested flow and offline PCAP/PCAPNG analysis APIs.
2. Detection rule registry, confidence calibration, and ATT&CK mapping where justified.
3. Case management, role-based access, audit persistence, and retention controls.
4. Benchmark suite with labeled datasets, false-positive metrics, and performance baselines.
5. Optional AI-assisted summaries with citations to concrete evidence and strict data controls.

## Responsible use

Use only on networks and traffic you own or are explicitly authorized to analyze. Follow applicable privacy, data-protection, and organizational policies.
