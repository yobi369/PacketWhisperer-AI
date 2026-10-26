# Deployment and Production Readiness

## Deployment stance

This service is suitable for controlled evaluation and internal pilots using authorized, non-sensitive test captures. It is **not approved by this project for unrestricted public exposure or critical security monitoring**. A green CI run proves only the checks in that workflow passed; it is not a penetration test or an operational acceptance certificate.

## No-cost deployment profile

The current deployment is intentionally kept on a no-cost setup. **Do not create paid resources or reuse the ShuleLedger database.** The application supports PostgreSQL and Redis when separately provisioned and configured, but those services are not active in the current deployment.

- **Storage:** With `DATABASE_URL` unset, the service uses its SQLite fallback. On an ephemeral hosting filesystem, the database file may be removed during redeploys, restarts, instance replacement, or platform maintenance. Accounts, cases, audit events, and stored rate-limit windows may therefore be lost. This is not durable production storage and must not be treated as a reliable audit archive.
- **Rate limiting:** With `REDIS_URL` unset, rate limits are process-local. They can reset on restart and do not coordinate across multiple service instances. This is not distributed rate limiting and is not sufficient as the only abuse-prevention control.
- **Backups and recovery:** No durable database or tested database backup/restore path is currently configured for this no-cost deployment. Do not store operationally critical case records or rely on the deployed audit history for compliance or incident response.
- **Detection quality:** Synthetic tests cover expected behavior in generated scenarios only. Real-world accuracy is unverified until representative, authorized, labeled benign/malicious traffic is evaluated.
- **Independent review:** The review handoff checklist is prepared, but no independent security review is claimed complete.

## Render configuration

1. Set `APP_ENV=production`.
2. Set `PACKETWHISPERER_API_TOKEN` and `PACKETWHISPERER_SESSION_SECRET` to separate randomly generated secrets of at least 32 bytes each. Set `PACKETWHISPERER_BOOTSTRAP_TOKEN` to a separate one-time secret of at least 32 bytes.
3. For this no-cost profile, leave `DATABASE_URL` and `REDIS_URL` unset unless suitable no-cost resources are separately available and deliberately configured. Do not point PacketWhisperer at the ShuleLedger database.
4. Restrict access at a trusted gateway, VPN, or identity-aware proxy. Use HTTPS and do not expose sensitive capture data during pilot deployment.
5. Create the first administrator exactly once using `POST /v1/auth/bootstrap` and the bootstrap token; remove `PACKETWHISPERER_BOOTSTRAP_TOKEN` from the service environment immediately afterward. Log in via `POST /v1/auth/login`; create analyst/viewer accounts through `POST /v1/admin/users`.
6. Verify that `/ready` returns 200 after secret configuration and 503 if the API token is absent or too short.

The container listens on the platform-provided `PORT` (default 8000 locally); Render health checks use `/ready`.

## Post-deploy acceptance checklist

Run from a trusted machine. Replace the host with the actual service hostname and keep the token in an environment variable.

- [ ] `GET /health` returns 200 and service/version metadata.
- [ ] `GET /ready` returns 200 only when production authentication is configured safely.
- [ ] Analysis upload without a bearer token returns 401.
- [ ] A valid token and synthetic CSV return a report with a SHA-256 evidence fingerprint.
- [ ] A valid token and synthetic PCAP/PCAPNG return bounded packet metadata and an evidence fingerprint.
- [ ] Wrong extensions, malformed files, and oversized requests are rejected.
- [ ] API responses include `Cache-Control: no-store`.
- [ ] No uploaded capture or token appears in application logs.
- [ ] TLS, gateway authentication/allowlisting, request timeouts, alerting, and service ownership are confirmed.
- [ ] Run `python benchmarks/evaluate_labeled_flows.py --input YOUR_LABELED.csv --dataset-name NAME --provenance "collection source, authorization, date range, and labeling method"` against authorized representative benign/malicious data; review precision, recall, false-positive rate, and dataset provenance.
- [ ] Before operational use, configure durable storage, verify backup/restore, confirm shared rate limiting, and rehearse recovery and incident response.

Example request:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $PACKETWHISPERER_API_TOKEN" \
  -F "file=@examples/sample_flows.csv;type=text/csv" \
  https://YOUR-SERVICE-HOST/v1/analyze/flows
```

## Operational limitations and upgrade gates

The code includes individual account login, admin/analyst/viewer role checks, case APIs, application audit events, login throttling, a PostgreSQL persistence backend, and a Redis-backed shared rate limiter. **Implemented code does not mean the corresponding infrastructure is configured or verified.**

Before describing the service as durable or suitable for operational security monitoring, all of the following are required:

1. Configure a dedicated persistent database and verify case/audit records survive redeployment; test backup restoration.
2. Configure `REDIS_URL` to a shared Redis-compatible service and test rate-limit behavior across separate instances.
3. Evaluate against authorized, representative labeled traffic and document dataset provenance and metrics without fabricating results.
4. Complete retention/deletion controls and recovery procedures.
5. Obtain an independent security review and track remediation of its findings.

Until those gates are complete, use a restricted pilot with synthetic or otherwise approved data. Do not rely on this service as the sole control for network defense.
