# Deployment and Production Readiness

## Deployment stance

This service is suitable for controlled evaluation and internal pilots using authorized, non-sensitive test captures. It is **not approved by this project for unrestricted public exposure or critical security monitoring**. A green CI run proves only the checks in that workflow passed; it is not a penetration test or an operational acceptance certificate.

## Render Blueprint

1. Create a Blueprint from this repository.
2. Set `APP_ENV=production`, `PACKETWHISPERER_API_TOKEN` and `PACKETWHISPERER_SESSION_SECRET` to separate randomly generated secrets of at least 32 bytes each. Set `PACKETWHISPERER_BOOTSTRAP_TOKEN` to a separate one-time secret of at least 32 bytes.
3. Set `PACKETWHISPERER_DB_PATH` to a persistent mounted path. The default Render Free filesystem is ephemeral: account, case, and audit data can be lost on restart/redeploy unless persistent storage or a managed database is configured.
4. Configure `REDIS_URL` with the private connection URL of a shared Redis/Render Key Value instance to enable atomic distributed rate limiting. Without it, rate limits use the local SQLite store and do not coordinate across instances.
5. Restrict access at a trusted gateway, VPN, or identity-aware proxy. Use HTTPS and do not expose sensitive capture data during pilot deployment.
6. Create the first administrator exactly once using `POST /v1/auth/bootstrap` and the bootstrap token; remove `PACKETWHISPERER_BOOTSTRAP_TOKEN` from the service environment immediately afterward. Log in via `POST /v1/auth/login`; create analyst/viewer accounts through `POST /v1/admin/users`.
7. Verify that `/ready` returns 200 after secret configuration and 503 if the API token is absent or too short.

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
- [ ] TLS, gateway authentication/allowlisting, rate limiting, request timeouts, alerting, and service ownership are confirmed.
- [ ] Run `python benchmarks/evaluate_labeled_flows.py --input YOUR_LABELED.csv --dataset-name NAME --provenance "collection source, authorization, date range, and labeling method"` against authorized representative benign/malicious data; review precision, recall, false-positive rate, and dataset provenance.
- [ ] Recovery and incident-response procedures are documented and rehearsed if the deployment stores any operational state.

Example request:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $PACKETWHISPERER_API_TOKEN" \
  -F "file=@examples/sample_flows.csv;type=text/csv" \
  https://YOUR-SERVICE-HOST/v1/analyze/flows
```

## Operational limitations

Individual account login, admin/analyst/viewer role checks, case APIs, application audit events, login throttling, and an optional Redis-backed shared rate limiter are implemented. Durable case/audit retention still depends on configuring persistent database storage; Redis must be configured through `REDIS_URL` for cross-instance rate limiting. The project still does not provide live packet capture or a validated production IDS. Use gateway-level controls and a restricted pilot until persistent storage, backup/restore, labeled-dataset evaluation, retention controls, and independent security review are complete. Do not rely on this service as the sole control for network defense.
