# Deployment and Production Readiness

## Deployment stance

This service is suitable for controlled evaluation and internal pilots using authorized, non-sensitive test captures. It is **not approved by this project for unrestricted public exposure or critical security monitoring**. A green CI run proves only the checks in that workflow passed; it is not a penetration test or an operational acceptance certificate.

## Render Blueprint

1. Create a Blueprint from this repository.
2. Set `PACKETWHISPERER_API_TOKEN` to a randomly generated secret of at least 32 bytes in the Render dashboard. Do not commit or paste the secret into issues, logs, or screenshots.
3. Keep `APP_ENV=production`.
4. Restrict access at a trusted gateway, VPN, or identity-aware proxy. Use HTTPS.
5. Verify that `/ready` returns 200 after secret configuration and 503 if the secret is absent or too short.

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
- [ ] Detection rules are evaluated against representative labelled benign and malicious traffic; precision, recall, false-positive rate, and test dataset provenance are recorded.
- [ ] Recovery and incident-response procedures are documented and rehearsed if the deployment stores any operational state.

Example request:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $PACKETWHISPERER_API_TOKEN" \
  -F "file=@examples/sample_flows.csv;type=text/csv" \
  https://YOUR-SERVICE-HOST/v1/analyze/flows
```

## Operational limitations

The current bearer token is shared across clients; it is not user identity or role-based authorization. There is no durable case management or audit database. The application does not provide distributed rate limiting, live packet capture, or a validated production IDS. Use gateway-level controls and a restricted pilot until identity, audit, retention, and operational requirements are implemented and independently reviewed. Do not rely on this service as the sole control for network defense.
