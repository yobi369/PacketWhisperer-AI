# Deployment Guide

## Before deployment

This project is an early-stage analysis service, not a validated production IDS. Review the threat model and ensure your intended data handling is authorized.

## Render Blueprint

The repository includes `render.yaml`. In Render, create a new Blueprint from this repository and set a long random value for `PACKETWHISPERER_API_TOKEN` when prompted. Store it in a password manager or approved secret manager; do not commit it to Git. The Blueprint sets `APP_ENV=production`, and the service will fail readiness if the token is missing.

The container listens on the platform-provided `PORT` value (defaulting to 8000 locally). Render health checks use `/ready`.

## Smoke tests after deploy

1. Open `/` and confirm the PacketWhisperer analyst dashboard loads.
2. Confirm `/health` returns `200`.
3. Confirm `/ready` returns `200` only after the production token is configured.
4. Call `POST /v1/analyze/flows` without a token and confirm it returns `401`.
5. Call the same endpoint with `Authorization: Bearer <your-token>` and a small authorized test CSV; confirm it returns a report and SHA-256 evidence fingerprint.
6. Upload a small synthetic PCAP to `POST /v1/analyze/pcap` with the same bearer header; confirm packet totals and evidence hash.
7. Confirm malformed and oversized uploads are rejected and no source traffic is stored by the application.

Example request:

```bash
curl -H "Authorization: Bearer $PACKETWHISPERER_API_TOKEN" \
  -F "file=@examples/sample_flows.csv;type=text/csv" \
  https://YOUR-SERVICE-HOST/v1/analyze/flows
```

Replace the host with the actual service hostname. Do not paste your token into public logs or screenshots.

## Important production gaps

The bearer token is a shared-secret gate, not user identity or role-based authorization. Before handling customer traffic or offering this as a multi-user service, add managed identity, per-user permissions, durable audit records, rate limiting at a trusted gateway, retention/deletion controls, dependency scanning, load tests, backups where applicable, and an incident-response procedure. Keep service access restricted to authorized analysts.
