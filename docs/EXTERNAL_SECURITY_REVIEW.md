# Independent Security Review Packet

**Status: prepared for external review; not reviewed or approved by an independent assessor.**

## Scope requested

Review the PacketWhisperer-AI API and deployment for authentication, authorization, upload parsing/resource exhaustion, secrets management, session handling, rate limiting, case/audit integrity, dependency risk, deployment configuration, privacy, and recovery.

## Evidence to collect

- Exact Git commit SHA and release image digest.
- CI and security workflow results for that SHA.
- Architecture and data-flow diagrams, including upload limits and trust boundaries.
- Endpoint inventory and role/permission matrix.
- Threat model, abuse cases, and security assumptions.
- Dependency inventory/SBOM and vulnerability scan output.
- Tests for auth bypass, role escalation, session expiry, brute force, upload size bypass, malformed PCAP/CSV, audit tampering, and rate-limit behavior across instances.
- Database backup, restore, retention, and deletion evidence.
- Configuration evidence with secret values redacted.
- Detection benchmark dataset provenance, label methodology, class balance, precision/recall/FPR per rule, and known limitations.

## Required reviewer activities

1. Review source code and deployment configuration at a pinned commit.
2. Independently reproduce tests and run static/dependency analysis.
3. Test authenticated and unauthenticated routes, all role boundaries, and session invalidation.
4. Exercise malformed and oversized multipart uploads, including chunked requests without Content-Length.
5. Test rate limits concurrently across more than one application instance using the configured shared Redis endpoint.
6. Verify that case/audit data survives redeploy/restart and can be restored from backup; inspect audit tamper-resistance and retention.
7. Conduct a scoped penetration test only with written authorization and a defined environment.
8. Provide a signed report with severity, reproducible evidence, remediation guidance, retest results, and explicit residual risk.

## Known gates before operational reliance

- Configure DATABASE_URL to a dedicated managed PostgreSQL database with an appropriate non-expiring plan, backups, access restrictions, and a tested restore process. Do not point this app at the ShuleLedger database.
- Configure REDIS_URL with the private URL for the dedicated Render Key Value instance and verify multi-instance rate limiting.
- Remove the one-time bootstrap secret after initial administrator creation.
- Do not upload sensitive captures until retention, access, incident response, and external review requirements are approved.
- Obtain authorized, representative labeled benign/malicious network flows. Synthetic fixtures are for regression testing and cannot establish real-world accuracy.
- This application is a research/triage tool, not a certified IDS. Findings are investigation leads, not proof of compromise.

## Reviewer independence

The reviewer must be external to the implementation, disclose conflicts, document the tested commit and scope, and not treat this checklist or CI output as a substitute for their findings.
