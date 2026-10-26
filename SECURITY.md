# Security Policy

## Scope

PacketWhisperer AI is an early-stage network-analysis research project. It analyzes uploaded network-flow CSV records and bounded offline PCAP/PCAPNG packet metadata. It is not a certified intrusion-detection product, and heuristic alerts are not proof of compromise.

## Reporting a vulnerability

Please do not publish sensitive traffic captures, credentials, personal data, or exploit details in a public issue. Contact the repository owner privately through GitHub to coordinate a report. Include the affected revision, impact, reproducible steps, and a suggested mitigation where possible.

## Minimum deployment controls

- Keep the service behind a trusted TLS ingress or VPN; do not expose the application server directly to the public internet.
- Set `APP_ENV=production` and a randomly generated `PACKETWHISPERER_API_TOKEN` of at least 32 bytes using the platform secret manager.
- Treat the bearer token as a shared-secret gate, not individual identity. Rotate it after suspected disclosure and restrict who can retrieve it.
- Configure gateway-level rate limits, request timeouts, connection limits, and upload limits. In-process controls are not a substitute for edge protections.
- Restrict access to analysts authorized to handle the capture data.
- Do not upload traffic you lack permission to inspect.
- Treat alerts as investigation leads, not conclusive attribution.
- Establish retention, deletion, backup, incident-response, and data-protection procedures before handling customer captures.
- Review dependency advisories and CI results before each release.

## Current limitations

Production readiness checks fail closed when the shared token is missing or shorter than 32 bytes. Analysis uploads are bounded and API responses are marked non-cacheable. These controls do not provide user identity, role-based access control, distributed rate limiting, durable audit storage, case management, or independent security certification. Those capabilities must not be assumed present.
