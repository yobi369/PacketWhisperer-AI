# Security Policy

## Scope

PacketWhisperer AI is an early-stage research project. The current implementation analyzes uploaded network-flow CSV records using deterministic heuristics. It is not yet a certified intrusion-detection product.

## Reporting a vulnerability

Please do not publish sensitive traffic captures, credentials, personal data, or exploit details in a public issue. Contact the repository owner privately through GitHub to coordinate a report. Include the affected revision, impact, reproducible steps, and a suggested mitigation where possible.

## Deployment precautions

- Keep the API behind trusted network controls until authentication, authorization, and rate limiting are implemented.
- Use TLS at the trusted ingress and restrict access to analysts who are authorized to handle the data.
- Do not upload traffic that you lack permission to inspect.
- Treat alerts as investigation leads, not conclusive attribution.
- Apply dependency updates and review security advisories before each deployment.
- Establish retention, deletion, backup, and incident-response policies before handling real customer captures.

## Current limitations

The initial service has no user authentication, role-based access control, persistent audit store, case management, or production-grade rate limiting. These are known gaps, not features to assume are present.
