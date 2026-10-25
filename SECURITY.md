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

A configurable shared bearer-token gate is available, and production mode fails closed if the token is missing. This is not user identity or role-based access control. Persistent audit storage, case management, and production-grade rate limiting remain known gaps, not features to assume are present.
