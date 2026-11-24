# PacketWhisperer Hybrid SOC — Demo Walkthrough

This walkthrough is designed for the hosted #BuildHybridAI 2026 web client. The included dataset is synthetic and uses documentation-only IP ranges; it is not a real incident or evidence of malicious activity.

## Hosted application

- Web client: https://packetwhisper-git-hackathon-bui-7b6d58-brians-projects-a132bca2.vercel.app
- Analysis API: https://packetwhisperer-ai.onrender.com
- Repository: https://github.com/yobi369/PacketWhisperer-AI/tree/hackathon/buildhybridai-web
- Sample file: use **Download synthetic demo CSV** in the Evidence intake panel.

The hosted API includes a fixed, read-only synthetic demo endpoint that does not require a bearer token. The API bearer token is required only when uploading custom CSV/PCAP evidence. Never publish the token in this document, source control, screenshots, or the public demo video.

## Three-minute presentation flow

### 0:00–0:30 — Explain the problem and architecture

Introduce PacketWhisperer as an evidence-first network investigation assistant. The deterministic FastAPI engine produces measurable findings; Firebase AI Logic explains those findings using a hybrid inference path. The AI does not replace the detection engine or decide whether a host is compromised.

### 0:30–1:15 — Run deterministic analysis

1. Open the hosted web client. The Render API endpoint is prefilled.
2. Click **Load safe synthetic demo**. This requests a fixed 21-row fixture from the public read-only demo endpoint; no upload or bearer token is needed.
3. Point out the record count, deterministic findings, and SHA-256 evidence fingerprint.
4. For custom authorized uploads, enter the operator-issued bearer token and select a CSV or offline PCAP/PCAPNG file.

The 21-row fixture is designed to trigger destination fan-out and destination-port-diversity signals. Explain that these are heuristics, not proof of scanning or compromise.

### 1:15–2:15 — Ask the hybrid AI analyst

Use this focused question:

> Explain the strongest evidence for a scan-like pattern. Separate observed facts from hypotheses, state what information is missing, and list safe validation steps.

On a supported desktop with Gemini Nano available, leave cloud fallback unchecked and verify that the displayed inference source is `ON_DEVICE`.

If the device cannot run Gemini Nano, explicitly enable **Allow cloud fallback for this investigation**. The app uses `PREFER_ON_DEVICE`; the actual source is reported by the Firebase AI Logic SDK and should be shown accurately as `IN_CLOUD` when cloud inference is used. Cloud fallback is opt-in and the minimized findings summary may be sent to Google's cloud model.

### 2:15–3:00 — Show responsible analysis

Highlight that the answer:
- Uses the supplied findings rather than inventing IPs, timestamps, or packet contents.
- Separates observations from interpretation.
- States uncertainty and missing context.
- Recommends safe validation through asset inventory and authorized endpoint, DNS, firewall, or proxy logs.
- Does not treat heuristic alerts as proof of compromise.

## Evidence and privacy boundary

Raw CSV/PCAP uploads go to the analysis API endpoint configured by the operator. The Firebase AI prompt contains a bounded structured summary of findings and an evidence hash, not the raw uploaded capture bytes. If cloud fallback is explicitly enabled and used, that minimized summary may be processed by Google's cloud model. Do not upload sensitive production captures to this public demonstration.

## Reproducibility and limitations

- The synthetic CSV is available at `web/public/demo-flows.csv`.
- The deterministic API returns the findings and SHA-256 fingerprint for the exact uploaded bytes.
- The backend also supports bounded offline PCAP/PCAPNG metadata analysis; the hosted web walkthrough focuses on CSV.
- On-device inference depends on browser/device eligibility and model availability.
- The API's shared bearer token is a single-operator access gate, not multi-tenant identity or role-based authorization.
- The project is a research prototype, not a certified IDS, EDR, or production SOC platform.

For local development, see [the web client guide](../web/README.md) and [the root README](../README.md).
