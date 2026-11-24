# #BuildHybridAI 2026 — Submission Package

This document is the source of truth for the project description and demo narrative. Keep every claim aligned with the deployed implementation.

## Platform selection

**Web (Chrome)** — the application integrates Firebase AI Logic hybrid inference for the web platform.

## Project title

**PacketWhisperer AI — Evidence-First Hybrid SOC Analyst**

## One-line summary

A network investigation assistant that combines deterministic, reproducible traffic analysis with consent-controlled on-device and cloud AI explanations.

## Short description

PacketWhisperer AI helps security analysts move from network observations to cautious, evidence-grounded investigation. Its deterministic FastAPI engine analyzes validated flow CSV files and bounded offline PCAP/PCAPNG metadata, produces explainable heuristic findings, and fingerprints the uploaded evidence with SHA-256. A Firebase AI Logic analyst then explains the structured findings using hybrid inference: on-device-only by default, with cloud fallback available only after explicit analyst consent. The interface reports the inference source returned by the SDK, and the AI is instructed to separate observations from hypotheses, state uncertainty, and recommend safe validation steps.

## Devpost-ready full description

PacketWhisperer AI is an evidence-first hybrid security operations assistant for network investigations. It addresses two common problems: analysts need to understand why traffic was flagged, and organizations should not have to send entire packet captures to a generative AI model just to receive an explanation.

The project starts with a deterministic Python/FastAPI engine. It validates flow records, analyzes bounded offline PCAP/PCAPNG metadata, produces transparent heuristic findings, and computes a SHA-256 fingerprint of the exact evidence supplied. Each finding includes a rule identifier, measured observation, threshold, and interpretation caveat.

Firebase AI Logic adds a hybrid analyst experience. The application requests on-device-only inference by default. If an analyst explicitly enables cloud fallback, the application switches to prefer-on-device mode and allows cloud inference only when local inference is unavailable. The UI displays the inference source reported by the SDK. The model receives a bounded summary of findings rather than raw packet bytes and is instructed to distinguish facts from hypotheses, identify missing context, and recommend safe validation.

The result is a practical demonstration of a hybrid design: deterministic evidence generation, minimized AI context, explicit cloud consent, and transparent inference provenance. It is a research prototype, not a replacement for a mature SIEM, NDR, or EDR platform.

## How we built it

The FastAPI service performs CSV flow analysis and bounded offline PCAP/PCAPNG metadata inspection. A Vite browser client connects to that API and to Firebase AI Logic. Firebase App Check uses the registered reCAPTCHA Enterprise provider; anonymous Firebase Authentication scopes investigation metadata saved in Firestore. The client uses `ONLY_ON_DEVICE` unless the analyst checks the cloud-fallback consent control, in which case it uses `PREFER_ON_DEVICE`. The application reports the SDK's actual `inferenceSource` value.

The web client is deployed on Vercel, and the analysis API runs on Render. A fixed synthetic demo endpoint lets reviewers try the core analysis without uploading a file or receiving an operator API token. Custom evidence uploads remain protected by the operator token.

## Accomplishments

- Connected a deterministic network-analysis engine to Firebase AI Logic hybrid inference.
- Implemented explicit consent for cloud fallback and display of actual inference provenance.
- Minimized the AI input to structured findings rather than raw capture bytes.
- Added reproducible SHA-256 evidence fingerprints and a fixed public synthetic demo.
- Preserved cautious language: heuristic detections are leads, not proof of compromise.
- Added automated tests, security checks, deployment documentation, and a three-minute demo plan.

## Challenges

The central challenge was balancing local inference, privacy, and real device constraints. Gemini Nano is not available on every computer, so the application must distinguish the selected inference mode from the actual source used. Another challenge was separating deterministic network observations from AI-generated interpretation so that the model cannot invent evidence or turn weak heuristics into claims of compromise. The project also needed a public judging path that did not expose the private upload API token; the fixed synthetic demo endpoint addresses that without opening arbitrary uploads.

## Impact and next steps

The design can help analysts understand traffic findings faster while limiting the information passed to generative AI. Next steps include validating on-device inference across compatible hardware, evaluating heuristics against properly licensed labeled traffic datasets, adding per-user API authorization and rate limiting, and building auditable investigation workflows. These are future goals, not features claimed as complete.

## Built with

Firebase AI Logic, Firebase App Check, Firebase Authentication, Cloud Firestore, Python, FastAPI, Vite, JavaScript, Docker, GitHub Actions, Vercel, and Render.

## Existing project disclosure

PacketWhisperer AI began as an existing network-analysis project. During the #BuildHybridAI submission period, the project was significantly extended with the following work:

- Added a Vite-based Hybrid SOC web application.
- Integrated Firebase AI Logic at runtime with on-device-only and consented cloud-fallback inference modes.
- Added device-model initialization and SDK-reported inference-source labels.
- Integrated Firebase App Check with reCAPTCHA Enterprise, anonymous Firebase Authentication, and Firestore investigation metadata.
- Added owner-scoped Firestore rules and a bounded evidence-summary prompt that excludes raw packet bytes.
- Added the public fixed synthetic demo endpoint so judges can try deterministic analysis without an API token.
- Added a hosted deployment, security/CI coverage, and updated documentation and submission materials.

The pre-existing deterministic engine is the foundation: it validates flow data, analyzes bounded offline packet metadata, produces explainable heuristic findings, and fingerprints evidence. The hackathon work adds a consent-aware hybrid AI analyst that explains those findings without replacing the deterministic engine.

## Problem

Network alerts often compress complex traffic into severity labels without giving analysts enough context to understand what was actually observed. Generative AI can make explanations easier to read, but sending raw packet captures to a cloud model creates unnecessary data exposure, cost, and trust concerns. At the same time, purely local AI may not be available on every device.

## Solution

PacketWhisperer separates detection from explanation:

1. A deterministic analysis engine validates traffic records and calculates measurable signals.
2. Each report includes rule identifiers, observed values, interpretive caveats, and a SHA-256 fingerprint of the exact uploaded bytes.
3. Firebase AI Logic receives only a bounded structured summary of findings, not raw uploaded packet bytes.
4. The analyst chooses whether cloud fallback is permitted. Without consent, the client requests `ONLY_ON_DEVICE`; with consent, it requests `PREFER_ON_DEVICE`.
5. The UI reports the SDK's actual inference source rather than treating the selected mode as proof of where inference ran.

The AI is an explanation assistant, not the detection authority. It must not invent indicators or claim that a heuristic finding proves compromise.

## Hybrid AI implementation

- **SDK:** Firebase AI Logic for the web.
- **Default path:** `InferenceMode.ONLY_ON_DEVICE`.
- **Consent path:** `InferenceMode.PREFER_ON_DEVICE`, allowing local inference first and cloud fallback when the local model is unavailable.
- **Source transparency:** reads `result.response.inferenceSource` and displays `ON_DEVICE`, `IN_CLOUD`, or `UNKNOWN`.
- **Model initialization:** attempts device-model initialization before generation.
- **Grounding:** the prompt contains a bounded JSON evidence object with flow count, up to 20 findings, selected measured signals, and the evidence hash.
- **Persistence:** Firebase anonymous authentication scopes analyst metadata in Firestore; raw capture files are not written to Firestore by this client.
- **Abuse protection:** Firebase App Check is initialized with the registered reCAPTCHA Enterprise provider.

A successful cloud-fallback run has been observed and reported by the SDK as `PREFER_ON_DEVICE · IN_CLOUD`. Local inference still depends on compatible desktop Chrome hardware, model availability, and supported browser capabilities.

## Architecture

- **Web client:** Vite application deployed on Vercel.
- **Network analysis:** Python/FastAPI service deployed on Render.
- **Hybrid AI and metadata:** Firebase AI Logic, Firebase Authentication, Firestore, and App Check.
- **Evidence processing:** CSV flow records and bounded offline PCAP/PCAPNG metadata.
- **Integrity:** SHA-256 evidence fingerprint.
- **Test data:** synthetic 21-row CSV using documentation-only addresses.

## Responsible AI and privacy

- Raw uploaded evidence is sent to the operator-configured PacketWhisperer analysis API.
- Raw packet bytes are not included in the Firebase AI prompt; only a minimized findings summary is sent.
- If the analyst explicitly permits cloud fallback and the SDK uses it, that minimized summary may be processed by Google's cloud model.
- On-device inference is not claimed unless the SDK reports `ON_DEVICE`.
- Heuristic alerts are investigation leads, not proof of malicious activity.
- Analysts should use only traffic they own or are authorized to inspect.

## Current limitations

- No live packet capture or network sensor.
- No full protocol dissection or endpoint detection.
- Heuristic thresholds have not been calibrated against representative production traffic.
- No production-grade multi-tenant identity, role-based authorization, or case-management workflow.
- The hosted analysis API exposes a fixed read-only synthetic demo route without authentication; custom evidence upload routes still use an operator-issued shared bearer token. The upload API is not a public multi-user service.
- On-device inference depends on supported browser/device hardware and model availability.
- This is a research prototype, not a certified IDS, EDR, or production SOC platform.

## Three-minute demo script

**0:00–0:30 — The idea**
"PacketWhisperer separates what the network evidence shows from what an analyst thinks it means. Deterministic analysis comes first; AI explains the evidence without replacing it."

**0:30–1:15 — Evidence**
Open the hosted web client and click **Load safe synthetic demo**. The fixed public demo endpoint requires no API token. Show the 21 records, findings, and SHA-256 fingerprint. Explain that the signals are not proof of compromise.

**1:15–2:15 — Hybrid analyst**
Ask: "Explain the strongest evidence for a scan-like pattern. Separate observed facts from hypotheses, state what information is missing, and list safe validation steps." On compatible hardware, demonstrate the on-device-only path and verify `ON_DEVICE`. Otherwise, explicitly enable cloud fallback and show the SDK-reported source. Never describe a cloud result as on-device.

**2:15–3:00 — Trust and limits**
Show the evidence-minimization boundary, explain the consent control, and point out that the analyst response identifies uncertainty and safe validation steps. Close by stating the current limitations honestly.

## Submission checklist

- [ ] Select **Web (Chrome)** as the Devpost platform.
- [ ] Confirm final Vercel Preview deployment is READY.
- [ ] Confirm Render API health and synthetic CSV analysis.
- [ ] Complete the final consent/source verification on an available test device.
- [ ] Record a YouTube demo of no more than three minutes.
- [ ] Set the YouTube video visibility to the competition's accepted setting.
- [ ] Confirm GitHub repository is public and includes an appropriate license.
- [ ] Add the live app URL and YouTube demo URL to the Devpost entry.
- [ ] Review the final Devpost description for unsupported claims.
- [ ] Submit before **November 30, 2026 at 2:00 PM Pacific Time (December 1, 2026 at 1:00 AM Kenya time)**.

## Public links

- Repository: https://github.com/yobi369/PacketWhisperer-AI
- Hackathon branch: https://github.com/yobi369/PacketWhisperer-AI/tree/hackathon/buildhybridai-web
- Hosted Preview alias (SSO-protected; use the time-limited share URL for judges): https://packetwhisper-git-hackathon-bui-7b6d58-brians-projects-a132bca2.vercel.app
- Analysis API: https://packetwhisperer-ai.onrender.com
- YouTube demo: add after recording.
- Devpost submission: add after publishing.
