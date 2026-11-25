# #BuildHybridAI 2026 — 3-minute demo script

Use a real browser session and a configured Firebase project. Do not fake the inference-source label or edit screenshots to imply local inference.

| Time | Screen / action | Narration |
|---|---|---|
| 0:00–0:20 | Show the PacketWhisperer Hybrid SOC dashboard. | “Network evidence is sensitive. PacketWhisperer separates deterministic network analysis from AI explanation, keeping the evidence traceable and local inference as the default.” |
| 0:20–0:45 | Download and upload `demo-flows.csv`; run the FastAPI analysis. | “This synthetic dataset contains 21 flows from a documentation-only source address. The deterministic engine identifies high destination fan-out and port diversity.” |
| 0:45–1:10 | Show findings, rule IDs, evidence text, and SHA-256 fingerprint. | “Every finding is tied to a measurable signal and an evidence fingerprint. A heuristic is an investigation lead, not proof of compromise.” |
| 1:10–1:40 | Leave cloud fallback unchecked; ask the analyst to explain the pattern on a supported Chrome desktop. | “The default path is on-device only. Firebase AI Logic reports the actual inference source, so the interface does not guess whether the model ran locally.” |
| 1:40–2:15 | Enable cloud fallback explicitly. Use a setup where local inference is unavailable, then ask the same question. | “If the analyst authorizes cloud fallback, the SDK prefers on-device inference and falls back to the cloud model when local inference is unavailable. Only the bounded findings summary is sent, never the raw capture.” |
| 2:15–2:35 | Show the observed `IN_CLOUD` or `ON_DEVICE` source and Firestore metadata record. | “The inference source and investigation metadata are stored with the authenticated analyst's record.” |
| 2:35–3:00 | Show the limitations / responsible-use note. | “PacketWhisperer combines explainable detection with hybrid inference. It does not claim that model output proves an intrusion, and an analyst remains responsible for validation and response.” |

## Recording checklist

- Capture the app functioning in Chrome desktop, not just slides or code.
- Show the real SDK inference source for each run.
- If demonstrating local inference, confirm that the response reports `ON_DEVICE`.
- If demonstrating fallback, confirm that the response reports `IN_CLOUD`.
- Do not expose Firebase service-account credentials, debug tokens, API tokens, private PCAP data, or personal information.
- Keep the video under three minutes and add English narration or subtitles.
- Publish the video publicly on YouTube and include the URL in the Devpost submission.
- Rehearse once before recording; avoid unsupported performance or privacy claims.
