# PacketWhisperer Hybrid SOC (Web)

Competition web client for #BuildHybridAI 2026. This app preserves the existing FastAPI detection engine and adds an evidence-minimizing analyst experience using Firebase AI Logic hybrid inference.

## Architecture

- **Deterministic analysis:** the existing PacketWhisperer API analyzes CSV flow records and offline PCAP/PCAPNG metadata.
- **Hybrid AI:** Firebase AI Logic uses `ONLY_ON_DEVICE` by default. If the analyst explicitly enables cloud fallback, it uses `PREFER_ON_DEVICE` so the SDK attempts Chrome on-device inference and falls back to the cloud model when local inference is unavailable.
- **Evidence minimization:** only a bounded structured summary of returned findings is included in the AI prompt. Raw capture bytes are never sent to Firebase AI Logic.
- **Identity and persistence:** anonymous Firebase Authentication sessions scope investigation metadata in Firestore. No raw PCAP, packet payload, or uploaded CSV is persisted by this client.
- **App Check:** Firebase App Check is initialized before Firebase AI Logic using the reCAPTCHA Enterprise provider. Local development uses the App Check debug-token flow; production uses the registered Enterprise site key.

## Requirements

- Node.js 20 or newer.
- A Firebase project with the Gemini Developer API / Firebase AI Logic enabled.
- Firebase Authentication with Anonymous sign-in enabled.
- Firestore database created.
- Firebase App Check configured with reCAPTCHA Enterprise.
- A deployed or locally running PacketWhisperer FastAPI service.
- For on-device inference: desktop Chrome 139+ with the required Prompt API / Gemini Nano configuration and model available. Otherwise, hybrid mode may use cloud inference.

## Firebase Console setup

Complete these steps in the same Firebase project before expecting hybrid inference to work:

1. Register a Web app under Project settings and copy its Firebase web configuration into `.env.local`.
2. In Firebase AI Logic, enable the Gemini Developer API backend for the project.
3. In Authentication > Sign-in method, enable **Anonymous** sign-in.
4. Create a Cloud Firestore database.
5. In Google Cloud Console, create a score-based reCAPTCHA Enterprise web key for the production domains. Do not add `localhost` to a production key.
6. In Firebase Console > App Check > Apps, register the web app with the **reCAPTCHA Enterprise** provider and the same Enterprise key.
7. For local development, use the App Check debug token flow described below and register the generated token under the app's Manage debug tokens panel. Debug tokens are private and must never be shipped in production.
8. Deploy `firestore.rules` from this repository before testing investigation persistence.

App Check enforcement and Firebase AI Logic project enablement are Firebase Console settings; initializing the SDK in source code does not automatically enable them. Check the current enforcement state and request metrics when diagnosing rejected calls. Do not weaken enforcement or change billing as a speculative workaround.

## Local setup

```bash
cd web
cp .env.example .env.local
npm install
npm run dev
```

Populate `.env.local` from Firebase Project settings > Your apps > Web app. Set `VITE_RECAPTCHA_ENTERPRISE_SITE_KEY` to the same public Enterprise site key registered in Firebase App Check.

For local development, also set `VITE_APPCHECK_DEBUG=true`. The SDK will use a debug token instead of reCAPTCHA attestation. Open the app, copy the generated App Check debug token from the browser console, and register it in Firebase Console > App Check > Apps > Manage debug tokens. Keep the token private and never commit it.

The app will display configuration status and keep hybrid AI disabled until required Firebase settings are supplied.

## Reproducible demo

The web client serves [demo-flows.csv](public/demo-flows.csv), a synthetic 21-row dataset using documentation-only IP ranges. Upload it to demonstrate the deterministic high-destination-fan-out and destination-port-diversity findings. It is synthetic test data, not a malicious capture or evidence of a real incident.

Hosted walkthrough:
1. Open the Vercel Preview URL listed in `docs/BUILDHYBRIDAI-DEPLOYMENT.md`; the Render API endpoint is prefilled.
2. Click **Load safe synthetic demo**. This calls the fixed public `GET /v1/demo/flows` endpoint; it accepts no uploads and does not require a bearer token.
3. Inspect the 21 records, deterministic findings, and SHA-256 evidence fingerprint.
4. Ask: "Explain the strongest evidence for a scan-like pattern. Separate observed facts from hypotheses, state what information is missing, and list safe validation steps."
5. On a supported device, keep cloud fallback unchecked and verify the SDK reports `ON_DEVICE`. If local inference is unavailable, enable cloud fallback explicitly and show the actual source reported by the SDK.
6. Explain that Firebase stores analyst metadata under the anonymous user's Firestore path.

For custom uploads, the hosted Render API still requires an operator-issued bearer token. Do not publish it or include it in the demo recording. The token is a single-operator access gate, not multi-user authorization.

## Firestore rules

Deploy the repository's `firestore.rules` file. It restricts each anonymous or authenticated user to their own investigation metadata.

## API connection

Start the existing backend separately:

```bash
cd ..
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
uvicorn packetwhisperer.api:app --host 127.0.0.1 --port 8000
```

Enter `http://127.0.0.1:8000` as the analysis API endpoint in the web app. Configure the backend CORS allowlist for the web origin:

```bash
export PACKETWHISPERER_CORS_ORIGINS="http://localhost:5173,https://your-deployed-web-origin"
```

For the current hosted deployment, the Render API uses the server-side `PACKETWHISPERER_API_TOKEN` gate. The operator enters that token in the web client's password field; it is held in page memory and is not stored in local storage. Keep the token private and do not include it in public recordings or source control.

Firebase anonymous authentication is used to scope investigation metadata saved in Firestore. The current FastAPI backend does **not** verify Firebase Authentication ID tokens; do not treat Firebase sign-in as API authorization. A future multi-user deployment needs Firebase Admin token verification or another managed identity gateway, plus per-user authorization and rate limiting.

## Hybrid inference behavior

The app defaults to `getGenerativeModel(..., { mode: InferenceMode.ONLY_ON_DEVICE })`. When the analyst checks the cloud-fallback consent control, it uses `InferenceMode.PREFER_ON_DEVICE`. The app reads `result.response.inferenceSource`. The UI labels the observed source as `ON_DEVICE` or `IN_CLOUD`. Do not describe an inference request as local unless the SDK reports `ON_DEVICE`.

On-device inference is currently limited by Chrome desktop support, model availability, and supported input capabilities. This implementation uses a single-turn text prompt with structured findings because hybrid on-device multi-turn chat and tool calling are not supported.

## Security notes

- Firebase web config values are public client configuration, not server secrets.
- Never put service-account credentials or private API keys in Vite environment variables prefixed with `VITE_`.
- Do not use App Check debug tokens in production.
- The backend bearer token is a temporary single-operator control, not user-level authorization. Do not expose a shared production token to untrusted public users.
- Findings are heuristic investigation leads, not proof of compromise. Human review is required before operational action.
