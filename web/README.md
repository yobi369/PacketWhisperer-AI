# PacketWhisperer Hybrid SOC (Web)

Competition web client for #BuildHybridAI 2026. This app preserves the existing FastAPI detection engine and adds an evidence-minimizing analyst experience using Firebase AI Logic hybrid inference.

## Architecture

- **Deterministic analysis:** the existing PacketWhisperer API analyzes CSV flow records and offline PCAP/PCAPNG metadata.
- **Hybrid AI:** Firebase AI Logic uses `ONLY_ON_DEVICE` by default. If the analyst explicitly enables cloud fallback, it uses `PREFER_ON_DEVICE` so the SDK attempts Chrome on-device inference and falls back to the cloud model when local inference is unavailable.
- **Evidence minimization:** only a bounded structured summary of returned findings is included in the AI prompt. Raw capture bytes are never sent to Firebase AI Logic.
- **Identity and persistence:** anonymous Firebase Authentication sessions scope investigation metadata in Firestore. No raw PCAP, packet payload, or uploaded CSV is persisted by this client.
- **App Check:** Firebase App Check is initialized before Firebase AI Logic use. Use debug tokens only for development and a registered reCAPTCHA v3 provider for production.

## Requirements

- Node.js 20 or newer.
- A Firebase project with the Gemini Developer API / Firebase AI Logic enabled.
- Firebase Authentication with Anonymous sign-in enabled.
- Firestore database created.
- Firebase App Check configured.
- A deployed or locally running PacketWhisperer FastAPI service.
- For on-device inference: desktop Chrome 139+ with the required Prompt API / Gemini Nano configuration and model available. Otherwise, hybrid mode may use cloud inference.

## Firebase Console setup

Complete these steps in the same Firebase project before expecting hybrid inference to work:

1. Register a Web app under Project settings and copy its Firebase web configuration into `.env.local`.
2. In Firebase AI Logic, enable the Gemini Developer API backend for the project.
3. In Authentication > Sign-in method, enable **Anonymous** sign-in.
4. Create a Cloud Firestore database.
5. In App Check, register the web app with a reCAPTCHA v3 site key and configure enforcement for Firebase AI Logic. Do not add localhost to the reCAPTCHA allowed domains to bypass local attestation.
6. For local development, use the App Check debug token flow described above and register the generated token under the app's Manage debug tokens panel. Debug tokens are private and must never be shipped in production.
7. Deploy `firestore.rules` from this repository before testing investigation persistence.

App Check enforcement and Firebase AI Logic project enablement are Firebase Console settings; initializing the SDK in source code does not automatically enable them.

## Local setup

```bash
cd web
cp .env.example .env.local
npm install
npm run dev
```

Populate `.env.local` from Firebase Project settings > Your apps > Web app. Set the App Check reCAPTCHA v3 site key in `.env.local`. For local development, also set `VITE_APPCHECK_DEBUG=true`; the SDK will use a debug token instead of reCAPTCHA attestation. Open the app, copy the generated App Check debug token from the browser console, and register it in Firebase Console > App Check > Apps > Manage debug tokens. Keep the token private and never commit it.

The app will display configuration status and keep hybrid AI disabled until required Firebase settings are supplied.

## Reproducible demo

The web client serves [demo-flows.csv](public/demo-flows.csv), a synthetic 21-row dataset using documentation-only IP ranges. Upload it to demonstrate the deterministic high-destination-fan-out and destination-port-diversity findings. It is synthetic test data, not a malicious capture or evidence of a real incident.

Suggested walkthrough:
1. Download or select the synthetic CSV and connect the FastAPI API.
2. Run deterministic analysis and inspect the evidence SHA-256 and rule findings.
3. Ask the analyst to explain why the observations are scan-like without asserting compromise.
4. Keep cloud fallback unchecked to demonstrate the on-device-only path on supported Chrome hardware.
5. Enable cloud fallback with explicit consent and demonstrate the SDK-reported inference source when local inference is unavailable.
6. Show that investigation metadata is saved under the authenticated user's Firestore path.

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

For a deployed app, configure Firebase Admin verification on the API using server-side secrets (never Vite variables):

```bash
export APP_ENV=production
export FIREBASE_PROJECT_ID="your-firebase-project-id"
export FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"service_account", "...":"..."}'
```

The service-account JSON must be stored as a secret in the backend hosting provider. With this setting, the web client signs in anonymously through Firebase Authentication and sends its short-lived Firebase ID token to the API; the backend verifies it using Firebase Admin. If Firebase Admin credentials are not configured, the legacy `PACKETWHISPERER_API_TOKEN` bearer gate remains available for local/single-operator testing only. Do not put a shared production bearer token in a public browser app.

## Hybrid inference behavior

The app defaults to `getGenerativeModel(..., { mode: InferenceMode.ONLY_ON_DEVICE })`. When the analyst checks the cloud-fallback consent control, it uses `InferenceMode.PREFER_ON_DEVICE`. The app reads `result.response.inferenceSource`. The UI labels the observed source as `ON_DEVICE` or `IN_CLOUD`. Do not describe an inference request as local unless the SDK reports `ON_DEVICE`.

On-device inference is currently limited by Chrome desktop support, model availability, and supported input capabilities. This implementation uses a single-turn text prompt with structured findings because hybrid on-device multi-turn chat and tool calling are not supported.

## Security notes

- Firebase web config values are public client configuration, not server secrets.
- Never put service-account credentials or private API keys in Vite environment variables prefixed with `VITE_`.
- Do not use App Check debug tokens in production.
- The backend bearer token is a temporary single-operator control, not user-level authorization. Do not expose a shared production token to untrusted public users.
- Findings are heuristic investigation leads, not proof of compromise. Human review is required before operational action.
