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

## Local setup

```bash
cd web
cp .env.example .env.local
npm install
npm run dev
```

Populate `.env.local` from Firebase Project settings > Your apps > Web app. Set the App Check reCAPTCHA v3 site key in `.env.local`. For local development, also set `VITE_APPCHECK_DEBUG=true`; the SDK will use a debug token instead of reCAPTCHA attestation. Open the app, copy the generated App Check debug token from the browser console, and register it in Firebase Console > App Check > Apps > Manage debug tokens. Keep the token private and never commit it.

The app will display configuration status and keep hybrid AI disabled until required Firebase settings are supplied.

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
