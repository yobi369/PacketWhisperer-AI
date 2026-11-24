# BuildHybridAI hosted deployment

The competition web client is deployed from `web/` through Vercel and connects to the existing FastAPI analysis service on Render.

## Current deployment

- Vercel project: `packetwhisper`
- Git repository: `yobi369/PacketWhisperer-AI`
- Hackathon branch: `hackathon/buildhybridai-web`
- Vercel root directory: `web`
- Framework: Vite
- Build command: `npm run build`
- Output directory: `dist`
- Preview URL: https://packetwhisper-git-hackathon-bui-7b6d58-brians-projects-a132bca2.vercel.app
- Analysis API: https://packetwhisperer-ai.onrender.com
- Firebase project: `packetwhisper-hybrid-soc`

The Preview deployment is the hackathon test target. Do not promote it to Production until the final review is complete.

## Environment and secrets

Firebase web configuration and the reCAPTCHA Enterprise site key are supplied as Vercel Preview environment variables. These are browser-side configuration values; they are not service-account credentials.

The hosted Render API currently uses a server-side `PACKETWHISPERER_API_TOKEN` and CORS allowlisting. The operator enters the bearer token into the app's password field when using the hosted demo. Never commit the token, put it in a `VITE_*` variable, include it in screenshots/video, or distribute it publicly. This shared token is a single-operator gate, not per-user authorization.

Do not claim Firebase Authentication ID tokens are accepted by the current API unless Firebase Admin token verification has actually been implemented and deployed on that backend.

## Hybrid inference behavior

- With cloud fallback unchecked, the client requests `InferenceMode.ONLY_ON_DEVICE`.
- With explicit cloud-fallback consent, the client requests `InferenceMode.PREFER_ON_DEVICE`.
- The interface reports the SDK's actual `inferenceSource`; do not infer the source from the selected mode.
- A cloud result is possible only when the analyst has opted in. The minimized structured findings summary may then be sent to Google's cloud model.
- Raw uploaded capture bytes are sent to the configured analysis API, not included in the Firebase AI prompt.

## Cost and safety constraints

- Keep Firebase on the Spark plan; do not enable billing for this demo.
- Do not add paid hosting plans, paid APIs, or subscriptions for the competition build.
- Keep secrets in the hosting provider's secret/environment settings, not in Git.
- App Check is initialized in the client with the registered reCAPTCHA Enterprise provider. Check Firebase App Check metrics and the current console enforcement state when diagnosing rejected requests; do not weaken enforcement or change billing as a speculative workaround.
- Use only synthetic or explicitly authorized traffic for demonstrations.

## Validation before recording

1. Confirm the Vercel Preview deployment is READY and corresponds to the intended branch commit.
2. Confirm the API health endpoint responds.
3. Run the included synthetic CSV through deterministic analysis.
4. Ask the AI analyst the question in [DEMO.md](DEMO.md).
5. Show the actual inference source returned by the SDK.
6. Verify no previous inference-source label remains after a failed request.
7. Keep API tokens, Firebase secrets, and private console values out of the recording.

## Known deployment limitations

The hosted API currently relies on one operator-issued bearer token. It is not a public multi-user service and should not receive customer or production network captures. Firebase anonymous authentication scopes saved analyst metadata in Firestore; it does not, by itself, authenticate requests to the Render analysis API.
