# BuildHybridAI hosted deployment

The hackathon web client is deployed from the `web/` directory using Vercel.

## Deployment configuration

- Framework: Vite
- Root directory: `web`
- Build command: `npm run build`
- Output directory: `dist`
- Firebase client configuration is supplied through Vercel Preview environment variables.
- App Check uses the reCAPTCHA Enterprise site key registered for the Firebase web app.

## Safety and cost constraints

- Keep Firebase on the Spark plan; do not enable billing for this demo.
- Keep App Check enforcement disabled until the deployed client has been verified.
- The client defaults to on-device inference. Cloud inference must remain an explicit user opt-in.
- Never commit local environment files, service-account credentials, or private API secrets.

## Validation

Verify the Preview deployment before promoting any build to Production. Confirm Firebase initialization, App Check, and the actual inference source in the browser before recording the demo.
