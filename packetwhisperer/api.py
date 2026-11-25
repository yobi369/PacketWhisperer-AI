"""HTTP API for PacketWhisperer AI flow analysis."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from packetwhisperer import __version__
from packetwhisperer.analyzer import FlowValidationError, analyze_flows, parse_flows
from packetwhisperer.pcap_analyzer import CaptureValidationError, MAX_CAPTURE_BYTES, analyze_pcap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packetwhisperer")
app = FastAPI(title="PacketWhisperer AI", version=__version__, description="Explainable network-flow analysis API. Findings are heuristic investigation leads, not proof of compromise.", docs_url="/docs", redoc_url="/redoc")
cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "PACKETWHISPERER_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# Fixed, non-sensitive 21-row fixture for an unauthenticated read-only product demo.
# This endpoint never accepts user uploads; it only analyzes this bounded synthetic dataset.
DEMO_FLOW_CSV = (
    "src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n"
    + "".join(
        f"10.0.0.5,192.0.2.{index},51000,{1000 + index},TCP,2048,5,0.25\n"
        for index in range(1, 22)
    )
).encode("utf-8")


MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _verify_firebase_id_token(token: str) -> bool:
    """Verify a Firebase Authentication ID token when Admin credentials are configured."""
    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "")
    if not service_account_json:
        return False
    try:
        import firebase_admin
        from firebase_admin import auth as firebase_auth, credentials

        try:
            firebase_app = firebase_admin.get_app()
        except ValueError:
            service_account_info = json.loads(service_account_json)
            credential = credentials.Certificate(service_account_info)
            options = {}
            project_id = os.getenv("FIREBASE_PROJECT_ID") or service_account_info.get("project_id")
            if project_id:
                options["projectId"] = project_id
            firebase_app = firebase_admin.initialize_app(credential, options)
        firebase_auth.verify_id_token(token, app=firebase_app, check_revoked=True)
        return True
    except Exception as exc:
        logger.warning("firebase_auth_rejected error_type=%s", type(exc).__name__)
        return False


def require_api_access(request: Request) -> None:
    """Accept Firebase ID tokens when configured; otherwise retain the legacy bearer gate."""
    supplied = request.headers.get("authorization", "")
    prefix = "Bearer "
    token = supplied[len(prefix):] if supplied.startswith(prefix) else ""

    if os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON"):
        if not token or not _verify_firebase_id_token(token):
            raise HTTPException(status_code=401, detail="Valid Firebase ID token required", headers={"WWW-Authenticate": "Bearer"})
        return

    expected = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    production = os.getenv("APP_ENV", "development").strip().lower() == "production"
    if not expected:
        if production:
            raise HTTPException(status_code=503, detail="API authentication is not configured")
        return
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})

@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "packetwhisperer-ai", "version": __version__}

@app.get("/ready", tags=["operations"])
def ready() -> JSONResponse:
    production = os.getenv("APP_ENV", "development").strip().lower() == "production"
    token_configured = bool(os.getenv("PACKETWHISPERER_API_TOKEN", "") or os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", ""))
    if production and not token_configured:
        return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "API authentication is not configured"})
    return JSONResponse(content={"status": "ready"})

@app.get("/v1/demo/flows", tags=["demo"])
def demo_flows() -> JSONResponse:
    """Return deterministic analysis of a fixed synthetic fixture; accepts no uploads."""
    flows = parse_flows(DEMO_FLOW_CSV)
    report = analyze_flows(flows)
    report["evidence"] = {
        "sha256": hashlib.sha256(DEMO_FLOW_CSV).hexdigest(),
        "filename": "demo-flows.csv",
        "bytes_received": len(DEMO_FLOW_CSV),
        "format": "network-flow-csv",
        "synthetic": True,
    }
    return JSONResponse(content=report)



# Separate bounded fixture so the original public demo remains stable.
# Both scan patterns are synthetic and deliberately use documentation-only IP ranges.
DEMO_SCAN_CSV = (
    "src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\\n"
    + "".join(
        f"10.0.0.50,192.0.2.{index},52000,22,TCP,512,3,0.1\\n"
        for index in range(1, 22)
    )
    + "".join(
        f"10.0.0.60,198.51.100.10,{53000 + port},{port},TCP,512,3,0.1\\n"
        for port in range(1, 22)
    )
).encode("utf-8")


@app.get("/v1/demo/scan-patterns", tags=["demo"])
def demo_scan_patterns() -> JSONResponse:
    """Return deterministic analysis of fixed synthetic horizontal and vertical scan patterns."""
    flows = parse_flows(DEMO_SCAN_CSV)
    report = analyze_flows(flows)
    report["evidence"] = {
        "sha256": hashlib.sha256(DEMO_SCAN_CSV).hexdigest(),
        "filename": "synthetic-scan-patterns.csv",
        "bytes_received": len(DEMO_SCAN_CSV),
        "format": "network-flow-csv",
        "synthetic": True,
    }
    return JSONResponse(content=report)


@app.post("/v1/analyze/flows", tags=["analysis"], dependencies=[Depends(require_api_access)])
async def analyze_upload(file: UploadFile = File(...)) -> JSONResponse:
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Upload a .csv network-flow file")
    if file.content_type not in ("text/csv", "application/csv", "application/vnd.ms-excel", "application/octet-stream", None):
        raise HTTPException(status_code=415, detail="Unsupported content type; expected CSV")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 10 MiB limit")
    try:
        flows = parse_flows(raw)
    except FlowValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report = analyze_flows(flows)
    report["evidence"] = {"sha256": hashlib.sha256(raw).hexdigest(), "filename": filename, "bytes_received": len(raw), "format": "network-flow-csv"}
    logger.info("analysis_complete flow_count=%d findings=%d evidence_sha256=%s", report["flow_count"], report["findings_count"], report["evidence"]["sha256"])
    return JSONResponse(content=report)

@app.post("/v1/analyze/pcap", tags=["analysis"], dependencies=[Depends(require_api_access)])
async def analyze_capture(file: UploadFile = File(...)) -> JSONResponse:
    """Analyze offline PCAP/PCAPNG packet metadata; never enable live capture."""
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=415, detail="Upload a .pcap, .pcapng, or .cap capture")
    raw = await file.read(MAX_CAPTURE_BYTES + 1)
    await file.close()
    if len(raw) > MAX_CAPTURE_BYTES:
        raise HTTPException(status_code=413, detail="Capture exceeds the 20 MiB upload limit")
    try:
        report = analyze_pcap(raw)
    except CaptureValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report["evidence"] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "filename": filename,
        "bytes_received": len(raw),
        "format": "pcap-or-pcapng",
    }
    logger.info(
        "pcap_analysis_complete packets=%d findings=%d evidence_sha256=%s",
        report["capture"]["packets_analyzed"],
        report["findings_count"],
        report["evidence"]["sha256"],
    )
    return JSONResponse(content=report)


@app.exception_handler(Exception)
async def unexpected_error_handler(request, exc: Exception):
    logger.exception("unhandled_api_error path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
