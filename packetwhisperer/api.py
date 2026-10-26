"""HTTP API for PacketWhisperer AI flow analysis."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from packetwhisperer import __version__
from packetwhisperer.analyzer import FlowValidationError, analyze_flows, parse_flows
from packetwhisperer.pcap_analyzer import (
    CaptureValidationError,
    MAX_CAPTURE_BYTES,
    analyze_pcap,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packetwhisperer")
app = FastAPI(
    title="PacketWhisperer AI",
    version=__version__,
    description=(
        "Explainable network-flow analysis API. Findings are heuristic "
        "investigation leads, not proof of compromise."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Multipart boundaries and form fields need some overhead beyond the file.
MAX_MULTIPART_OVERHEAD = 256 * 1024
MIN_PRODUCTION_TOKEN_BYTES = 32


def _production_mode() -> bool:
    return os.getenv("APP_ENV", "development").strip().lower() == "production"


def _token_configuration_error() -> str | None:
    """Return a safe, non-secret configuration error for production mode."""
    token = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    if not token:
        return "API authentication is not configured"
    if len(token.encode("utf-8")) < MIN_PRODUCTION_TOKEN_BYTES:
        return f"API token must be at least {MIN_PRODUCTION_TOKEN_BYTES} bytes"
    return None


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Reject oversized declared requests before Starlette parses multipart data.
    # The bounded file reads below remain necessary for requests without a
    # trustworthy Content-Length header.
    if request.url.path == "/v1/analyze/flows":
        request_limit = MAX_UPLOAD_BYTES + MAX_MULTIPART_OVERHEAD
    elif request.url.path == "/v1/analyze/pcap":
        request_limit = MAX_CAPTURE_BYTES + MAX_MULTIPART_OVERHEAD
    else:
        request_limit = None

    if request_limit is not None:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared_length < 0:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared_length > request_limit:
                return JSONResponse(status_code=413, content={"detail": "Request exceeds upload limit"})

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if request.url.path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def require_api_access(request: Request) -> None:
    """Require bearer auth when configured; fail closed in production."""
    expected = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    if _production_mode():
        config_error = _token_configuration_error()
        if config_error:
            raise HTTPException(status_code=503, detail=config_error)
    if not expected:
        return

    supplied = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not supplied.startswith(prefix) or not hmac.compare_digest(
        supplied[len(prefix):], expected
    ):
        raise HTTPException(
            status_code=401,
            detail="Valid bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    """Liveness only; does not imply the service is configured for production."""
    return {"status": "ok", "service": "packetwhisperer-ai", "version": __version__}


@app.get("/ready", tags=["operations"])
def ready() -> JSONResponse:
    """Readiness fails closed if production authentication is unsafe."""
    if _production_mode():
        config_error = _token_configuration_error()
        if config_error:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": config_error},
            )
    return JSONResponse(content={"status": "ready"})


@app.post(
    "/v1/analyze/flows",
    tags=["analysis"],
    dependencies=[Depends(require_api_access)],
)
async def analyze_upload(file: UploadFile = File(...)) -> JSONResponse:
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith(".csv"):
        await file.close()
        raise HTTPException(status_code=415, detail="Upload a .csv network-flow file")
    if file.content_type not in (
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "application/octet-stream",
        None,
    ):
        await file.close()
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
    report["evidence"] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "filename": filename,
        "bytes_received": len(raw),
        "format": "network-flow-csv",
    }
    logger.info(
        "analysis_complete flow_count=%d findings=%d evidence_sha256=%s",
        report["flow_count"],
        report["findings_count"],
        report["evidence"]["sha256"],
    )
    return JSONResponse(content=report)


@app.post(
    "/v1/analyze/pcap",
    tags=["analysis"],
    dependencies=[Depends(require_api_access)],
)
async def analyze_capture(file: UploadFile = File(...)) -> JSONResponse:
    """Analyze offline PCAP/PCAPNG packet metadata; never enable live capture."""
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        await file.close()
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
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.exception("unhandled_api_error path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
