"""HTTP API for PacketWhisperer AI flow analysis."""
from __future__ import annotations

import hashlib
import logging
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from packetwhisperer import __version__
from packetwhisperer.analyzer import FlowValidationError, analyze_flows, parse_flows
from packetwhisperer.pcap_analyzer import CaptureValidationError, MAX_CAPTURE_BYTES, analyze_pcap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packetwhisperer")
app = FastAPI(title="PacketWhisperer AI", version=__version__, description="Explainable network-flow analysis API. Findings are heuristic investigation leads, not proof of compromise.", docs_url="/docs", redoc_url="/redoc")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "packetwhisperer-ai", "version": __version__}

@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    return {"status": "ready"}

@app.post("/v1/analyze/flows", tags=["analysis"])
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

@app.post("/v1/analyze/pcap", tags=["analysis"])
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
