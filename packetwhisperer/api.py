"""HTTP API for PacketWhisperer AI flow analysis."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from packetwhisperer import security_store as store

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
RATE_LIMIT = int(os.getenv("PACKETWHISPERER_RATE_LIMIT", "60"))
RATE_WINDOW_SECONDS = 60


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _session_secret() -> bytes:
    return (os.getenv("PACKETWHISPERER_SESSION_SECRET") or os.getenv("PACKETWHISPERER_API_TOKEN", "")).encode()


def _issue_session(actor: dict, ttl_seconds: int = 3600) -> str:
    payload = {"sub": actor["id"], "username": actor["username"], "role": actor["role"], "exp": int(time.time()) + ttl_seconds}
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return body + "." + _b64(hmac.new(_session_secret(), body.encode(), hashlib.sha256).digest())


def _session_actor(token: str) -> dict | None:
    if "." not in token or len(_session_secret()) < MIN_PRODUCTION_TOKEN_BYTES:
        return None
    body, signature = token.split(".", 1)
    expected = _b64(hmac.new(_session_secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload["exp"]) <= int(time.time()):
            return None
        actor = store.get_user(str(payload["sub"]))
        if not actor or actor["username"] != payload["username"] or actor["role"] != payload["role"]:
            return None
        return actor
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _actor_from_request(request: Request) -> dict | None:
    supplied = request.headers.get("authorization", "")
    if not supplied.startswith("Bearer "):
        return None
    token = supplied[7:]
    actor = _session_actor(token)
    if actor:
        return actor
    expected = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    if expected and hmac.compare_digest(token, expected):
        return {"id": "service-token", "username": "service-token", "role": "admin"}
    return None


def _require_roles(request: Request, roles: set[str]) -> dict:
    actor = _actor_from_request(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})
    if actor["id"] == "service-token":
        raise HTTPException(status_code=403, detail="Create an individual administrator account for identity and case-management operations")
    if actor["role"] not in roles:
        store.audit(actor, "authorization.denied", outcome="denied", details={"path": request.url.path})
        raise HTTPException(status_code=403, detail="Insufficient role")
    return actor


class LoginInput(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class BootstrapInput(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    bootstrap_token: str = Field(min_length=32, max_length=512)


class UserInput(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class CaseInput(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    severity: str = Field(default="medium", pattern="^(informational|low|medium|high|critical)$")
    summary: dict = Field(default_factory=dict)
    evidence_sha256: str | None = Field(default=None, pattern="^[a-fA-F0-9]{64}$")


class CaseStatusInput(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|closed)$")


def _production_mode() -> bool:
    return os.getenv("APP_ENV", "development").strip().lower() == "production"


def _token_configuration_error() -> str | None:
    """Return a safe, non-secret configuration error for production mode."""
    token = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    if not token:
        return "API authentication is not configured"
    if len(token.encode("utf-8")) < MIN_PRODUCTION_TOKEN_BYTES:
        return f"API token must be at least {MIN_PRODUCTION_TOKEN_BYTES} bytes"
    if len(_session_secret()) < MIN_PRODUCTION_TOKEN_BYTES:
        return f"Session signing secret must be at least {MIN_PRODUCTION_TOKEN_BYTES} bytes"
    return None


def _access_error(request: Request) -> tuple[int, str] | None:
    """Return an HTTP failure before multipart parsing when access is invalid."""
    expected = os.getenv("PACKETWHISPERER_API_TOKEN", "")
    if _production_mode():
        config_error = _token_configuration_error()
        if config_error:
            return 503, config_error
    supplied = request.headers.get("authorization", "")
    if supplied.startswith("Bearer "):
        token = supplied[7:]
        if _session_actor(token) is not None:
            return None
        if expected and hmac.compare_digest(token, expected):
            return None
    if not expected and not _production_mode():
        return None
    return 401, "Valid bearer token required"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Authenticate before Starlette parses multipart bodies. This prevents
    # unauthenticated clients from making the app spend resources parsing files.
    # The endpoint dependency repeats the check as defense in depth.
    is_analysis_upload = request.url.path in {
        "/v1/analyze/flows",
        "/v1/analyze/pcap",
    }
    response = None
    if is_analysis_upload:
        # Bound unauthenticated upload attempts before reading their bodies.
        client_ip = request.client.host if request.client else "unknown"
        if not store.allow_request(f"upload-preauth:{client_ip}", 30, RATE_WINDOW_SECONDS):
            response = JSONResponse(status_code=429, content={"detail": "Upload rate limit exceeded"}, headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
            store.audit(None, "upload.rate_limit.exceeded", outcome="denied", details={"path": request.url.path})
        else:
            failure = _access_error(request)
            if failure:
                status_code, detail = failure
                headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else {}
                store.audit(None, "authentication.denied", outcome="denied", details={"path": request.url.path, "status": status_code})
                response = JSONResponse(
                    status_code=status_code,
                    content={"detail": detail},
                    headers=headers,
                )

    # Reject oversized declared requests before multipart parsing. Bounded file
    # reads below remain necessary for requests without Content-Length.
    if response is None:
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
                    response = JSONResponse(
                        status_code=400, content={"detail": "Invalid Content-Length"}
                    )
                else:
                    if declared_length < 0:
                        response = JSONResponse(
                            status_code=400, content={"detail": "Invalid Content-Length"}
                        )
                    elif declared_length > request_limit:
                        response = JSONResponse(
                            status_code=413,
                            content={"detail": "Request exceeds upload limit"},
                        )

    # Enforce a hard streaming cap even when Content-Length is absent or
    # dishonest (for example, chunked transfer). Read at most limit + 1 bytes
    # before FastAPI/Starlette's multipart parser can spool the upload to disk.
    # The bounded body is replayed to downstream middleware via Request's cache.
    if response is None and is_analysis_upload:
        if request.url.path == "/v1/analyze/flows":
            body_limit = MAX_UPLOAD_BYTES + MAX_MULTIPART_OVERHEAD
        else:
            body_limit = MAX_CAPTURE_BYTES + MAX_MULTIPART_OVERHEAD
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > body_limit:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request exceeds upload limit"},
                )
                break
        if response is None:
            request._body = bytes(body)

    if response is None and request.url.path.startswith("/v1/"):
        actor = _actor_from_request(request)
        identity = actor["id"] if actor else (request.client.host if request.client else "unknown")
        if not store.allow_request(f"api:{identity}", RATE_LIMIT, RATE_WINDOW_SECONDS):
            response = JSONResponse(status_code=429, content={"detail": "Rate limit exceeded; retry shortly"}, headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
            store.audit(actor, "rate_limit.exceeded", outcome="denied", details={"path": request.url.path})
    if response is None:
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
    failure = _access_error(request)
    if failure:
        status_code, detail = failure
        headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else {}
        raise HTTPException(status_code=status_code, detail=detail, headers=headers)
    if _production_mode():
        actor = _actor_from_request(request)
        if actor is None:
            raise HTTPException(status_code=401, detail="Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})
        if actor["role"] == "viewer":
            raise HTTPException(status_code=403, detail="Analyst or administrator role required")


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



@app.post("/v1/auth/bootstrap", tags=["identity"])
def bootstrap_admin(payload: BootstrapInput) -> dict:
    """Create the first administrator once, using a deployment-only secret."""
    configured = os.getenv("PACKETWHISPERER_BOOTSTRAP_TOKEN", "")
    if not configured or not hmac.compare_digest(payload.bootstrap_token, configured):
        raise HTTPException(status_code=403, detail="Bootstrap is unavailable or token is invalid")
    if store.user_count() != 0:
        raise HTTPException(status_code=409, detail="Initial administrator already exists")
    try:
        actor = store.create_user(payload.username, payload.password, "admin")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.audit(actor, "identity.bootstrap", "user", actor["id"])
    return {"user": actor, "message": "Administrator created; remove the bootstrap secret from deployment configuration."}


@app.post("/v1/auth/login", tags=["identity"])
def login(payload: LoginInput, request: Request) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    if not store.allow_request(f"login:{client_ip}", 10, 300):
        raise HTTPException(status_code=429, detail="Too many login attempts; retry later", headers={"Retry-After": "300"})
    actor = store.authenticate_user(payload.username, payload.password)
    if not actor:
        store.audit(None, "identity.login", outcome="denied", details={"username": payload.username[:64]})
        raise HTTPException(status_code=401, detail="Invalid username or password")
    store.audit(actor, "identity.login", "user", actor["id"])
    return {"access_token": _issue_session(actor), "token_type": "bearer", "expires_in": 3600, "user": actor}


@app.post("/v1/admin/users", tags=["identity"])
def create_analyst(payload: UserInput, request: Request) -> dict:
    actor = _require_roles(request, {"admin"})
    try:
        user = store.create_user(payload.username, payload.password, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="Username already exists") from exc
        raise
    store.audit(actor, "identity.user.create", "user", user["id"], details={"role": user["role"]})
    return {"user": user}


@app.get("/v1/cases", tags=["cases"])
def cases(request: Request, limit: int = 50, offset: int = 0) -> dict:
    actor = _require_roles(request, {"admin", "analyst", "viewer"})
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(status_code=422, detail="limit must be 1-100 and offset non-negative")
    store.audit(actor, "case.list", "case", details={"limit": limit, "offset": offset})
    return {"items": store.list_cases(limit, offset), "limit": limit, "offset": offset}


@app.post("/v1/cases", tags=["cases"])
def case_create(payload: CaseInput, request: Request) -> dict:
    actor = _require_roles(request, {"admin", "analyst"})
    try:
        item = store.create_case(payload.title, payload.severity, payload.summary, payload.evidence_sha256, actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"case": item}


@app.patch("/v1/cases/{case_id}", tags=["cases"])
def case_update(case_id: str, payload: CaseStatusInput, request: Request) -> dict:
    actor = _require_roles(request, {"admin", "analyst"})
    item = store.update_case(case_id, payload.status, actor)
    if item is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": item}


@app.get("/v1/audit", tags=["audit"])
def audit_events(request: Request, limit: int = 100, offset: int = 0) -> dict:
    actor = _require_roles(request, {"admin"})
    if not 1 <= limit <= 200 or offset < 0:
        raise HTTPException(status_code=422, detail="limit must be 1-200 and offset non-negative")
    store.audit(actor, "audit.read", "audit_event", details={"limit": limit, "offset": offset})
    return {"items": store.list_audit(limit, offset), "limit": limit, "offset": offset}


@app.post(
    "/v1/analyze/flows",
    tags=["analysis"],
    dependencies=[Depends(require_api_access)],
)
async def analyze_upload(request: Request, file: UploadFile = File(...)) -> JSONResponse:
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
    store.audit(_actor_from_request(request), "analysis.complete", "evidence", report["evidence"]["sha256"], details={"flow_count": report["flow_count"], "findings_count": report["findings_count"]})
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
async def analyze_capture(request: Request, file: UploadFile = File(...)) -> JSONResponse:
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
    store.audit(_actor_from_request(request), "analysis.pcap.complete", "evidence", report["evidence"]["sha256"], details={"packets_analyzed": report["capture"]["packets_analyzed"], "findings_count": report["findings_count"]})
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
