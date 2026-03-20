"""Dashboard, health, SSE stream, extension heartbeat, and handshake."""

import asyncio
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel

from core.audit import audit_log
from core.auth import create_access_token, verify_api_key
from core.config import DEFAULT_MODEL, R3D_API_KEY, now
from core.db import serialize_dates
from core.security_monitor import track_event
from core.sse import broadcast, subscribers
from core import state

router = APIRouter(tags=["dashboard"])
_DASHBOARD_HTML_PATH = Path(__file__).parent.parent / "static" / "index.html"

# ─── Request Models ──────────────────────────────────────────────────


class ExtensionHeartbeat(BaseModel):
    sessionId: str | None = None
    sessionName: str | None = None
    sessionState: str | None = None
    pendingEvents: int = 0
    counters: dict = {}


class HandshakeRequest(BaseModel):
    extensionId: str


# ─── Handshake Security ──────────────────────────────────────────────

# Rate limiting state: {ip: [(timestamp, timestamp, ...)]}
_handshake_attempts: dict[str, list[float]] = defaultdict(list)
_HANDSHAKE_RATE_LIMIT = 5  # Max attempts per minute
_HANDSHAKE_WINDOW = 60  # seconds


def _rate_limit_handshake(ip: str):
    """Enforce sliding window rate limit for handshake attempts.

    Allows max 5 attempts per minute per IP address. This prevents
    credential harvesting via brute-force handshake abuse.
    """
    now_ts = datetime.now(timezone.utc).timestamp()
    attempts = _handshake_attempts[ip]

    # Remove expired attempts (older than 1 minute)
    _handshake_attempts[ip] = [ts for ts in attempts if now_ts - ts < _HANDSHAKE_WINDOW]

    if len(_handshake_attempts[ip]) >= _HANDSHAKE_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {_HANDSHAKE_RATE_LIMIT} handshake attempts per minute.",
        )

    _handshake_attempts[ip].append(now_ts)


def _validate_extension_id(extension_id: str):
    """Validate extension ID against allowlist.

    In production, set R3D_ALLOWED_EXTENSION_IDS to your published extension ID.
    Development accepts "*" wildcard.
    """
    allowed_ids = os.environ.get("R3D_ALLOWED_EXTENSION_IDS", "*")
    if allowed_ids == "*":
        return  # Development mode

    allowed_list = [e.strip() for e in allowed_ids.split(",")]
    if extension_id not in allowed_list:
        raise HTTPException(
            status_code=403,
            detail="Extension ID not authorized. Contact administrator to whitelist your extension.",
        )


# ─── Helpers ─────────────────────────────────────────────────────────


def _is_extension_connected() -> bool:
    last = state.extension_heartbeat.get("lastSeen")
    if not last:
        return False
    try:
        dt = datetime.fromisoformat(last)
        return (datetime.now(timezone.utc) - dt).total_seconds() < 15
    except Exception:
        return False


def _dashboard_build() -> str:
    try:
        stamp = _DASHBOARD_HTML_PATH.stat().st_mtime_ns
    except FileNotFoundError:
        stamp = 0
    return f"5.3.0-{stamp}"


# ─── Endpoints ───────────────────────────────────────────────────────


@router.get("/health")
async def health(request: Request):
    """Health check endpoint.

    Unauthenticated requests only receive minimal status info. Authenticated
    requests receive full system details including MongoDB, CSFLE, and model config.

    This prevents information disclosure to potential attackers probing the system.
    """
    # Try to verify API key without raising on failure
    try:
        await verify_api_key(request)
        authenticated = True
    except Exception:
        authenticated = False

    if not authenticated:
        return {"status": "ok"}

    return {
        "status": "ok",
        "version": "5.3.0",
        "mongodb": "connected" if request.app.state.sessions_col is not None else "not configured",
        "csfle": getattr(request.app.state, "csfle_info", {"status": "disabled"}),
        "default_model": DEFAULT_MODEL,
        "auth": "enabled" if R3D_API_KEY else "disabled",
    }


@router.get("/r3d/dashboard/bootstrap", dependencies=[Depends(verify_api_key)])
async def dashboard_bootstrap(request: Request):
    """Single call for the dashboard to get everything it needs on first load."""
    col = request.app.state.sessions_col
    mongo_ok = col is not None

    total_sessions = 0
    active_sessions = 0
    total_findings = 0
    total_events = 0
    latest_session = None

    if mongo_ok:
        try:
            total_sessions = await col.count_documents({})
            active_sessions = await col.count_documents({"endedAt": None})

            pipeline = [
                {"$group": {
                    "_id": None,
                    "totalEvents": {"$sum": "$eventCount"},
                    "totalFindings": {"$sum": {"$ifNull": ["$summary.totalFindings", 0]}},
                }}
            ]
            cursor = await col.aggregate(pipeline)
            async for agg in cursor:
                total_events = agg.get("totalEvents", 0)
                total_findings = agg.get("totalFindings", 0)

            latest_doc = await col.find_one(
                {}, {"_id": 1, "name": 1, "startedAt": 1, "endedAt": 1, "eventCount": 1, "summary": 1},
                sort=[("startedAt", -1)],
            )
            if latest_doc:
                serialize_dates(latest_doc)
                latest_session = {
                    "id": latest_doc["_id"],
                    "name": latest_doc.get("name", ""),
                    "startedAt": latest_doc.get("startedAt"),
                    "endedAt": latest_doc.get("endedAt"),
                    "eventCount": latest_doc.get("eventCount", 0),
                    "riskLevel": (latest_doc.get("summary") or {}).get("riskLevel", "UNKNOWN"),
                }
        except Exception as exc:
            print(f"Bootstrap DB error: {exc}")

    if not mongo_ok:
        reason = "mongo_unavailable"
    elif total_sessions == 0:
        reason = "no_sessions"
    else:
        reason = "ok"

    return {
        "status": reason,
        "health": {
            "version": "5.3.0",
            "mongodb": "connected" if mongo_ok else "not configured",
            "csfle": getattr(request.app.state, "csfle_info", {"status": "disabled"}),
            "model": DEFAULT_MODEL,
            "auth": "enabled" if R3D_API_KEY else "disabled",
        },
        "stats": {
            "totalSessions": total_sessions,
            "activeSessions": active_sessions,
            "totalFindings": total_findings,
            "totalEvents": total_events,
        },
        "latestSession": latest_session,
        "extension": {
            "connected": _is_extension_connected(),
            "lastSeen": state.extension_heartbeat.get("lastSeen"),
            "sessionState": state.extension_heartbeat.get("sessionState"),
            "pendingEvents": state.extension_heartbeat.get("pendingEvents", 0),
        },
        "dashboardBuild": _dashboard_build(),
    }


@router.get("/r3d/dashboard/version")
async def dashboard_version(request: Request):
    """Expose dashboard version and build info (authenticated only).

    Prevents version disclosure to unauthenticated attackers.
    """
    try:
        await verify_api_key(request)
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication required")

    return {"build": _dashboard_build(), "version": "5.3.0"}


@router.post("/r3d/extension/heartbeat", dependencies=[Depends(verify_api_key)])
async def extension_heartbeat(body: ExtensionHeartbeat):
    """Lightweight ping from the Chrome extension so the dashboard knows it's alive."""
    state.extension_heartbeat["lastSeen"] = datetime.now(timezone.utc).isoformat()
    state.extension_heartbeat["sessionId"] = body.sessionId
    state.extension_heartbeat["sessionName"] = body.sessionName
    state.extension_heartbeat["sessionState"] = body.sessionState
    state.extension_heartbeat["pendingEvents"] = body.pendingEvents
    state.extension_heartbeat["counters"] = body.counters
    return {"ok": True}


@router.get("/r3d/security/metrics", dependencies=[Depends(verify_api_key)])
async def security_metrics():
    """Internal security metrics (authenticated only, not exposed externally)."""
    from core.security_monitor import get_security_metrics
    return get_security_metrics()


@router.get("/r3d/extension/status", dependencies=[Depends(verify_api_key)])
async def extension_status():
    """Dashboard reads this to know if the extension is connected."""
    last = state.extension_heartbeat.get("lastSeen")
    connected = False
    if last:
        try:
            dt = datetime.fromisoformat(last)
            connected = (datetime.now(timezone.utc) - dt).total_seconds() < 15
        except Exception:
            pass
    return {
        "connected": connected,
        **state.extension_heartbeat,
    }


_LOCALHOST_ADDRS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


@router.post("/r3d/handshake")
async def handshake(body: HandshakeRequest, request: Request):
    """Secure extension handshake — mints short-lived JWT tokens.

    Security measures:
      1. POST-only (prevents CSRF)
      2. Extension ID validation (pinned to published extension ID in production)
      3. Rate limiting (5 attempts per minute per IP)
      4. Audit logging (all attempts, success + failure)
      5. JWT minting (24h expiry, never transmits master API key)
      6. Localhost-only (prevents remote exploitation)

    The extension must send its chrome.runtime.id for validation. In production,
    set R3D_ALLOWED_EXTENSION_IDS to your published extension ID to prevent
    sideloaded/rogue extensions from obtaining credentials.

    Returns a short-lived JWT token instead of the master R3D_API_KEY. This
    limits the blast radius of a compromised token and enables revocation.
    """
    client_host = request.client.host if request.client else ""

    # Security monitoring
    track_event("handshake_attempt", ip=client_host, detail={"extensionId": body.extensionId})

    # Localhost-only enforcement
    if client_host not in _LOCALHOST_ADDRS:
        track_event("handshake_denied", ip=client_host, detail={"reason": "non_localhost"})
        await audit_log(request, "handshake_denied", "localhost_check_failed", {
            "extensionId": body.extensionId,
            "reason": "non_localhost_connection",
        })
        raise HTTPException(status_code=403, detail="Handshake only available from localhost")

    # Rate limiting
    try:
        _rate_limit_handshake(client_host)
    except HTTPException as e:
        track_event("rate_limit_hit", ip=client_host, detail={"endpoint": "handshake"})
        await audit_log(request, "handshake_denied", "rate_limit_exceeded", {
            "extensionId": body.extensionId,
        })
        raise e

    # Extension ID validation
    try:
        _validate_extension_id(body.extensionId)
    except HTTPException as e:
        track_event("handshake_denied", ip=client_host, detail={"reason": "invalid_extension_id"})
        await audit_log(request, "handshake_denied", "extension_id_rejected", {
            "extensionId": body.extensionId,
        })
        raise e

    # Mint short-lived JWT (24 hours)
    token = create_access_token(
        user_id="extension",
        username="extension",
        role="operator",
        expires_minutes=1440,  # 24 hours
    )

    await audit_log(request, "handshake_success", "token_issued", {
        "extensionId": body.extensionId,
        "tokenExpiry": "24h",
    })

    return {
        "ok": True,
        "token": token,
        "endpoint": "/v1/chat/completions",
        "version": "5.3.0",
        "mongodb": "connected" if request.app.state.sessions_col is not None else "not configured",
    }


@router.get("/r3d/stream", dependencies=[Depends(verify_api_key)])
async def event_stream():
    """Server-Sent Events stream for real-time dashboard updates."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=256)
    subscribers.append(queue)

    async def generate():
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                data = await queue.get()
                yield f"data: {data}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/login")
async def login_page():
    """Serve the login page."""
    return HTMLResponse("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>R3D — Login</title>
<style>
body{margin:0;background:#0a0a0f;color:#c8c8d0;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#0f0f1a;border:1px solid #1e1e32;border-radius:8px;padding:32px;width:320px}
h1{font-family:'SF Mono',monospace;color:#ff1744;font-size:20px;margin:0 0 24px;text-align:center}
label{display:block;font-size:12px;color:#666680;margin-bottom:4px;font-family:'SF Mono',monospace}
input{width:100%;padding:10px;margin-bottom:16px;background:#08081a;border:1px solid #1e1e32;border-radius:4px;color:#e8e8f0;font-size:14px;box-sizing:border-box}
input:focus{outline:none;border-color:#ff1744}
button{width:100%;padding:10px;background:#ff1744;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:700;cursor:pointer}
button:hover{background:#d50000}
.error{color:#ff1744;font-size:12px;text-align:center;margin-bottom:12px;display:none}
</style></head><body>
<div class="card">
<h1>R3D</h1>
<div class="error" id="err"></div>
<form id="form">
<label>Username</label><input name="username" autocomplete="username" required>
<label>Password</label><input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign In</button>
</form>
</div>
<script>
document.getElementById('form').onsubmit=async e=>{
  e.preventDefault();const d=new FormData(e.target);
  const r=await fetch('/r3d/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:d.get('username'),password:d.get('password')})});
  if(r.ok){window.location.href='/';}
  else{const j=await r.json();const el=document.getElementById('err');el.textContent=j.detail||'Login failed';el.style.display='block';}
};
</script></body></html>""")


@router.get("/")
async def root():
    """Serve dashboard with session JWT cookie (not master API key).

    Issues a short-lived JWT token for dashboard authentication. The master
    R3D_API_KEY never leaves the server.
    """
    html_path = _DASHBOARD_HTML_PATH
    if html_path.exists():
        content = html_path.read_text().replace("__R3D_DASHBOARD_BUILD__", _dashboard_build())
        response = HTMLResponse(content)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # Mint a session JWT instead of transmitting the master API key
        if R3D_API_KEY:
            session_token = create_access_token(
                user_id="dashboard",
                username="dashboard",
                role="operator",
                expires_minutes=60,  # 1 hour for dashboard sessions
            )
            response.set_cookie(
                key="r3d_session",
                value=session_token,
                httponly=True,
                samesite="strict",
                path="/",
                max_age=3600,  # 1 hour
            )
        return response
    return RedirectResponse(url="/static/index.html")
