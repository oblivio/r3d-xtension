"""Auth context push/retrieve and encrypted credential vault."""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import now
from core.replay import auth_contexts

router = APIRouter(prefix="/r3d", tags=["auth-context"])

# ─── Request Models ──────────────────────────────────────────────────


class AuthContextRequest(BaseModel):
    origin: str
    cookies: str = ""
    headers: dict = {}
    userAgent: str = ""


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/auth-context", dependencies=[Depends(verify_api_key)])
async def push_auth_context(body: AuthContextRequest, request: Request):
    """Extension pushes auth context for an origin so attack helpers can use it.

    Also persists to the encrypted r3d_credentials collection (CSFLE) so
    credentials survive proxy restarts.
    """
    auth_contexts[body.origin] = {
        "cookies": body.cookies,
        "headers": body.headers,
        "userAgent": body.userAgent,
        "ts": now().isoformat(),
    }
    creds = getattr(request.app.state, "credentials_col", None)
    if creds is not None:
        try:
            await creds.delete_many({"origin": body.origin})
            await creds.insert_one({
                "origin": body.origin,
                "cookies": body.cookies,
                "headers_json": json.dumps(body.headers),
                "userAgent": body.userAgent,
                "capturedAt": now(),
            })
        except Exception:
            pass
    return {"ok": True}


@router.get("/auth-context/{origin:path}", dependencies=[Depends(verify_api_key)])
async def get_auth_context(origin: str):
    """Dashboard retrieves auth context for a given origin."""
    ctx = auth_contexts.get(origin, {})
    return {"ok": True, "origin": origin, "context": ctx}


@router.get("/credentials", dependencies=[Depends(verify_api_key)])
async def list_credentials(request: Request):
    """List all persisted auth credentials (auto-decrypted by CSFLE)."""
    creds = getattr(request.app.state, "credentials_col", None)
    if creds is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    results = []
    async for doc in creds.find().sort("capturedAt", -1).limit(100):
        doc["id"] = str(doc.pop("_id"))
        if isinstance(doc.get("capturedAt"), datetime):
            doc["capturedAt"] = doc["capturedAt"].isoformat()
        results.append(doc)
    return {"ok": True, "credentials": results, "csfle": request.app.state.csfle_info}


@router.delete("/credentials/{origin:path}", dependencies=[Depends(verify_api_key)])
async def delete_credentials(origin: str, request: Request):
    """Delete stored credentials for an origin."""
    creds = getattr(request.app.state, "credentials_col", None)
    if creds is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    result = await creds.delete_many({"origin": origin})
    auth_contexts.pop(origin, None)
    return {"ok": True, "deleted": result.deleted_count}
