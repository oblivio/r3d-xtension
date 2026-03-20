"""Auth context push/retrieve and encrypted credential vault."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from core.auth import verify_api_key
from core.vault import CredentialVault

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

    Credentials are encrypted via CSFLE and stored in MongoDB. No in-memory
    cache is kept — credentials are decrypted on-demand per request.
    """
    vault: CredentialVault = request.app.state.credential_vault
    await vault.store(body.origin, body.cookies, body.headers, body.userAgent)
    return {"ok": True}


@router.get("/auth-context/{origin:path}", dependencies=[Depends(verify_api_key)])
async def get_auth_context(origin: str, request: Request):
    """Dashboard retrieves auth context for a given origin.

    Credentials are decrypted on-demand from CSFLE-encrypted storage.
    """
    vault: CredentialVault = request.app.state.credential_vault
    ctx = await vault.get_context(origin)
    return {"ok": True, "origin": origin, "context": ctx}


@router.get("/credentials", dependencies=[Depends(verify_api_key)])
async def list_credentials(request: Request):
    """List credential metadata without decrypting full credentials.

    Returns metadata (origins, timestamp) but not the actual credentials,
    which are only decrypted on-demand when needed.
    """
    vault: CredentialVault = request.app.state.credential_vault
    origins = await vault.list_origins()
    return {"ok": True, "credentials": origins, "csfle": request.app.state.csfle_info}


@router.delete("/credentials/{origin:path}", dependencies=[Depends(verify_api_key)])
async def delete_credentials(origin: str, request: Request):
    """Delete stored credentials for an origin."""
    vault: CredentialVault = request.app.state.credential_vault
    deleted = await vault.delete(origin)
    return {"ok": True, "deleted": deleted}
