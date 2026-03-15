"""Auth-context capture and credential replay helpers."""

import json
from pathlib import Path

import httpx

from core.config import SSL_VERIFY

auth_contexts: dict[str, dict] = {}

payloads: dict[str, list[str]] = {}
payload_meta: dict[str, dict] = {}


def load_payloads():
    payload_dir = Path(__file__).parent.parent / "payloads"
    if not payload_dir.is_dir():
        return
    for f in payload_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, dict) and "payloads" in data:
                payloads[f.stem] = data["payloads"]
                payload_meta[f.stem] = {
                    k: v for k, v in data.items() if k != "payloads"
                }
            elif isinstance(data, list):
                payloads[f.stem] = data
        except Exception:
            pass


def get_http_client(**kwargs) -> httpx.AsyncClient:
    """Return an httpx client that respects the global SSL_VERIFY setting."""
    kwargs.setdefault("verify", SSL_VERIFY)
    return httpx.AsyncClient(**kwargs)


def get_replay_headers(origin: str, extra_headers: dict | None = None) -> dict:
    """Merge stored auth context headers with any request-specific headers.

    If OPSEC UA rotation is enabled and no stored User-Agent exists,
    a rotated UA is injected automatically.
    """
    from core.opsec import get_profile, get_user_agent, sanitize_outbound_headers

    ctx = auth_contexts.get(origin, {})
    h: dict[str, str] = {}
    if ctx.get("cookies"):
        h["Cookie"] = ctx["cookies"]
    if ctx.get("userAgent"):
        h["User-Agent"] = ctx["userAgent"]
    for k, v in (ctx.get("headers") or {}).items():
        if k.lower() not in ("host", "content-length", "content-type"):
            h[k] = v
    if extra_headers:
        h.update(extra_headers)

    profile = get_profile()
    if "User-Agent" not in h:
        rotated = get_user_agent(profile)
        if rotated:
            h["User-Agent"] = rotated

    return sanitize_outbound_headers(h, profile)
