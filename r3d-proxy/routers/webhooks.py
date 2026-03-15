"""Webhook registration and delivery."""

from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import now
from core import state

router = APIRouter(prefix="/r3d/hooks", tags=["webhooks"])

# ─── Request Models ──────────────────────────────────────────────────


class WebhookConfigRequest(BaseModel):
    url: str
    events: list[str] = ["session_end", "critical_finding"]
    name: str = ""


# ─── Helpers ─────────────────────────────────────────────────────────


async def fire_webhooks(event_type: str, payload: dict):
    """Fire registered webhooks for an event type."""
    for hook in state.webhooks:
        if event_type in hook.get("events", []):
            try:
                async with httpx.AsyncClient(timeout=5) as c:
                    await c.post(hook["url"], json={
                        "type": event_type, "ts": now().isoformat(), **payload,
                    })
            except Exception:
                pass


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/configure", dependencies=[Depends(verify_api_key)])
async def configure_webhook(body: WebhookConfigRequest):
    """Register a webhook URL for event notifications."""
    import uuid as _uuid
    hook = {
        "id": str(_uuid.uuid4())[:8],
        "url": body.url,
        "events": body.events,
        "name": body.name or urlparse(body.url).hostname or "webhook",
        "createdAt": now().isoformat(),
    }
    state.webhooks.append(hook)
    return {"ok": True, "webhook": hook}


@router.get("", dependencies=[Depends(verify_api_key)])
async def list_webhooks():
    """List configured webhooks."""
    return state.webhooks


@router.delete("/{hook_id}", dependencies=[Depends(verify_api_key)])
async def delete_webhook(hook_id: str):
    """Remove a webhook."""
    for i, h in enumerate(state.webhooks):
        if h["id"] == hook_id:
            state.webhooks.pop(i)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Webhook not found")
