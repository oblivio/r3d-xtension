"""OPSEC profile configuration and system introspection endpoints."""

from fastapi import APIRouter, Depends

from core.auth import verify_api_key
from core.opsec import OpsecProfile, get_profile, set_profile
from core.replay import payload_meta, payloads
from core import state

router = APIRouter(prefix="/r3d", tags=["opsec"])


@router.get("/opsec", dependencies=[Depends(verify_api_key)])
async def get_opsec():
    """Return the current OPSEC profile."""
    return {"ok": True, "profile": get_profile().model_dump()}


@router.post("/opsec/configure", dependencies=[Depends(verify_api_key)])
async def configure_opsec(body: OpsecProfile):
    """Set the global OPSEC profile."""
    set_profile(body)
    return {"ok": True, "profile": body.model_dump()}


@router.get("/detectors", dependencies=[Depends(verify_api_key)])
async def list_detectors():
    """List registered detectors (extension-side via heartbeat) and payload libraries."""
    ext_detectors = state.extension_heartbeat.get("counters", {}).get("detectors", [])

    payload_libs = []
    for name, plist in payloads.items():
        meta = payload_meta.get(name, {})
        payload_libs.append({
            "id": name,
            "name": meta.get("name", name),
            "version": meta.get("version", "1.0"),
            "description": meta.get("description", ""),
            "tags": meta.get("tags", []),
            "payloadCount": len(plist),
        })

    return {
        "ok": True,
        "extensionDetectors": ext_detectors,
        "payloadLibraries": payload_libs,
    }
