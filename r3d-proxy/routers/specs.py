"""OpenAPI / Swagger spec import, coverage diff, and auto-scan."""

import json
import uuid as _uuid
from datetime import datetime

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import now
from core.replay import get_http_client
from core.sse import broadcast
from core import state
from routers.scans import ScanRunRequest, scan_run

router = APIRouter(prefix="/r3d", tags=["specs"])

# ─── Request Models ──────────────────────────────────────────────────


class SpecImportRequest(BaseModel):
    url: str | None = None
    content: str | None = None
    format: str = "json"
    name: str = ""
    sessionId: str = ""


# ─── Helpers ─────────────────────────────────────────────────────────


def _parse_openapi_spec(raw: str, fmt: str = "json") -> dict:
    if fmt in ("yaml", "yml"):
        return yaml.safe_load(raw)
    return json.loads(raw)


def _extract_endpoints(spec: dict) -> list[dict]:
    endpoints = []
    base_path = spec.get("basePath", "")
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        full_path = f"{base_path}{path}" if base_path else path
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "head", "options"):
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("type") or p.get("schema", {}).get("type", "string"),
                    })

                req_body = details.get("requestBody", {})
                body_schema = {}
                if req_body:
                    content = req_body.get("content", {})
                    for _ct, ct_detail in content.items():
                        body_schema = ct_detail.get("schema", {})
                        break

                sensitive_flags = []
                all_param_names = [p["name"].lower() for p in params]
                if any(n in all_param_names for n in ("redirect_uri", "url", "callback", "next", "return_url")):
                    sensitive_flags.append("ssrf_candidate")
                if any(n in all_param_names for n in ("redirect_uri", "return_url", "next", "continue")):
                    sensitive_flags.append("open_redirect_candidate")
                if "{id}" in path or "{user_id}" in path or "{uid}" in path:
                    sensitive_flags.append("idor_candidate")
                if any(n in all_param_names for n in ("password", "secret", "token", "ssn", "credit_card")):
                    sensitive_flags.append("sensitive_data")

                auth_required = bool(details.get("security")) or bool(spec.get("security"))

                endpoints.append({
                    "path": full_path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "operationId": details.get("operationId", ""),
                    "parameters": params,
                    "bodySchema": body_schema,
                    "authRequired": auth_required,
                    "tags": details.get("tags", []),
                    "sensitiveFlags": sensitive_flags,
                })

    return endpoints


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/spec/import", dependencies=[Depends(verify_api_key)])
async def import_spec(body: SpecImportRequest, request: Request):
    """Import an OpenAPI/Swagger specification."""
    raw = ""
    if body.url:
        async with get_http_client(timeout=15) as c:
            resp = await c.get(body.url)
            raw = resp.text
    elif body.content:
        raw = body.content
    else:
        raise HTTPException(status_code=400, detail="Provide url or content")

    try:
        spec = _parse_openapi_spec(raw, body.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse spec: {e}")

    endpoints = _extract_endpoints(spec)
    spec_id = str(_uuid.uuid4())[:8]
    doc = {
        "_id": spec_id,
        "name": body.name or spec.get("info", {}).get("title", "Unnamed"),
        "version": spec.get("info", {}).get("version", ""),
        "sessionId": body.sessionId,
        "importedAt": now(),
        "endpointCount": len(endpoints),
        "endpoints": endpoints,
        "servers": [s.get("url", "") for s in spec.get("servers", [])],
        "basePath": spec.get("basePath", ""),
        "sensitiveEndpoints": [e for e in endpoints if e.get("sensitiveFlags")],
    }

    col = request.app.state.specs_col
    if col is not None:
        await col.insert_one(doc)
    else:
        state.active_scans[f"spec-{spec_id}"] = doc

    broadcast("spec_imported", {
        "specId": spec_id, "name": doc["name"],
        "endpointCount": len(endpoints),
        "sensitiveCount": len(doc["sensitiveEndpoints"]),
    })
    return {"ok": True, "specId": spec_id, "name": doc["name"],
            "endpointCount": len(endpoints), "endpoints": endpoints}


@router.post("/spec/upload", dependencies=[Depends(verify_api_key)])
async def upload_spec(request: Request, file: UploadFile = File(...)):
    """Upload an OpenAPI spec file (JSON or YAML)."""
    raw = (await file.read()).decode(errors="replace")
    fmt = "yaml" if file.filename and file.filename.endswith((".yml", ".yaml")) else "json"
    try:
        spec = _parse_openapi_spec(raw, fmt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse spec: {e}")

    endpoints = _extract_endpoints(spec)
    spec_id = str(_uuid.uuid4())[:8]
    doc = {
        "_id": spec_id,
        "name": spec.get("info", {}).get("title", file.filename or "Unnamed"),
        "version": spec.get("info", {}).get("version", ""),
        "importedAt": now(),
        "endpointCount": len(endpoints),
        "endpoints": endpoints,
        "servers": [s.get("url", "") for s in spec.get("servers", [])],
        "basePath": spec.get("basePath", ""),
        "sensitiveEndpoints": [e for e in endpoints if e.get("sensitiveFlags")],
    }
    col = request.app.state.specs_col
    if col is not None:
        await col.insert_one(doc)

    return {"ok": True, "specId": spec_id, "name": doc["name"],
            "endpointCount": len(endpoints), "endpoints": endpoints}


@router.get("/spec/{spec_id}/endpoints", dependencies=[Depends(verify_api_key)])
async def get_spec_endpoints(spec_id: str, request: Request):
    """List endpoints from an imported spec."""
    col = request.app.state.specs_col
    if col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    doc = await col.find_one({"_id": spec_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Spec not found")
    doc["id"] = doc.pop("_id")
    if isinstance(doc.get("importedAt"), datetime):
        doc["importedAt"] = doc["importedAt"].isoformat()
    return doc


@router.get("/specs", dependencies=[Depends(verify_api_key)])
async def list_specs(request: Request):
    """List all imported API specs."""
    col = request.app.state.specs_col
    if col is None:
        return []
    cursor = col.find({}, {"endpoints": 0}).sort("importedAt", -1).limit(50)
    specs = []
    async for doc in cursor:
        doc["id"] = doc.pop("_id")
        if isinstance(doc.get("importedAt"), datetime):
            doc["importedAt"] = doc["importedAt"].isoformat()
        specs.append(doc)
    return specs


@router.post("/spec/{spec_id}/diff", dependencies=[Depends(verify_api_key)])
async def diff_spec_coverage(spec_id: str, request: Request):
    """Compare spec endpoints against observed session requests."""
    col = request.app.state.specs_col
    s_col = request.app.state.sessions_col
    if col is None or s_col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    spec_doc = await col.find_one({"_id": spec_id})
    if not spec_doc:
        raise HTTPException(status_code=404, detail="Spec not found")

    sid = spec_doc.get("sessionId", "")
    observed_urls: set[str] = set()
    if sid:
        session = await s_col.find_one({"_id": sid}, {"events": 1})
        if session:
            for ev in session.get("events", []):
                if ev.get("type") == "request":
                    url = ev.get("data", {}).get("url", "")
                    if url:
                        observed_urls.add(url)

    coverage = []
    for ep in spec_doc.get("endpoints", []):
        path_pattern = ep["path"]
        method = ep["method"]
        matched = any(
            path_pattern.split("{")[0] in u and method == "GET"
            for u in observed_urls
        ) if observed_urls else False
        coverage.append({
            **ep,
            "observed": matched,
            "status": "tested" if matched else "untested",
        })

    tested = sum(1 for c in coverage if c["observed"])
    return {
        "specId": spec_id,
        "totalEndpoints": len(coverage),
        "tested": tested,
        "untested": len(coverage) - tested,
        "coveragePercent": round(tested / max(len(coverage), 1) * 100, 1),
        "endpoints": coverage,
    }


@router.post("/spec/{spec_id}/scan", dependencies=[Depends(verify_api_key)])
async def scan_from_spec(spec_id: str, request: Request):
    """Auto-generate and run scan probes from untested spec endpoints."""
    col = request.app.state.specs_col
    if col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    spec_doc = await col.find_one({"_id": spec_id})
    if not spec_doc:
        raise HTTPException(status_code=404, detail="Spec not found")

    servers = spec_doc.get("servers", [])
    base_url = servers[0] if servers else "http://localhost"
    base_url = base_url.rstrip("/")

    probes = []
    for ep in spec_doc.get("endpoints", []):
        url = f"{base_url}{ep['path']}"
        probe = {
            "url": url, "method": ep["method"],
            "findingTitle": f"Spec scan: {ep['method']} {ep['path']}",
        }

        for flag in ep.get("sensitiveFlags", []):
            if flag == "idor_candidate":
                probe["payload"] = "IDOR probe"
                probe["expectedVulnerable"] = "user"
            elif flag == "ssrf_candidate":
                probe["payload"] = "SSRF probe"
            elif flag == "open_redirect_candidate":
                probe["payload"] = "redirect probe"

        probes.append(probe)

    body = ScanRunRequest(sessionId=spec_doc.get("sessionId", ""), probes=probes, useAuthContext=True)
    return await scan_run(body)
