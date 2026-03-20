"""Scan orchestrator and parameter fuzzer."""

import asyncio
import uuid as _uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import now
from core.opsec import throttle
from core.replay import get_http_client, payload_meta, payloads
from core.sse import broadcast
from core.vault import CredentialVault
from core import state

router = APIRouter(prefix="/r3d/scan", tags=["scans"])

# ─── Request Models ──────────────────────────────────────────────────


class ScanRunRequest(BaseModel):
    sessionId: str = ""
    probes: list[dict] = []
    useAuthContext: bool = True


class FuzzRequest(BaseModel):
    sessionId: str = ""
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str | None = None
    paramPositions: list[dict] = []
    payloadSets: list[str] = []
    useAuthContext: bool = True
    maxRequests: int = 500


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/run", dependencies=[Depends(verify_api_key)])
async def scan_run(body: ScanRunRequest, request: Request):
    """Execute a list of probe tasks against target endpoints."""
    scan_id = str(_uuid.uuid4())[:8]
    scan = {
        "scanId": scan_id, "sessionId": body.sessionId,
        "status": "running", "total": len(body.probes),
        "completed": 0, "results": [], "startedAt": now().isoformat(),
    }
    state.active_scans[scan_id] = scan

    async def _run():
        for i, probe in enumerate(body.probes):
            await throttle()
            try:
                url = probe.get("url", "")
                method = probe.get("method", "GET")
                origin = ""
                try:
                    p = urlparse(url)
                    origin = f"{p.scheme}://{p.netloc}"
                except Exception:
                    pass
                vault: CredentialVault = request.app.state.credential_vault
                headers = probe.get("headers", {})
                if body.useAuthContext:
                    headers = await vault.get_replay_headers(origin, headers)

                async with get_http_client(timeout=10, follow_redirects=True) as client:
                    resp = await client.request(
                        method=method, url=url, headers=headers,
                        content=probe.get("body", "").encode() if probe.get("body") else None,
                    )
                result = {
                    "probeIndex": i, "url": url, "method": method,
                    "status": resp.status_code,
                    "bodyPreview": resp.text[:2000], "bodyLength": len(resp.text),
                    "headers": {k: v for k, v in resp.headers.items()
                                if k.lower() in ("content-type", "content-security-policy",
                                                  "access-control-allow-origin", "location",
                                                  "set-cookie", "x-frame-options",
                                                  "strict-transport-security")},
                    "elapsed_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0,
                    "findingId": probe.get("findingId", ""),
                    "findingTitle": probe.get("findingTitle", ""),
                    "payload": probe.get("payload", ""),
                }
                ev = probe.get("expectedVulnerable", "")
                es = probe.get("expectedSafe", "")
                if ev and ev.lower() in resp.text.lower():
                    result["verdict"] = "vulnerable"
                elif es and es.lower() in resp.text.lower():
                    result["verdict"] = "safe"
                else:
                    result["verdict"] = "inconclusive"
                scan["results"].append(result)
            except Exception as exc:
                scan["results"].append({
                    "probeIndex": i, "url": probe.get("url", ""),
                    "error": str(exc), "verdict": "error",
                })
            scan["completed"] = i + 1
            broadcast("scan_progress", {
                "scanId": scan_id, "completed": i + 1, "total": scan["total"],
                "latest": scan["results"][-1] if scan["results"] else None,
            })

        scan["status"] = "complete"
        scan["completedAt"] = now().isoformat()
        broadcast("scan_complete", {
            "scanId": scan_id,
            "results": scan["results"],
            "vulnerable": sum(1 for r in scan["results"] if r.get("verdict") == "vulnerable"),
        })

    asyncio.create_task(_run())
    return {"ok": True, "scanId": scan_id, "total": len(body.probes)}


@router.post("/fuzz", dependencies=[Depends(verify_api_key)])
async def scan_fuzz(body: FuzzRequest, request: Request):
    """Parameter fuzzing — mutate parameters with payload libraries."""
    scan_id = str(_uuid.uuid4())[:8]
    payload_list: list[str] = []
    for pset in body.payloadSets:
        payload_list.extend(payloads.get(pset, []))
    if not payload_list:
        payload_list = ["'", "\"", "<script>alert(1)</script>", "{{7*7}}",
                        "../../../etc/passwd", "; ls", "' OR '1'='1"]
    total = min(len(payload_list) * max(len(body.paramPositions), 1), body.maxRequests)
    scan = {
        "scanId": scan_id, "sessionId": body.sessionId,
        "status": "running", "total": total, "completed": 0,
        "results": [], "anomalies": [], "startedAt": now().isoformat(),
    }
    state.active_scans[scan_id] = scan

    async def _run():
        origin = ""
        try:
            p = urlparse(body.url)
            origin = f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        vault: CredentialVault = request.app.state.credential_vault
        headers = body.headers.copy()
        if body.useAuthContext:
            headers = await vault.get_replay_headers(origin, headers)

        baseline = None
        try:
            async with get_http_client(timeout=10) as c:
                r = await c.request(method=body.method, url=body.url, headers=headers,
                                    content=body.body.encode() if body.body else None)
                baseline = {"status": r.status_code, "length": len(r.text),
                            "elapsed": r.elapsed.total_seconds() * 1000 if r.elapsed else 0}
        except Exception:
            pass

        count = 0
        for param in (body.paramPositions or [{"name": "q", "position": "query"}]):
            for payload in payload_list:
                await throttle()
                if count >= body.maxRequests:
                    break
                try:
                    fuzz_url, fuzz_body, fuzz_h = body.url, body.body, headers.copy()
                    pos = param.get("position", "query")
                    name = param.get("name", "")
                    original = param.get("original", "")

                    if pos == "query":
                        sep = "&" if "?" in fuzz_url else "?"
                        fuzz_url = f"{fuzz_url}{sep}{name}={payload}"
                    elif pos == "path" and original:
                        fuzz_url = fuzz_url.replace(original, payload)
                    elif pos == "body" and fuzz_body and original:
                        fuzz_body = fuzz_body.replace(original, payload)
                    elif pos == "header":
                        fuzz_h[name] = payload

                    async with get_http_client(timeout=10) as c:
                        r = await c.request(method=body.method, url=fuzz_url, headers=fuzz_h,
                                            content=fuzz_body.encode() if fuzz_body else None)
                    result = {
                        "index": count, "param": name, "position": pos,
                        "payload": payload[:200], "status": r.status_code,
                        "bodyLength": len(r.text), "bodyPreview": r.text[:500],
                        "elapsed_ms": r.elapsed.total_seconds() * 1000 if r.elapsed else 0,
                    }
                    if baseline:
                        s_diff = result["status"] != baseline["status"]
                        l_ratio = abs(result["bodyLength"] - baseline["length"]) / max(baseline["length"], 1)
                        t_ratio = (result["elapsed_ms"] / max(baseline["elapsed"], 1)
                                   if baseline["elapsed"] > 0 else 1)
                        is_anomaly = s_diff or l_ratio > 0.3 or t_ratio > 3
                        result["anomaly"] = is_anomaly
                        if is_anomaly:
                            reasons = []
                            if s_diff:
                                reasons.append(f"status {baseline['status']}->{result['status']}")
                            if l_ratio > 0.3:
                                reasons.append(f"length {int(l_ratio*100)}% diff")
                            if t_ratio > 3:
                                reasons.append(f"timing {t_ratio:.1f}x slower")
                            result["anomalyReasons"] = reasons
                            scan["anomalies"].append(result)
                    scan["results"].append(result)
                except Exception as exc:
                    scan["results"].append({
                        "index": count, "param": name,
                        "payload": payload[:200], "error": str(exc),
                    })
                count += 1
                scan["completed"] = count
                if count % 10 == 0:
                    broadcast("scan_progress", {
                        "scanId": scan_id, "completed": count,
                        "total": total, "anomalies": len(scan["anomalies"]),
                    })

        scan["status"] = "complete"
        scan["completedAt"] = now().isoformat()
        broadcast("scan_complete", {
            "scanId": scan_id, "anomalies": scan["anomalies"], "totalProbes": count,
        })

    asyncio.create_task(_run())
    return {"ok": True, "scanId": scan_id, "total": total}


@router.get("/status/{scan_id}", dependencies=[Depends(verify_api_key)])
async def scan_status(scan_id: str):
    """Get current status of a running or completed scan."""
    scan = state.active_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/payloads", dependencies=[Depends(verify_api_key)])
async def list_payloads():
    """List available payload libraries with metadata."""
    result = {}
    for name, plist in payloads.items():
        meta = payload_meta.get(name, {})
        result[name] = {
            "count": len(plist),
            **meta,
        }
    return result
