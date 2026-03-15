"""Tool integration — Burp Suite import/export, Nuclei run/import, SARIF export."""

import asyncio
import json
import uuid as _uuid
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import now
from core.db import get_sessions_col
from core.sse import broadcast
from core import state

router = APIRouter(prefix="/r3d", tags=["tools"])

# ─── Constants ───────────────────────────────────────────────────────

_BURP_SEVERITY_MAP = {
    "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW",
    "Information": "INFO", "False positive": "INFO",
}
_BURP_CONFIDENCE_MAP = {
    "Certain": "high", "Firm": "high", "Tentative": "medium",
}

# ─── Request Models ──────────────────────────────────────────────────


class NucleiRunRequest(BaseModel):
    targets: list[str] = []
    tags: list[str] = []
    templates: list[str] = []
    severity: str = ""
    useAuthContext: bool = True
    sessionId: str = ""


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/tools/burp/import", dependencies=[Depends(verify_api_key)])
async def import_burp(request: Request):
    """Import Burp Suite XML export (issues format)."""
    raw = (await request.body()).decode(errors="replace")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML: {e}")

    findings = []
    for issue in root.iter("issue"):
        finding = {
            "type": "imported_finding",
            "source": "burp",
            "ts": int(now().timestamp() * 1000),
            "data": {
                "title": (issue.findtext("name") or "Burp finding").strip(),
                "severity": _BURP_SEVERITY_MAP.get(
                    (issue.findtext("severity") or "").strip(), "MEDIUM"),
                "confidence": _BURP_CONFIDENCE_MAP.get(
                    (issue.findtext("confidence") or "").strip(), "medium"),
                "url": (issue.findtext("host") or "") + (issue.findtext("path") or ""),
                "detail": (issue.findtext("issueDetail") or "").strip()[:2000],
                "remediation": (issue.findtext("remediationDetail") or "").strip()[:1000],
                "issueType": issue.findtext("type") or "",
                "status": "confirmed",
            },
        }
        findings.append(finding)

    broadcast("burp_imported", {"count": len(findings)})
    return {"ok": True, "imported": len(findings), "findings": findings}


@router.get("/tools/burp/export/{sid}", dependencies=[Depends(verify_api_key)])
async def export_burp(sid: str, request: Request):
    """Export session findings as Burp-compatible XML."""
    col = get_sessions_col(request)
    doc = await col.find_one({"_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    sev_reverse = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Information"}
    root = ET.Element("issues", burpVersion="2024.0", exportTime=now().isoformat())
    for ev in doc.get("events", []):
        if ev.get("type") not in ("finding", "imported_finding"):
            continue
        data = ev.get("data", {})
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "serialNumber").text = data.get("id", "")
        ET.SubElement(issue, "type").text = data.get("cwe", "0")
        ET.SubElement(issue, "name").text = data.get("title", "")
        ET.SubElement(issue, "host").text = data.get("url", "")
        ET.SubElement(issue, "path").text = ""
        ET.SubElement(issue, "severity").text = sev_reverse.get(data.get("severity", "MEDIUM"), "Medium")
        ET.SubElement(issue, "confidence").text = "Firm" if data.get("confidence") == "high" else "Tentative"
        ET.SubElement(issue, "issueDetail").text = data.get("detail", data.get("evidenceSummary", ""))

    xml_str = ET.tostring(root, encoding="unicode", xml_declaration=True)
    return StreamingResponse(
        iter([xml_str]),
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=r3d-{sid}.xml"},
    )


@router.post("/tools/nuclei/run", dependencies=[Depends(verify_api_key)])
async def run_nuclei(body: NucleiRunRequest):
    """Run Nuclei scanner against targets (requires nuclei binary in PATH)."""
    scan_id = str(_uuid.uuid4())[:8]
    scan = {
        "scanId": scan_id, "tool": "nuclei", "status": "running",
        "targets": body.targets, "results": [], "startedAt": now().isoformat(),
    }
    state.active_scans[scan_id] = scan

    async def _run():
        cmd = ["nuclei", "-jsonl", "-silent"]
        for t in body.targets:
            cmd.extend(["-u", t])
        if body.tags:
            cmd.extend(["-tags", ",".join(body.tags)])
        if body.severity:
            cmd.extend(["-severity", body.severity])
        for tmpl in body.templates:
            cmd.extend(["-t", tmpl])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            async for line in proc.stdout:
                try:
                    result = json.loads(line.decode())
                    scan["results"].append(result)
                    broadcast("nuclei_result", {
                        "scanId": scan_id,
                        "templateId": result.get("template-id", ""),
                        "name": result.get("info", {}).get("name", ""),
                        "severity": result.get("info", {}).get("severity", ""),
                        "matched": result.get("matched-at", ""),
                    })
                except json.JSONDecodeError:
                    pass
            await proc.wait()
            scan["status"] = "complete"
            scan["exitCode"] = proc.returncode
        except FileNotFoundError:
            scan["status"] = "error"
            scan["error"] = "nuclei binary not found in PATH"
        except Exception as exc:
            scan["status"] = "error"
            scan["error"] = str(exc)

        scan["completedAt"] = now().isoformat()
        broadcast("nuclei_complete", {
            "scanId": scan_id, "resultCount": len(scan["results"]),
            "status": scan["status"],
        })

    asyncio.create_task(_run())
    return {"ok": True, "scanId": scan_id}


@router.post("/tools/nuclei/import", dependencies=[Depends(verify_api_key)])
async def import_nuclei(request: Request):
    """Import Nuclei JSON-lines output."""
    raw = (await request.body()).decode(errors="replace")
    findings = []
    nuclei_sev = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "info": "INFO"}
    for line in raw.strip().split("\n"):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            info = r.get("info", {})
            findings.append({
                "type": "imported_finding",
                "source": "nuclei",
                "ts": int(now().timestamp() * 1000),
                "data": {
                    "title": info.get("name", r.get("template-id", "")),
                    "severity": nuclei_sev.get(info.get("severity", "").lower(), "MEDIUM"),
                    "url": r.get("matched-at", r.get("host", "")),
                    "detail": info.get("description", "")[:2000],
                    "templateId": r.get("template-id", ""),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "status": "confirmed",
                    "confidence": "high",
                },
            })
        except json.JSONDecodeError:
            pass

    broadcast("nuclei_imported", {"count": len(findings)})
    return {"ok": True, "imported": len(findings), "findings": findings}


# ─── SARIF Export ─────────────────────────────────────────────────────


@router.get("/export/sarif/{sid}", dependencies=[Depends(verify_api_key)])
async def export_sarif(sid: str, request: Request):
    """Export session findings as SARIF 2.1.0 JSON."""
    col = get_sessions_col(request)
    doc = await col.find_one({"_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    sev_level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                 "LOW": "note", "INFO": "note"}

    rules = {}
    results = []
    for ev in doc.get("events", []):
        if ev.get("type") not in ("finding", "imported_finding"):
            continue
        data = ev.get("data", {})
        cwe = data.get("cwe", "")
        rule_id = cwe or data.get("title", "unknown")[:50]

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": data.get("title", "")},
                "fullDescription": {"text": data.get("detail", data.get("title", ""))[:500]},
                "defaultConfiguration": {
                    "level": sev_level.get(data.get("severity", "MEDIUM"), "warning"),
                },
                "properties": {"severity": data.get("severity", "MEDIUM")},
            }
            if cwe:
                rules[rule_id]["properties"]["cwe"] = cwe

        result = {
            "ruleId": rule_id,
            "level": sev_level.get(data.get("severity", "MEDIUM"), "warning"),
            "message": {"text": data.get("title", "")},
            "locations": [],
        }
        url = data.get("url", "")
        if url:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {"uri": url},
                },
            })
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "R3D",
                    "version": "5.3.0",
                    "informationUri": "https://github.com/oblivio/r3d-xtension",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }

    return JSONResponse(
        content=sarif,
        headers={"Content-Disposition": f"attachment; filename=r3d-{sid}.sarif.json"},
    )
