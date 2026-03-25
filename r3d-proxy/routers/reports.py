"""Report generation endpoints — PDF and HTML reports from session data."""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from core.audit import audit_log
from core.auth import verify_api_key
from core.config import DEFAULT_MODEL
from core.llm import acompletion
from core.db import get_sessions_col
from reports.generator import generate_report

router = APIRouter(prefix="/r3d/report", tags=["reports"])


class ReportRequest(BaseModel):
    type: str = "executive"
    format: str = "pdf"


@router.get("/templates", dependencies=[Depends(verify_api_key)])
async def list_templates():
    """List available report templates."""
    return {
        "ok": True,
        "templates": [
            {"id": "executive", "name": "Executive Summary", "description": "2-page C-suite overview with risk score, top findings, and recommendations"},
            {"id": "technical", "name": "Technical Findings", "description": "Full finding details with CWE references, evidence, and remediation"},
            {"id": "compliance", "name": "Compliance Assessment", "description": "GDPR, PCI-DSS, SOC2, HIPAA compliance matrix"},
            {"id": "narrative", "name": "Engagement Narrative", "description": "Timeline-based red team attack story with exploitation attempts"},
        ],
    }


@router.post("/generate/{sid}", dependencies=[Depends(verify_api_key)])
async def generate(sid: str, body: ReportRequest, request: Request):
    """Generate a PDF or HTML report for a session."""
    col = get_sessions_col(request)
    session = await col.find_one({"_id": sid})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session["id"] = session.pop("_id")

    # Fetch graph if available
    graph = None
    g_col = request.app.state.graphs_col
    if g_col is not None:
        graph = await g_col.find_one({"_id": f"graph-{sid}"})

    # AI summary for executive/narrative reports
    ai_summary = {}
    if body.type in ("executive", "narrative", "compliance"):
        findings_preview = []
        for ev in session.get("events", [])[:30]:
            if ev.get("type") in ("finding", "imported_finding"):
                findings_preview.append(ev.get("data", {}))

        if findings_preview:
            prompt = (
                f"Summarize these {len(findings_preview)} security findings for a {body.type} report.\n\n"
                f"Findings: {json.dumps(findings_preview, default=str)[:4000]}\n\n"
                "Return valid JSON with: executiveSummary, businessImpact, hardeningRecs (array), "
                "complianceGaps (array of {{framework, gap}}), attackVectors (array of {{vector, test}})"
            )
            try:
                resp = await acompletion(
                    model=DEFAULT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are R3D, an offensive security intelligence system generating engagement reports."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                )
                ai_summary = json.loads(resp.choices[0].message.content or "{}")
            except Exception:
                pass

    content, media_type = generate_report(
        session=session,
        report_type=body.type,
        output_format=body.format,
        graph=graph,
        ai_summary=ai_summary,
    )

    await audit_log(request, "report.generate", sid, {"type": body.type, "format": body.format})

    filename = f"r3d-{sid}-{body.type}.{'pdf' if body.format == 'pdf' else 'html'}"

    if isinstance(content, bytes):
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
