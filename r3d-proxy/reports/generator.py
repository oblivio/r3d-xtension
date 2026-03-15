"""Report generation engine — produces HTML or PDF reports from session data."""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)

REPORT_TYPES = ("executive", "technical", "compliance", "narrative")


def _extract_findings(session: dict) -> list[dict]:
    findings = []
    for ev in session.get("events", []):
        if ev.get("type") in ("finding", "imported_finding"):
            findings.append(ev.get("data", {}))
    return findings


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _extract_systems(session: dict) -> list[dict]:
    systems: dict[str, dict] = {}
    for ev in session.get("events", []):
        if ev.get("type") == "request":
            sid = ev.get("data", {}).get("systemId")
            if sid and sid not in systems:
                systems[sid] = {
                    "id": sid,
                    "name": ev.get("data", {}).get("systemName", sid),
                }
    return list(systems.values())


def _extract_test_results(session: dict) -> list[dict]:
    results = []
    for ev in session.get("events", []):
        if ev.get("type") == "test_artifact":
            results.append(ev.get("data", {}))
    return results


def build_report_context(
    session: dict,
    report_type: str,
    graph: dict | None = None,
    ai_summary: dict | None = None,
) -> dict[str, Any]:
    """Assemble the template context from session data."""
    findings = _extract_findings(session)
    sev_counts = _severity_counts(findings)
    systems = _extract_systems(session)
    tests = _extract_test_results(session)
    summary = session.get("summary", {}) or {}

    overall_risk = summary.get("overallRisk", 0)
    if not overall_risk:
        if sev_counts["CRITICAL"] > 0:
            overall_risk = 90
        elif sev_counts["HIGH"] > 0:
            overall_risk = 70
        elif sev_counts["MEDIUM"] > 0:
            overall_risk = 45
        else:
            overall_risk = 20

    return {
        "report_type": report_type,
        "session_id": session.get("id") or session.get("_id", ""),
        "session_name": session.get("name", "Unnamed Session"),
        "started_at": session.get("startedAt", ""),
        "ended_at": session.get("endedAt", ""),
        "scope": session.get("scope", []),
        "created_by": session.get("createdBy", "unknown"),
        "notes": session.get("notes", ""),
        "findings": findings,
        "finding_count": len(findings),
        "severity_counts": sev_counts,
        "overall_risk": overall_risk,
        "systems": systems,
        "system_count": len(systems),
        "tests": tests,
        "test_count": len(tests),
        "graph": graph,
        "ai_summary": ai_summary or {},
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "critical_findings": [f for f in findings if f.get("severity") == "CRITICAL"],
        "high_findings": [f for f in findings if f.get("severity") == "HIGH"],
    }


def render_html(report_type: str, context: dict) -> str:
    """Render a report as HTML string."""
    template_name = f"{report_type}.html"
    try:
        tmpl = _env.get_template(template_name)
    except Exception:
        tmpl = _env.get_template("executive.html")
    return tmpl.render(**context)


def render_pdf(html_content: str) -> bytes:
    """Convert rendered HTML to PDF bytes via WeasyPrint."""
    from weasyprint import HTML
    buf = io.BytesIO()
    HTML(string=html_content, base_url=str(TEMPLATES_DIR)).write_pdf(buf)
    return buf.getvalue()


def generate_report(
    session: dict,
    report_type: str = "executive",
    output_format: str = "pdf",
    graph: dict | None = None,
    ai_summary: dict | None = None,
) -> tuple[bytes | str, str]:
    """Generate a report and return (content, media_type).

    Returns HTML string or PDF bytes depending on output_format.
    """
    if report_type not in REPORT_TYPES:
        report_type = "executive"

    ctx = build_report_context(session, report_type, graph, ai_summary)
    html = render_html(report_type, ctx)

    if output_format == "html":
        return html, "text/html"

    pdf_bytes = render_pdf(html)
    return pdf_bytes, "application/pdf"
