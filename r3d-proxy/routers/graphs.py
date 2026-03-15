"""Attack graph — build, retrieve, pathfinding, and AI enrichment."""

import json

import litellm
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import DEFAULT_MODEL, now
from core.db import get_sessions_col
from core.sse import broadcast
from graph_builder import build_graph_from_session, find_all_attack_paths

router = APIRouter(prefix="/r3d/graph", tags=["graphs"])

# ─── Request Models ──────────────────────────────────────────────────


class PathQueryRequest(BaseModel):
    source: str | None = None
    target: str | None = None
    maxDepth: int = 8
    minConfidence: str | None = None


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/build/{sid}", dependencies=[Depends(verify_api_key)])
async def build_graph(sid: str, request: Request):
    """Build an attack graph from session data."""
    col = get_sessions_col(request)
    doc = await col.find_one({"_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    graph = build_graph_from_session(doc)
    paths = find_all_attack_paths(graph)
    graph_dict = graph.to_dict()
    graph_dict["_id"] = f"graph-{sid}"
    graph_dict["paths"] = paths
    graph_dict["builtAt"] = now().isoformat()

    g_col = request.app.state.graphs_col
    if g_col is not None:
        await g_col.replace_one({"_id": graph_dict["_id"]}, graph_dict, upsert=True)

    graph_dict["id"] = graph_dict.pop("_id")
    broadcast("graph_built", {
        "sessionId": sid,
        "nodeCount": len(graph_dict.get("nodes", [])),
        "edgeCount": len(graph_dict.get("edges", [])),
        "pathCount": len(paths),
    })
    return graph_dict


@router.get("/{sid}", dependencies=[Depends(verify_api_key)])
async def get_graph(sid: str, request: Request):
    """Retrieve the attack graph for a session."""
    g_col = request.app.state.graphs_col
    if g_col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    doc = await g_col.find_one({"_id": f"graph-{sid}"})
    if not doc:
        raise HTTPException(status_code=404, detail="Graph not found — build it first via POST /r3d/graph/build/{sid}")
    doc["id"] = doc.pop("_id")
    return doc


@router.post("/{sid}/paths", dependencies=[Depends(verify_api_key)])
async def find_graph_paths(sid: str, body: PathQueryRequest, request: Request):
    """Find attack paths between specific nodes in the graph."""
    col = get_sessions_col(request)
    doc = await col.find_one({"_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    graph = build_graph_from_session(doc)

    if body.source and body.target:
        raw_paths = graph.find_paths(body.source, body.target,
                                     max_depth=body.maxDepth,
                                     min_confidence=body.minConfidence)
        paths = [graph.path_risk(p) for p in raw_paths]
        paths.sort(key=lambda x: (-x["riskScore"], x["length"]))
    else:
        paths = find_all_attack_paths(graph, max_depth=body.maxDepth,
                                      min_confidence=body.minConfidence)

    return {"sessionId": sid, "paths": paths, "count": len(paths)}


@router.post("/{sid}/enrich", dependencies=[Depends(verify_api_key)])
async def enrich_graph(sid: str, request: Request):
    """AI-enrich the attack graph with additional edges and path analysis."""
    g_col = request.app.state.graphs_col
    if g_col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    doc = await g_col.find_one({"_id": f"graph-{sid}"})
    if not doc:
        raise HTTPException(status_code=404, detail="Build graph first")

    nodes = doc.get("nodes", [])[:40]
    edges = doc.get("edges", [])[:80]
    paths = doc.get("paths", [])[:15]

    cwe_groups: dict[str, int] = {}
    for n in nodes:
        if n.get("type") == "vulnerability" and n.get("cwe"):
            cwe_groups[n["cwe"]] = cwe_groups.get(n["cwe"], 0) + 1
    cwe_context = ", ".join(f"{cwe} ({ct}x)" for cwe, ct in sorted(cwe_groups.items(), key=lambda x: -x[1])[:10])

    graph_summary = json.dumps({"nodes": nodes, "edges": edges, "paths": paths}, default=str)

    prompt = (
        "You are R3D. Analyze this attack graph from a security engagement "
        "of internal SaaS applications.\n\n"
        f"GRAPH DATA:\n{graph_summary}\n\n"
        + (f"CWE BREAKDOWN: {cwe_context}\n\n" if cwe_context else "")
        + "Return valid JSON with ALL of these keys:\n\n"
        '"additionalEdges" — array of {from, to, label, confidence} objects. '
        "Infer implicit trust relationships, shared SSO providers, lateral movement paths, "
        "and shared cookie domains between systems.\n\n"
        '"attackPaths" — array of {name, steps: [node IDs], risk: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", description} '
        "with concrete step-by-step exploitation instructions.\n\n"
        '"crownJewels" — array of {nodeId, reasoning} identifying the highest-value targets '
        "and why an attacker would prioritize them.\n\n"
        '"fixPriority" — ordered array of objects, each with:\n'
        '  "action" — a plain English remediation step (e.g. "Tighten CSP on hr.internal.example.com to remove unsafe-inline")\n'
        '  "reasoning" — why this fix matters for risk reduction\n'
        '  "severity" — "CRITICAL", "HIGH", "MEDIUM", or "LOW"\n'
        "IMPORTANT: The action field MUST be a human-readable remediation instruction. "
        "Do NOT put raw edge objects, node IDs, or JSON structures in the action field. "
        "Write it as you would in a security report for a CISO.\n\n"
        '"executiveSummary" — 2-3 sentence overview of the attack surface, '
        "key risk, and recommended immediate action.\n\n"
        "EXAMPLE fixPriority item (follow this format exactly):\n"
        '{"action": "Deploy Content-Security-Policy with strict-dynamic on hr.internal.example.com", '
        '"reasoning": "Removes the primary XSS entry point that enables credential theft and lateral movement", '
        '"severity": "CRITICAL"}'
    )

    try:
        response = await litellm.acompletion(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are R3D, an offensive security intelligence system."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        enrichment = json.loads(content)

        doc["enrichment"] = enrichment
        doc["enrichedAt"] = now().isoformat()
        await g_col.replace_one({"_id": doc["_id"]}, doc, upsert=True)

        doc["id"] = doc.pop("_id")
        return {"ok": True, "enrichment": enrichment, "graph": doc}
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})
