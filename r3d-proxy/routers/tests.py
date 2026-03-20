"""Test execution relay — queue tests for the extension and receive results."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import OPEN_CORS_HEADERS, now
from core.opsec import get_profile
from core.sse import broadcast
from core import state

router = APIRouter(prefix="/r3d", tags=["tests"])

# ─── Request Models ──────────────────────────────────────────────────


class TestRunRequest(BaseModel):
    snippet: str
    curlCommand: str | None = None
    findingTitle: str = ""
    findingId: str = ""
    sessionId: str = ""
    targetOrigin: str = ""
    testId: str | None = None


class TestExecutingRequest(BaseModel):
    testId: str
    tabId: int | None = None
    executedOn: str = ""


class TestOutputRequest(BaseModel):
    testId: str
    line: str


class TestResultRequest(BaseModel):
    testId: str
    success: bool
    output: str = ""
    error: str | None = None
    executedOn: str = ""
    tabId: int | None = None


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/test/run", dependencies=[Depends(verify_api_key)])
async def queue_test(body: TestRunRequest):
    """Queue a test for the extension to pick up and execute."""
    test_id = body.testId or f"test_{datetime.now(timezone.utc).strftime('%H%M%S')}_{id(body) % 10000}"
    test = {
        "testId": test_id,
        "snippet": body.snippet,
        "curlCommand": body.curlCommand,
        "findingTitle": body.findingTitle,
        "findingId": body.findingId,
        "sessionId": body.sessionId,
        "targetOrigin": body.targetOrigin,
        "status": "queued",
        "ts": now().isoformat(),
    }
    state.pending_tests[test_id] = test
    state.test_log[test_id] = test.copy()
    broadcast("run_test", test)
    return {"ok": True, "testId": test_id}


@router.get("/test/pending", dependencies=[Depends(verify_api_key)])
async def get_pending_tests():
    """Extension polls this to pick up queued tests."""
    tests = list(state.pending_tests.values())
    state.pending_tests.clear()
    for t in tests:
        if t["testId"] in state.test_log:
            state.test_log[t["testId"]]["status"] = "dispatched"
    return tests


@router.post("/test/executing", dependencies=[Depends(verify_api_key)])
async def report_test_executing(body: TestExecutingRequest):
    """Extension reports that it has picked up a test and is now executing it."""
    data = {
        "testId": body.testId,
        "tabId": body.tabId,
        "executedOn": body.executedOn,
        "ts": now().isoformat(),
    }
    if body.testId in state.test_log:
        state.test_log[body.testId]["status"] = "executing"
    broadcast("test_executing", data)
    return {"ok": True}


@router.post("/test/output", dependencies=[Depends(verify_api_key)])
async def report_test_output(body: TestOutputRequest):
    """Extension streams individual console lines as the test runs."""
    data = {
        "testId": body.testId,
        "line": body.line[:2000],
        "ts": now().isoformat(),
    }
    broadcast("test_output", data)
    return {"ok": True}


@router.post("/test/result", dependencies=[Depends(verify_api_key)])
async def report_test_result(body: TestResultRequest, request: Request):
    """Extension reports test execution results. Persists to session if available."""
    result_data = {
        "testId": body.testId,
        "success": body.success,
        "output": body.output,
        "error": body.error,
        "executedOn": body.executedOn,
        "tabId": body.tabId,
        "ts": now().isoformat(),
    }

    marker = get_profile().test_marker
    verdict = "error"
    if body.error:
        verdict = "error"
    elif f"{marker} VULNERABLE" in (body.output or "") or "VULNERABLE" in (body.output or ""):
        verdict = "vulnerable"
    elif f"{marker} SAFE" in (body.output or "") or "SAFE" in (body.output or ""):
        verdict = "safe"
    else:
        verdict = "inconclusive"
    result_data["verdict"] = verdict

    if body.testId in state.test_log:
        state.test_log[body.testId]["status"] = "completed"
        state.test_log[body.testId]["result"] = result_data

    session_id = state.test_log.get(body.testId, {}).get("sessionId")
    if session_id and request.app.state.sessions_col is not None:
        col = request.app.state.sessions_col
        artifact = {
            "type": "test_artifact",
            "ts": int(datetime.now(timezone.utc).timestamp() * 1000),
            "data": {
                "testId": body.testId,
                "findingTitle": state.test_log.get(body.testId, {}).get("findingTitle", ""),
                "findingId": state.test_log.get(body.testId, {}).get("findingId", ""),
                "targetOrigin": state.test_log.get(body.testId, {}).get("targetOrigin", ""),
                "executedOn": body.executedOn,
                "verdict": verdict,
                "output": (body.output or "")[:2000],
                "error": body.error,
                "snippet": (state.test_log.get(body.testId, {}).get("snippet", ""))[:3000],
            },
        }
        try:
            await col.update_one(
                {"_id": session_id},
                {"$push": {"events": artifact}, "$inc": {"eventCount": 1}},
            )
        except Exception:
            pass

    broadcast("test_result", result_data)
    return {"ok": True}


@router.api_route("/test/beacon", methods=["GET", "POST", "OPTIONS"], dependencies=[Depends(verify_api_key)])
async def test_beacon(request: Request):
    """Universal test beacon — snippets fire at this to prove exfil channels work.

    Accepts any method/body. Logs the receipt and broadcasts via SSE so the
    dashboard can confirm the data arrived. CORS is wide open on purpose.
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode(errors="replace")[:2000] if body_bytes else ""
    params = dict(request.query_params)
    broadcast("beacon_received", {
        "method": request.method,
        "body": body_str,
        "params": params,
        "origin": request.headers.get("origin", ""),
        "ts": now().isoformat(),
    })
    return JSONResponse(
        content={"ok": True, "received": len(body_bytes)},
        headers=OPEN_CORS_HEADERS,
    )
