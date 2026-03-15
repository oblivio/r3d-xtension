"""Session CRUD — create, append events, end, rename, delete, list, get."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from pymongo.errors import DuplicateKeyError

from core.audit import audit_log
from core.auth import verify_api_key
from core.config import EVENT_OVERFLOW_THRESHOLD, now
from core.db import get_overflow_col, get_sessions_col, serialize_dates
from core.sse import broadcast

router = APIRouter(prefix="/r3d", tags=["sessions"])

# ─── Request Models ──────────────────────────────────────────────────


class StartSessionRequest(BaseModel):
    sessionId: str
    name: str | None = None
    notes: str = ""
    scope: list[str] = []
    aiEnabled: bool = False


class AppendEventsRequest(BaseModel):
    events: list[dict] = []


class EndSessionRequest(BaseModel):
    summary: dict = {}


class RenameSessionRequest(BaseModel):
    name: str


# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/sessions/start", dependencies=[Depends(verify_api_key)])
async def start_session(body: StartSessionRequest, request: Request):
    """Create a new monitoring session."""
    col = get_sessions_col(request)

    user = getattr(request.state, "user", None)
    doc = {
        "_id": body.sessionId,
        "name": body.name or f"Session {now().isoformat()}",
        "startedAt": now(),
        "endedAt": None,
        "status": "active",
        "notes": body.notes,
        "scope": body.scope,
        "aiEnabled": body.aiEnabled,
        "createdBy": user["username"] if user else "api-key",
        "events": [],
        "eventCount": 0,
        "summary": None,
    }

    try:
        await col.insert_one(doc)
    except DuplicateKeyError:
        await col.replace_one({"_id": body.sessionId}, doc, upsert=True)

    broadcast("session_start", {"sessionId": body.sessionId, "name": doc["name"]})
    await audit_log(request, "session.start", body.sessionId, {"name": doc["name"], "scope": body.scope})
    return {"ok": True, "sessionId": body.sessionId}


@router.post("/sessions/{sid}/events", dependencies=[Depends(verify_api_key)])
async def append_events(sid: str, body: AppendEventsRequest, request: Request):
    """Append buffered events to a session, spilling to overflow past the threshold."""
    col = get_sessions_col(request)
    if not body.events:
        return {"ok": True, "appended": 0}

    for ev in body.events:
        if "ts" in ev and isinstance(ev["ts"], (int, float)):
            ev["ts_iso"] = datetime.fromtimestamp(ev["ts"] / 1000, tz=timezone.utc).isoformat()

    session = await col.find_one({"_id": sid}, {"eventCount": 1})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    current_count = session.get("eventCount", 0)
    batch_size = len(body.events)

    if current_count < EVENT_OVERFLOW_THRESHOLD:
        await col.update_one(
            {"_id": sid},
            {
                "$push": {"events": {"$each": body.events}},
                "$inc": {"eventCount": batch_size},
            },
        )
    else:
        overflow = get_overflow_col(request)
        await overflow.insert_one({
            "sessionId": sid,
            "seq": current_count,
            "events": body.events,
        })
        await col.update_one(
            {"_id": sid},
            {"$inc": {"eventCount": batch_size}},
        )

    broadcast("events", {"sessionId": sid, "events": body.events, "count": batch_size})
    return {"ok": True, "appended": batch_size}


@router.post("/sessions/{sid}/flush", dependencies=[Depends(verify_api_key)])
async def flush_session(sid: str):
    """Acknowledge a flush (events are already persisted on /events)."""
    return {"ok": True}


@router.post("/sessions/{sid}/end", dependencies=[Depends(verify_api_key)])
async def end_session(sid: str, body: EndSessionRequest, request: Request):
    """End a session and store the summary."""
    col = get_sessions_col(request)

    result = await col.update_one(
        {"_id": sid},
        {"$set": {
            "endedAt": now(),
            "status": "ended",
            "summary": body.summary,
        }},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")

    broadcast("session_end", {"sessionId": sid, "summary": body.summary})
    await audit_log(request, "session.end", sid)
    return {"ok": True}


@router.patch("/sessions/{sid}", dependencies=[Depends(verify_api_key)])
async def rename_session(sid: str, body: RenameSessionRequest, request: Request):
    """Rename a session from the dashboard."""
    col = get_sessions_col(request)
    result = await col.update_one({"_id": sid}, {"$set": {"name": body.name}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    broadcast("session_rename", {"sessionId": sid, "name": body.name})
    return {"ok": True}


@router.delete("/sessions/{sid}", dependencies=[Depends(verify_api_key)])
async def delete_session(sid: str, request: Request):
    """Permanently delete a session and its associated data."""
    col = get_sessions_col(request)
    result = await col.delete_one({"_id": sid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    overflow = get_overflow_col(request)
    if overflow is not None:
        await overflow.delete_many({"sessionId": sid})
    g_col = request.app.state.graphs_col
    if g_col is not None:
        await g_col.delete_many({"sessionId": sid})
    broadcast("session_delete", {"sessionId": sid})
    await audit_log(request, "session.delete", sid)
    return {"ok": True}


@router.get("/sessions", dependencies=[Depends(verify_api_key)])
async def list_sessions(request: Request):
    """List all sessions, newest first."""
    col = get_sessions_col(request)
    cursor = col.find(
        {},
        {"events": 0},
    ).sort("startedAt", -1).limit(100)
    sessions = []
    async for doc in cursor:
        doc["id"] = doc.pop("_id")
        serialize_dates(doc)
        sessions.append(doc)
    return sessions


@router.get("/sessions/{sid}", dependencies=[Depends(verify_api_key)])
async def get_session(sid: str, request: Request):
    """Get a single session with full event log, merging overflow when present."""
    col = get_sessions_col(request)
    doc = await col.find_one({"_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    event_count = doc.get("eventCount", 0)

    if event_count > EVENT_OVERFLOW_THRESHOLD:
        overflow = get_overflow_col(request)
        cursor = overflow.find({"sessionId": sid}).sort("seq", 1)
        async for bucket in cursor:
            doc["events"].extend(bucket["events"])

    doc["id"] = doc.pop("_id")
    serialize_dates(doc)
    return doc
