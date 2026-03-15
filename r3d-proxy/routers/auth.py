"""User authentication — login, register, refresh, user management, audit log."""

import uuid as _uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from core.audit import audit_log
from core.auth import (
    UserCreate,
    UserLogin,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    require_role,
    verify_api_key,
    verify_password,
    ROLES,
)
from core.config import now

router = APIRouter(prefix="/r3d/auth", tags=["auth"])


def _users_col(request: Request):
    col = getattr(request.app.state, "users_col", None)
    if col is None:
        raise HTTPException(status_code=503, detail="User management requires MongoDB")
    return col


@router.post("/register", dependencies=[Depends(require_role("admin"))])
async def register(body: UserCreate, request: Request):
    """Create a new user (admin only)."""
    col = _users_col(request)
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(ROLES)}")

    existing = await col.find_one({"username": body.username})
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_id = str(_uuid.uuid4())
    doc = {
        "_id": user_id,
        "username": body.username,
        "email": body.email,
        "passwordHash": hash_password(body.password),
        "role": body.role,
        "createdAt": now(),
        "lastLogin": None,
        "active": True,
    }
    await col.insert_one(doc)
    await audit_log(request, "user.register", user_id, {"username": body.username, "role": body.role})
    return {"ok": True, "userId": user_id, "username": body.username, "role": body.role}


@router.post("/login")
async def login(body: UserLogin, request: Request):
    """Authenticate and return JWT tokens."""
    col = getattr(request.app.state, "users_col", None)
    if col is None:
        raise HTTPException(status_code=503, detail="User management requires MongoDB")

    user = await col.find_one({"username": body.username})
    if not user or not user.get("active", True):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(body.password, user["passwordHash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await col.update_one({"_id": user["_id"]}, {"$set": {"lastLogin": now()}})

    access = create_access_token(user["_id"], user["username"], user["role"])
    refresh = create_refresh_token(user["_id"])

    await audit_log(request, "user.login", user["_id"], {"username": user["username"]})

    response = JSONResponse(content={
        "ok": True,
        "accessToken": access,
        "refreshToken": refresh,
        "user": {"id": user["_id"], "username": user["username"], "role": user["role"]},
    })
    response.set_cookie(
        key="r3d_jwt",
        value=access,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@router.post("/refresh")
async def refresh_token(request: Request):
    """Exchange a refresh token for a new access token."""
    col = getattr(request.app.state, "users_col", None)
    if col is None:
        raise HTTPException(status_code=503, detail="User management requires MongoDB")

    auth = request.headers.get("Authorization", "")
    token = ""
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Provide refresh token as Bearer")

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    user = await col.find_one({"_id": payload["sub"]})
    if not user or not user.get("active", True):
        raise HTTPException(status_code=401, detail="User not found or disabled")

    access = create_access_token(user["_id"], user["username"], user["role"])
    response = JSONResponse(content={"ok": True, "accessToken": access})
    response.set_cookie(
        key="r3d_jwt",
        value=access,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users(request: Request):
    """List all users (admin only)."""
    col = _users_col(request)
    users = []
    async for doc in col.find({}, {"passwordHash": 0}).sort("createdAt", -1).limit(200):
        doc["id"] = doc.pop("_id")
        if isinstance(doc.get("createdAt"), datetime):
            doc["createdAt"] = doc["createdAt"].isoformat()
        if isinstance(doc.get("lastLogin"), datetime):
            doc["lastLogin"] = doc["lastLogin"].isoformat()
        users.append(doc)
    return {"ok": True, "users": users}


@router.delete("/users/{user_id}", dependencies=[Depends(require_role("admin"))])
async def deactivate_user(user_id: str, request: Request):
    """Deactivate a user (admin only)."""
    col = _users_col(request)
    result = await col.update_one({"_id": user_id}, {"$set": {"active": False}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await audit_log(request, "user.deactivate", user_id)
    return {"ok": True}


@router.get("/me", dependencies=[Depends(verify_api_key)])
async def get_current_user(request: Request):
    """Return the currently authenticated user's info."""
    user = getattr(request.state, "user", None)
    if not user:
        return {"ok": True, "user": None, "authMethod": "api-key"}
    return {"ok": True, "user": user, "authMethod": "jwt"}


# ─── Audit Log Query ────────────────────────────────────────────────


@router.get("/audit", dependencies=[Depends(require_role("admin"))])
async def query_audit_log(request: Request, limit: int = 100, action: str = ""):
    """Query the audit log (admin only)."""
    col = getattr(request.app.state, "audit_col", None)
    if col is None:
        raise HTTPException(status_code=503, detail="Audit logging requires MongoDB")
    query = {}
    if action:
        query["action"] = {"$regex": action}
    entries = []
    async for doc in col.find(query).sort("ts", -1).limit(min(limit, 500)):
        doc["id"] = str(doc.pop("_id"))
        if isinstance(doc.get("ts"), datetime):
            doc["ts"] = doc["ts"].isoformat()
        entries.append(doc)
    return {"ok": True, "entries": entries, "count": len(entries)}
