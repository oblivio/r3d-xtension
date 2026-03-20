"""Authentication — API-key, JWT multi-user, and role-based access control."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import HTTPException, Request
from pydantic import BaseModel

from core.config import R3D_API_KEY

# ─── JWT Configuration ───────────────────────────────────────────────

JWT_ALGORITHM = "HS256"
JWT_ACCESS_EXPIRE_MINUTES = 60
JWT_REFRESH_EXPIRE_DAYS = 7

# Dynamic JWT secret with automatic rotation support
def _get_jwt_secret() -> str:
    """Get JWT secret with optional rotation support."""
    static_secret = os.environ.get("R3D_JWT_SECRET", "")
    if static_secret:
        return static_secret  # Use static secret if provided (legacy mode)

    # Use automatic rotation
    from core.rotation import get_current_secret
    return get_current_secret()

JWT_SECRET = _get_jwt_secret()

# ─── User Model ──────────────────────────────────────────────────────

ROLES = ("admin", "operator", "viewer")


class UserCreate(BaseModel):
    username: str
    email: str = ""
    password: str
    role: str = "operator"


class UserLogin(BaseModel):
    username: str
    password: str


# ─── Password Helpers ────────────────────────────────────────────────


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ─── JWT Helpers ─────────────────────────────────────────────────────


def create_access_token(user_id: str, username: str, role: str, expires_minutes: int | None = None, scope: str | None = None) -> str:
    """Create a JWT access token with optional custom expiry.

    Args:
        user_id: User identifier
        username: Username for audit logging
        role: User role (admin, operator, viewer)
        expires_minutes: Custom expiry in minutes (default: JWT_ACCESS_EXPIRE_MINUTES)

    Returns:
        Encoded JWT token string
    """
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes or JWT_ACCESS_EXPIRE_MINUTES),
        "type": "access",
    }
    if scope:
        payload["scope"] = scope

    # Use dynamic secret (supports rotation)
    secret = _get_jwt_secret()
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_EXPIRE_DAYS),
        "type": "refresh",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode JWT token with automatic rotation support."""
    if os.environ.get("R3D_JWT_SECRET"):
        # Static secret mode
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

    # Rotation mode - try current and previous secrets
    from core.rotation import verify_token_with_rotation
    return verify_token_with_rotation(token, JWT_ALGORITHM)


# ─── Auth Dependencies ───────────────────────────────────────────────


async def verify_api_key(request: Request):
    """Accept API key (Bearer or cookie) OR a valid JWT token.

    On success, sets request.state.user with user info (or None for API key auth).
    """
    request.state.user = None

    # 1. API key via Bearer header
    auth_header = request.headers.get("Authorization", "")
    if R3D_API_KEY and auth_header == f"Bearer {R3D_API_KEY}":
        return

    # 2. API key via httpOnly cookie (legacy)
    cookie = request.cookies.get("r3d_session", "")
    if R3D_API_KEY and cookie == R3D_API_KEY:
        return

    # 2b. JWT via r3d_session cookie (dashboard mints session JWTs here)
    if cookie:
        try:
            payload = decode_token(cookie)
            if payload.get("type") == "access":
                request.state.user = {
                    "_id": payload["sub"],
                    "username": payload["username"],
                    "role": payload["role"],
                }
                return
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass

    # 3. JWT via Bearer header
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")
            request.state.user = {
                "_id": payload["sub"],
                "username": payload["username"],
                "role": payload["role"],
            }
            return
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            pass

    # 4. JWT via cookie
    jwt_cookie = request.cookies.get("r3d_jwt", "")
    if jwt_cookie:
        try:
            payload = decode_token(jwt_cookie)
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")
            request.state.user = {
                "_id": payload["sub"],
                "username": payload["username"],
                "role": payload["role"],
            }
            return
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            pass

    # 5. No API key configured — open access
    if not R3D_API_KEY:
        return

    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_role(*roles: str):
    """Return a dependency that requires the user to have one of the given roles."""
    async def _check(request: Request):
        await verify_api_key(request)
        user = getattr(request.state, "user", None)
        if user and user.get("role") not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(roles)}")
    return _check
