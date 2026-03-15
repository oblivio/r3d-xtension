"""Tests for core/auth — password hashing, JWT lifecycle, verify_api_key."""

import os
import time
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from core.auth import (
    JWT_ALGORITHM,
    JWT_SECRET,
    ROLES,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    require_role,
    verify_api_key,
    verify_password,
)


# ── Password helpers ─────────────────────────────────────────────────


class TestPasswordHashing:
    def test_round_trip(self):
        hashed = hash_password("s3cret")
        assert verify_password("s3cret", hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_different_salts(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2
        assert verify_password("same", h1)
        assert verify_password("same", h2)


# ── JWT helpers ──────────────────────────────────────────────────────


class TestJWT:
    def test_access_token_round_trip(self):
        token = create_access_token("user-1", "alice", "admin")
        payload = decode_token(token)
        assert payload["sub"] == "user-1"
        assert payload["username"] == "alice"
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_refresh_token_round_trip(self):
        token = create_refresh_token("user-1")
        payload = decode_token(token)
        assert payload["sub"] == "user-1"
        assert payload["type"] == "refresh"

    def test_expired_token_raises(self):
        payload = {
            "sub": "user-1",
            "username": "alice",
            "role": "admin",
            "exp": int(time.time()) - 60,
            "type": "access",
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            decode_token(token)

    def test_tampered_token_raises(self):
        token = create_access_token("user-1", "alice", "admin")
        tampered = token[:-4] + "XXXX"
        with pytest.raises(pyjwt.InvalidTokenError):
            decode_token(tampered)

    def test_roles_constant(self):
        assert "admin" in ROLES
        assert "operator" in ROLES
        assert "viewer" in ROLES


# ── verify_api_key dependency ────────────────────────────────────────


def _make_request(
    auth_header: str = "",
    cookies: dict | None = None,
    api_key_env: str | None = None,
) -> MagicMock:
    """Build a fake Request with headers and cookies."""
    req = MagicMock()
    req.headers = {}
    if auth_header:
        req.headers["Authorization"] = auth_header
    req.cookies = cookies or {}
    req.state = MagicMock()
    req.state.user = None
    return req


class TestVerifyApiKey:
    @pytest.fixture(autouse=True)
    def _set_api_key(self, monkeypatch):
        """Ensure the auth module sees a known API key during tests."""
        monkeypatch.setattr("core.auth.R3D_API_KEY", "test-key")

    async def test_bearer_api_key(self):
        req = _make_request(auth_header="Bearer test-key")
        await verify_api_key(req)

    async def test_cookie_api_key(self):
        req = _make_request(cookies={"r3d_session": "test-key"})
        await verify_api_key(req)

    async def test_jwt_bearer(self):
        token = create_access_token("u1", "alice", "admin")
        req = _make_request(auth_header=f"Bearer {token}")
        await verify_api_key(req)
        assert req.state.user["username"] == "alice"

    async def test_jwt_cookie(self):
        token = create_access_token("u1", "bob", "viewer")
        req = _make_request(cookies={"r3d_jwt": token})
        await verify_api_key(req)
        assert req.state.user["username"] == "bob"

    async def test_open_access_when_no_key(self, monkeypatch):
        monkeypatch.setattr("core.auth.R3D_API_KEY", "")
        req = _make_request()
        await verify_api_key(req)

    async def test_rejects_invalid_key(self):
        req = _make_request(auth_header="Bearer wrong-key")
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key(req)
        assert exc_info.value.status_code == 401

    async def test_rejects_expired_jwt(self):
        payload = {
            "sub": "u1", "username": "alice", "role": "admin",
            "exp": int(time.time()) - 60, "type": "access",
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        req = _make_request(auth_header=f"Bearer {token}")
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key(req)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    async def test_rejects_refresh_token_as_bearer(self):
        token = create_refresh_token("u1")
        req = _make_request(auth_header=f"Bearer {token}")
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key(req)
        assert exc_info.value.status_code == 401


# ── require_role ─────────────────────────────────────────────────────


class TestRequireRole:
    @pytest.fixture(autouse=True)
    def _set_api_key(self, monkeypatch):
        monkeypatch.setattr("core.auth.R3D_API_KEY", "test-key")

    async def test_allowed_role(self):
        dep = require_role("admin", "operator")
        token = create_access_token("u1", "alice", "admin")
        req = _make_request(auth_header=f"Bearer {token}")
        await dep(req)

    async def test_forbidden_role(self):
        dep = require_role("admin")
        token = create_access_token("u1", "bob", "viewer")
        req = _make_request(auth_header=f"Bearer {token}")
        with pytest.raises(HTTPException) as exc_info:
            await dep(req)
        assert exc_info.value.status_code == 403
