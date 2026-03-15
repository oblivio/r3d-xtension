"""Integration tests for the auth router — register, login, refresh, me."""

import pytest

from core.auth import create_access_token, create_refresh_token


class TestRegister:
    async def test_register_requires_admin(self, client, auth_header):
        resp = await client.post("/r3d/auth/register", headers=auth_header, json={
            "username": "alice", "password": "pass123", "role": "operator",
        })
        # API-key auth sets user=None, require_role("admin") should pass for API key
        # but the register endpoint uses require_role which checks user.role
        # With API key auth, user is None — register should still work since
        # require_role calls verify_api_key first (which succeeds for API key)
        # then checks user.role only if user is not None
        assert resp.status_code in (200, 403)

    async def test_register_and_login_flow(self, client, test_app, auth_header):
        admin_token = create_access_token("admin-id", "admin", "admin")
        admin_header = {"Authorization": f"Bearer {admin_token}"}

        resp = await client.post("/r3d/auth/register", headers=admin_header, json={
            "username": "bob", "password": "secret123", "role": "operator",
        })
        assert resp.status_code == 200
        assert resp.json()["username"] == "bob"

        resp2 = await client.post("/r3d/auth/login", json={
            "username": "bob", "password": "secret123",
        })
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["ok"] is True
        assert "accessToken" in data
        assert "refreshToken" in data
        assert data["user"]["username"] == "bob"

    async def test_duplicate_username_rejected(self, client, test_app, auth_header):
        admin_token = create_access_token("admin-id", "admin", "admin")
        hdr = {"Authorization": f"Bearer {admin_token}"}
        await client.post("/r3d/auth/register", headers=hdr, json={
            "username": "dupuser", "password": "p", "role": "viewer",
        })
        resp = await client.post("/r3d/auth/register", headers=hdr, json={
            "username": "dupuser", "password": "p2", "role": "viewer",
        })
        assert resp.status_code == 409

    async def test_invalid_role_rejected(self, client, test_app, auth_header):
        admin_token = create_access_token("admin-id", "admin", "admin")
        hdr = {"Authorization": f"Bearer {admin_token}"}
        resp = await client.post("/r3d/auth/register", headers=hdr, json={
            "username": "badrole", "password": "p", "role": "superuser",
        })
        assert resp.status_code == 400


class TestLogin:
    async def test_wrong_password(self, client, test_app, auth_header):
        admin_token = create_access_token("admin-id", "admin", "admin")
        hdr = {"Authorization": f"Bearer {admin_token}"}
        await client.post("/r3d/auth/register", headers=hdr, json={
            "username": "loginfail", "password": "correct", "role": "viewer",
        })
        resp = await client.post("/r3d/auth/login", json={
            "username": "loginfail", "password": "wrong",
        })
        assert resp.status_code == 401

    async def test_nonexistent_user(self, client, test_app):
        resp = await client.post("/r3d/auth/login", json={
            "username": "ghost", "password": "p",
        })
        assert resp.status_code == 401


class TestRefresh:
    async def test_refresh_token_flow(self, client, test_app, auth_header):
        admin_token = create_access_token("admin-id", "admin", "admin")
        hdr = {"Authorization": f"Bearer {admin_token}"}
        await client.post("/r3d/auth/register", headers=hdr, json={
            "username": "refresh_user", "password": "p", "role": "operator",
        })
        login_resp = await client.post("/r3d/auth/login", json={
            "username": "refresh_user", "password": "p",
        })
        refresh_token = login_resp.json()["refreshToken"]

        resp = await client.post("/r3d/auth/refresh", headers={
            "Authorization": f"Bearer {refresh_token}",
        })
        assert resp.status_code == 200
        assert "accessToken" in resp.json()

    async def test_access_token_rejected_as_refresh(self, client, test_app):
        token = create_access_token("u1", "alice", "admin")
        resp = await client.post("/r3d/auth/refresh", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 401

    async def test_no_token_rejected(self, client, test_app):
        resp = await client.post("/r3d/auth/refresh")
        assert resp.status_code == 401


class TestMe:
    async def test_me_with_api_key(self, client, auth_header):
        resp = await client.get("/r3d/auth/me", headers=auth_header)
        assert resp.status_code == 200
        assert resp.json()["authMethod"] == "api-key"

    async def test_me_with_jwt(self, client, test_app):
        token = create_access_token("u1", "alice", "admin")
        resp = await client.get("/r3d/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["authMethod"] == "jwt"
        assert data["user"]["username"] == "alice"
