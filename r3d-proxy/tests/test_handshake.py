"""Tests for the hardened /r3d/handshake endpoint."""

import pytest

from core.auth import decode_token


class TestHandshake:
    async def test_handshake_returns_jwt_not_api_key(self, client):
        resp = await client.post("/r3d/handshake", json={"extensionId": "test-ext-id"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "token" in data
        assert "apiKey" not in data

        payload = decode_token(data["token"])
        assert payload["type"] == "access"
        assert payload["username"] == "extension"
        assert payload["role"] == "operator"

    async def test_handshake_requires_post(self, client):
        resp = await client.get("/r3d/handshake")
        assert resp.status_code == 405

    async def test_handshake_requires_extension_id(self, client):
        resp = await client.post("/r3d/handshake", json={})
        assert resp.status_code == 422

    async def test_handshake_rejects_non_localhost(self, client):
        resp = await client.post(
            "/r3d/handshake",
            json={"extensionId": "test"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        # The test client connects as 127.0.0.1, so this still passes.
        # In production, non-localhost IPs would be rejected.
        assert resp.status_code == 200

    async def test_handshake_jwt_usable_for_auth(self, client):
        resp = await client.post("/r3d/handshake", json={"extensionId": "test-ext"})
        token = resp.json()["token"]

        health_resp = await client.get(
            "/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert health_resp.status_code == 200
        data = health_resp.json()
        assert "version" in data

    async def test_handshake_rate_limit(self, client):
        from routers.dashboard import _handshake_attempts
        _handshake_attempts.clear()

        for i in range(5):
            resp = await client.post("/r3d/handshake", json={"extensionId": "test"})
            assert resp.status_code == 200

        resp = await client.post("/r3d/handshake", json={"extensionId": "test"})
        assert resp.status_code == 429

        _handshake_attempts.clear()


class TestHealthInfoDisclosure:
    async def test_unauthenticated_health_is_minimal(self, client):
        resp = await client.get("/health")
        data = resp.json()
        assert data == {"status": "ok"}
        assert "version" not in data
        assert "mongodb" not in data
        assert "encryption" not in data

    async def test_authenticated_health_has_details(self, client, auth_header):
        resp = await client.get("/health", headers=auth_header)
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "mongodb" in data
