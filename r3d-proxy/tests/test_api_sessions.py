"""Integration tests for session CRUD endpoints."""

import pytest

from conftest import FakeCollection


class TestStartSession:
    async def test_start_session(self, client, auth_header):
        resp = await client.post("/r3d/sessions/start", headers=auth_header, json={
            "sessionId": "s1", "name": "Test Session",
        })
        assert resp.status_code == 200
        assert resp.json()["sessionId"] == "s1"

    async def test_start_duplicate_upserts(self, client, test_app, auth_header):
        for _ in range(2):
            resp = await client.post("/r3d/sessions/start", headers=auth_header, json={
                "sessionId": "dup", "name": "Dup",
            })
            assert resp.status_code == 200

    async def test_requires_auth(self, client):
        resp = await client.post("/r3d/sessions/start", json={"sessionId": "x"})
        assert resp.status_code == 401


class TestAppendEvents:
    async def test_append_events(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "ev1"})
        resp = await client.post("/r3d/sessions/ev1/events", headers=auth_header, json={
            "events": [{"type": "request", "data": {"url": "https://a.com"}}],
        })
        assert resp.status_code == 200
        assert resp.json()["appended"] == 1

    async def test_append_empty_events(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "ev2"})
        resp = await client.post("/r3d/sessions/ev2/events", headers=auth_header, json={"events": []})
        assert resp.status_code == 200
        assert resp.json()["appended"] == 0

    async def test_append_to_nonexistent_session(self, client, auth_header):
        resp = await client.post("/r3d/sessions/missing/events", headers=auth_header, json={
            "events": [{"type": "x"}],
        })
        assert resp.status_code == 404


class TestGetSession:
    async def test_get_session(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "g1", "name": "G"})
        resp = await client.get("/r3d/sessions/g1", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "g1"
        assert data["name"] == "G"

    async def test_get_nonexistent(self, client, auth_header):
        resp = await client.get("/r3d/sessions/nope", headers=auth_header)
        assert resp.status_code == 404


class TestListSessions:
    async def test_list_sessions(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "l1"})
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "l2"})
        resp = await client.get("/r3d/sessions", headers=auth_header)
        assert resp.status_code == 200
        ids = {s["id"] for s in resp.json()}
        assert "l1" in ids
        assert "l2" in ids


class TestEndSession:
    async def test_end_session(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "e1"})
        resp = await client.post("/r3d/sessions/e1/end", headers=auth_header, json={"summary": {"findings": 5}})
        assert resp.status_code == 200

    async def test_end_nonexistent(self, client, auth_header):
        resp = await client.post("/r3d/sessions/nope/end", headers=auth_header, json={})
        assert resp.status_code == 404


class TestRenameSession:
    async def test_rename(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "r1", "name": "Old"})
        resp = await client.patch("/r3d/sessions/r1", headers=auth_header, json={"name": "New"})
        assert resp.status_code == 200

    async def test_rename_nonexistent(self, client, auth_header):
        resp = await client.patch("/r3d/sessions/nope", headers=auth_header, json={"name": "X"})
        assert resp.status_code == 404


class TestDeleteSession:
    async def test_delete(self, client, test_app, auth_header):
        await client.post("/r3d/sessions/start", headers=auth_header, json={"sessionId": "d1"})
        resp = await client.delete("/r3d/sessions/d1", headers=auth_header)
        assert resp.status_code == 200
        resp2 = await client.get("/r3d/sessions/d1", headers=auth_header)
        assert resp2.status_code == 404

    async def test_delete_nonexistent(self, client, auth_header):
        resp = await client.delete("/r3d/sessions/nope", headers=auth_header)
        assert resp.status_code == 404
