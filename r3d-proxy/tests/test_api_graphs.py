"""Integration tests for the /r3d/graph/* API endpoints."""

import pytest

from conftest import FakeCollection


SAMPLE_SESSION = {
    "_id": "sess-int",
    "events": [
        {"type": "request", "data": {"systemId": "sys-a", "systemName": "App A", "url": "https://a.corp.com/api"}},
        {"type": "request", "data": {"systemId": "sys-b", "systemName": "App B", "url": "https://b.corp.com/api"}},
        {"type": "finding", "data": {
            "id": "f1", "systemId": "sys-a", "title": "XSS in search",
            "severity": "HIGH", "cwe": "CWE-79", "confidence": "high", "status": "confirmed",
        }},
        {"type": "finding", "data": {
            "id": "f2", "systemId": "sys-b", "title": "IDOR in user profiles",
            "severity": "HIGH", "cwe": "CWE-639", "confidence": "medium", "status": "likely",
        }},
        {"type": "pattern", "data": {"title": "Token reuse across systems"}},
    ],
}


class TestBuildGraph:
    async def test_build_graph_success(self, client, test_app, auth_header):
        test_app.state.sessions_col = FakeCollection([SAMPLE_SESSION])
        test_app.state.graphs_col = FakeCollection()

        resp = await client.post("/r3d/graph/build/sess-int", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessionId"] == "sess-int"
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0
        assert "paths" in data

    async def test_build_graph_session_not_found(self, client, test_app, auth_header):
        test_app.state.sessions_col = FakeCollection()
        resp = await client.post("/r3d/graph/build/nonexistent", headers=auth_header)
        assert resp.status_code == 404

    async def test_build_graph_requires_auth(self, client):
        resp = await client.post("/r3d/graph/build/sess-int")
        assert resp.status_code == 401


class TestGetGraph:
    async def test_get_graph_success(self, client, test_app, auth_header):
        stored = {"_id": "graph-sess-1", "sessionId": "sess-1", "nodes": [], "edges": []}
        test_app.state.graphs_col = FakeCollection([stored])

        resp = await client.get("/r3d/graph/sess-1", headers=auth_header)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "graph-sess-1"

    async def test_get_graph_not_found(self, client, test_app, auth_header):
        test_app.state.graphs_col = FakeCollection()
        resp = await client.get("/r3d/graph/missing", headers=auth_header)
        assert resp.status_code == 404


class TestFindPaths:
    async def test_find_paths_with_source_and_target(self, client, test_app, auth_header):
        test_app.state.sessions_col = FakeCollection([SAMPLE_SESSION])

        resp = await client.post(
            "/r3d/graph/sess-int/paths",
            headers=auth_header,
            json={"source": "sys-a", "target": "sys-b", "maxDepth": 8},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessionId"] == "sess-int"
        assert "paths" in data
        assert "count" in data

    async def test_find_all_paths_no_source_target(self, client, test_app, auth_header):
        test_app.state.sessions_col = FakeCollection([SAMPLE_SESSION])

        resp = await client.post(
            "/r3d/graph/sess-int/paths",
            headers=auth_header,
            json={},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["paths"], list)

    async def test_find_paths_session_not_found(self, client, test_app, auth_header):
        test_app.state.sessions_col = FakeCollection()
        resp = await client.post(
            "/r3d/graph/missing/paths",
            headers=auth_header,
            json={},
        )
        assert resp.status_code == 404
