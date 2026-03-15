"""Shared test fixtures — mock DB, test client, auth helpers."""

from __future__ import annotations

import copy
import os
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

TEST_API_KEY = "test-r3d-key-for-testing"

os.environ["R3D_API_KEY"] = TEST_API_KEY
os.environ.setdefault("MDB_URI", "")


class _UpdateResult:
    def __init__(self, matched: int, modified: int = 0):
        self.matched_count = matched
        self.modified_count = modified


class _DeleteResult:
    def __init__(self, deleted: int):
        self.deleted_count = deleted


class FakeCollection:
    """In-memory stand-in for a Motor async collection."""

    def __init__(self, docs: list[dict] | None = None):
        self._docs: dict[str, dict] = {}
        for d in docs or []:
            self._docs[d["_id"]] = d

    async def find_one(self, filter: dict | None = None, projection: dict | None = None) -> dict | None:
        if filter and "_id" in filter:
            doc = self._docs.get(filter["_id"])
        else:
            doc = None
            for d in self._docs.values():
                if all(d.get(k) == v for k, v in (filter or {}).items()):
                    doc = d
                    break
        if doc is None:
            return None
        doc = copy.deepcopy(doc)
        if projection:
            for key, include in projection.items():
                if not include and key in doc:
                    del doc[key]
        return doc

    async def replace_one(self, filter: dict, replacement: dict, upsert: bool = False):
        key = filter.get("_id")
        if key and (key in self._docs or upsert):
            self._docs[key] = replacement
        return _UpdateResult(1 if key and key in self._docs else 0)

    async def insert_one(self, doc: dict):
        if doc.get("_id") in self._docs:
            from pymongo.errors import DuplicateKeyError
            raise DuplicateKeyError("duplicate key")
        self._docs[doc["_id"]] = doc

    async def update_one(self, filter: dict, update: dict):
        key = filter.get("_id")
        doc = self._docs.get(key) if key else None
        if not doc and not key:
            for k, d in self._docs.items():
                if all(d.get(fk) == fv for fk, fv in filter.items()):
                    doc = d
                    key = k
                    break
        if not doc:
            return _UpdateResult(0)
        if "$set" in update:
            doc.update(update["$set"])
        if "$inc" in update:
            for field, val in update["$inc"].items():
                doc[field] = doc.get(field, 0) + val
        if "$push" in update:
            for field, val in update["$push"].items():
                if isinstance(val, dict) and "$each" in val:
                    doc.setdefault(field, []).extend(val["$each"])
                else:
                    doc.setdefault(field, []).append(val)
        return _UpdateResult(1, 1)

    async def delete_one(self, filter: dict):
        key = filter.get("_id")
        if key and key in self._docs:
            del self._docs[key]
            return _DeleteResult(1)
        return _DeleteResult(0)

    async def delete_many(self, filter: dict):
        to_remove = []
        for k, doc in self._docs.items():
            if all(doc.get(fk) == fv for fk, fv in filter.items()):
                to_remove.append(k)
        for k in to_remove:
            del self._docs[k]
        return _DeleteResult(len(to_remove))

    async def create_index(self, *args: Any, **kwargs: Any):
        pass

    def find(self, filter: dict | None = None, projection: dict | None = None):
        docs = []
        for doc in self._docs.values():
            if filter:
                match = all(doc.get(k) == v for k, v in filter.items() if not isinstance(v, dict))
                if not match:
                    continue
            d = copy.deepcopy(doc)
            if projection:
                for key, include in projection.items():
                    if not include and key in d:
                        del d[key]
            docs.append(d)
        return _FakeCursor(docs)


class _FakeCursor:
    def __init__(self, docs: list[dict]):
        self._docs = docs
        self._idx = 0

    def sort(self, *args, **kwargs):
        return self

    def limit(self, n: int):
        self._docs = self._docs[:n]
        return self

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._idx >= len(self._docs):
            raise StopAsyncIteration
        doc = self._docs[self._idx]
        self._idx += 1
        return doc


def _build_test_app() -> Any:
    """Import and configure the FastAPI app with null-DB lifespan for tests.

    ASGITransport does NOT invoke the lifespan, so we eagerly set state
    on the app object and install a no-op lifespan to avoid real DB setup.
    """
    from app import app
    from core.replay import load_payloads

    load_payloads()

    @asynccontextmanager
    async def _noop_lifespan(a):
        yield

    app.router.lifespan_context = _noop_lifespan

    app.state.sessions_col = FakeCollection()
    app.state.overflow_col = FakeCollection()
    app.state.specs_col = FakeCollection()
    app.state.graphs_col = FakeCollection()
    app.state.credentials_col = FakeCollection()
    app.state.users_col = FakeCollection()
    app.state.audit_col = FakeCollection()
    app.state.csfle_info = {"status": "disabled"}

    return app


@pytest.fixture()
def test_app():
    app = _build_test_app()
    app.state.sessions_col = FakeCollection()
    app.state.overflow_col = FakeCollection()
    app.state.specs_col = FakeCollection()
    app.state.graphs_col = FakeCollection()
    app.state.credentials_col = FakeCollection()
    app.state.users_col = FakeCollection()
    app.state.audit_col = FakeCollection()
    return app


@pytest.fixture()
async def client(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture()
def auth_header():
    return {"Authorization": f"Bearer {TEST_API_KEY}"}
