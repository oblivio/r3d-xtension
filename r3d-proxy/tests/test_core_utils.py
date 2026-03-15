"""Tests for core utility functions — db helpers, audit, config."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from core.config import now
from core.db import get_sessions_col, serialize_dates
from core.audit import audit_log


# ── serialize_dates ──────────────────────────────────────────────────


class TestSerializeDates:
    def test_converts_datetime_to_iso(self):
        dt = datetime(2024, 6, 15, 12, 30, 0, tzinfo=timezone.utc)
        doc = {"startedAt": dt, "endedAt": None}
        serialize_dates(doc)
        assert doc["startedAt"] == "2024-06-15T12:30:00+00:00"
        assert doc["endedAt"] is None

    def test_leaves_non_datetime_untouched(self):
        doc = {"startedAt": "already-string", "endedAt": 12345}
        serialize_dates(doc)
        assert doc["startedAt"] == "already-string"
        assert doc["endedAt"] == 12345

    def test_missing_keys_no_error(self):
        doc = {"other": "data"}
        serialize_dates(doc)
        assert doc == {"other": "data"}


# ── get_sessions_col ─────────────────────────────────────────────────


class TestGetSessionsCol:
    def test_returns_col_when_set(self):
        req = MagicMock()
        req.app.state.sessions_col = "the-collection"
        assert get_sessions_col(req) == "the-collection"

    def test_raises_503_when_none(self):
        req = MagicMock()
        req.app.state.sessions_col = None
        with pytest.raises(HTTPException) as exc_info:
            get_sessions_col(req)
        assert exc_info.value.status_code == 503


# ── now() ────────────────────────────────────────────────────────────


class TestNow:
    def test_returns_utc_datetime(self):
        result = now()
        assert isinstance(result, datetime)
        assert result.tzinfo is not None
        assert result.tzinfo == timezone.utc


# ── audit_log ────────────────────────────────────────────────────────


class TestAuditLog:
    async def test_writes_audit_entry(self):
        inserted = {}

        class FakeAuditCol:
            async def insert_one(self, doc):
                inserted.update(doc)

        req = MagicMock()
        req.state.user = {"_id": "u1", "username": "alice"}
        req.client.host = "1.2.3.4"
        req.headers.get = lambda k, d="": {"user-agent": "R3D/1.0"}.get(k, d)
        req.app.state.audit_col = FakeAuditCol()

        await audit_log(req, "session.start", "s1", {"name": "Test"})
        assert inserted["action"] == "session.start"
        assert inserted["userId"] == "u1"
        assert inserted["username"] == "alice"
        assert inserted["resource"] == "s1"
        assert inserted["ip"] == "1.2.3.4"

    async def test_noop_when_col_is_none(self):
        req = MagicMock()
        req.state.user = None
        req.client.host = ""
        req.headers.get = lambda k, d="": d
        req.app.state.audit_col = None
        await audit_log(req, "test.action")

    async def test_noop_on_insert_error(self):
        class BrokenCol:
            async def insert_one(self, doc):
                raise RuntimeError("DB down")

        req = MagicMock()
        req.state.user = None
        req.client.host = ""
        req.headers.get = lambda k, d="": d
        req.app.state.audit_col = BrokenCol()
        await audit_log(req, "test.action")
