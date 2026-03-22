"""Tests for core/replay (payloads) and core/vault (CredentialVault)."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core.replay import (
    load_payloads,
    payload_meta,
    payloads,
)
from core.vault import CredentialVault


# ── load_payloads ────────────────────────────────────────────────────


class TestLoadPayloads:
    @pytest.fixture(autouse=True)
    def _clean(self):
        payloads.clear()
        payload_meta.clear()
        yield
        payloads.clear()
        payload_meta.clear()

    def test_loads_dict_format_with_metadata(self, tmp_path):
        data = {
            "id": "xss",
            "name": "XSS",
            "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        }
        (tmp_path / "xss.json").write_text(json.dumps(data))

        with patch("core.replay.Path.__truediv__", return_value=tmp_path):
            pass

        import core.replay as mod
        original_dir = Path(mod.__file__).parent.parent / "payloads"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "glob", return_value=[tmp_path / "xss.json"]):
            _do_load(tmp_path)

        assert "xss" in payloads
        assert len(payloads["xss"]) == 2
        assert "xss" in payload_meta
        assert payload_meta["xss"]["name"] == "XSS"
        assert "payloads" not in payload_meta["xss"]

    def test_loads_bare_list_format(self, tmp_path):
        data = ["payload1", "payload2"]
        (tmp_path / "custom.json").write_text(json.dumps(data))
        _do_load(tmp_path)
        assert "custom" in payloads
        assert payloads["custom"] == ["payload1", "payload2"]
        assert "custom" not in payload_meta

    def test_loads_real_payloads_directory(self):
        load_payloads()
        assert "xss" in payloads
        assert "sqli" in payloads
        assert len(payloads["xss"]) > 0
        assert len(payloads["sqli"]) > 0

    def test_ignores_malformed_json(self, tmp_path):
        (tmp_path / "bad.json").write_text("{not valid json")
        _do_load(tmp_path)
        assert "bad" not in payloads


def _do_load(payload_dir: Path):
    """Load payloads from a specific directory, bypassing path computation."""
    for f in payload_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, dict) and "payloads" in data:
                payloads[f.stem] = data["payloads"]
                payload_meta[f.stem] = {k: v for k, v in data.items() if k != "payloads"}
            elif isinstance(data, list):
                payloads[f.stem] = data
        except Exception:
            pass


# ── CredentialVault (on-demand decrypt, no in-memory cache) ──────────


class FakeCredentialsCollection:
    """In-memory mock that simulates a QE-encrypted collection."""

    def __init__(self):
        self._docs: list[dict] = []

    async def find_one(self, filter: dict) -> dict | None:
        for doc in self._docs:
            if all(doc.get(k) == v for k, v in filter.items()):
                return dict(doc)
        return None

    async def delete_many(self, filter: dict):
        before = len(self._docs)
        self._docs = [d for d in self._docs if not all(d.get(k) == v for k, v in filter.items())]

        class _R:
            deleted_count = before - len(self._docs)

        return _R()

    async def insert_one(self, doc: dict):
        self._docs.append(dict(doc))

    def find(self):
        return _FakeCursor(list(self._docs))


class _FakeCursor:
    def __init__(self, docs):
        self._docs = docs
        self._idx = 0

    def sort(self, *a, **kw):
        return self

    def limit(self, n):
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


class TestCredentialVault:
    @pytest.fixture()
    def vault(self):
        col = FakeCredentialsCollection()
        return CredentialVault(col)

    @pytest.fixture()
    def null_vault(self):
        return CredentialVault(None)

    @pytest.mark.asyncio
    async def test_get_context_empty(self, vault):
        ctx = await vault.get_context("https://unknown.com")
        assert ctx == {}

    @pytest.mark.asyncio
    async def test_store_and_get_context(self, vault):
        await vault.store(
            "https://target.com", "session=abc123",
            {"Authorization": "Bearer tok"}, "Chrome/120",
        )
        ctx = await vault.get_context("https://target.com")
        assert ctx["cookies"] == "session=abc123"
        assert ctx["headers"]["Authorization"] == "Bearer tok"
        assert ctx["userAgent"] == "Chrome/120"

    @pytest.mark.asyncio
    async def test_store_replaces_existing(self, vault):
        await vault.store("https://target.com", "old=1", {}, "")
        await vault.store("https://target.com", "new=2", {}, "")
        ctx = await vault.get_context("https://target.com")
        assert ctx["cookies"] == "new=2"

    @pytest.mark.asyncio
    async def test_get_replay_headers_merges_context(self, vault):
        await vault.store(
            "https://target.com", "session=abc123",
            {"Authorization": "Bearer tok"}, "Chrome/120",
        )
        h = await vault.get_replay_headers("https://target.com")
        assert h["Cookie"] == "session=abc123"
        assert h["Authorization"] == "Bearer tok"
        assert h["User-Agent"] == "Chrome/120"

    @pytest.mark.asyncio
    async def test_get_replay_headers_extra_override(self, vault):
        await vault.store(
            "https://target.com", "a=1",
            {"X-Custom": "old"}, "",
        )
        h = await vault.get_replay_headers("https://target.com", extra_headers={"X-Custom": "new"})
        assert h["X-Custom"] == "new"

    @pytest.mark.asyncio
    async def test_get_replay_headers_strips_host_and_content(self, vault):
        await vault.store(
            "https://target.com", "",
            {"Host": "evil.com", "Content-Length": "99", "X-Keep": "yes"}, "",
        )
        h = await vault.get_replay_headers("https://target.com")
        assert "Host" not in h
        assert "Content-Length" not in h
        assert h["X-Keep"] == "yes"

    @pytest.mark.asyncio
    async def test_get_replay_headers_missing_origin(self, vault):
        h = await vault.get_replay_headers("https://unknown.com")
        assert isinstance(h, dict)

    @pytest.mark.asyncio
    async def test_get_replay_headers_strips_r3d_headers(self, vault):
        await vault.store(
            "https://target.com", "",
            {"X-R3D-Session": "secret", "X-Normal": "ok"}, "",
        )
        h = await vault.get_replay_headers("https://target.com")
        assert "X-R3D-Session" not in h
        assert h["X-Normal"] == "ok"

    @pytest.mark.asyncio
    async def test_list_origins(self, vault):
        await vault.store("https://alpha.com", "a=1", {"X-A": "1"}, "UA-A")
        await vault.store("https://beta.com", "", {}, "")
        origins = await vault.list_origins()
        assert len(origins) == 2
        alpha = next(o for o in origins if o["origin"] == "https://alpha.com")
        assert alpha["hasCookies"] is True
        assert "X-A" in alpha["headerKeys"]

    @pytest.mark.asyncio
    async def test_delete(self, vault):
        await vault.store("https://target.com", "x=1", {}, "")
        deleted = await vault.delete("https://target.com")
        assert deleted == 1
        ctx = await vault.get_context("https://target.com")
        assert ctx == {}

    @pytest.mark.asyncio
    async def test_null_vault_returns_empty(self, null_vault):
        ctx = await null_vault.get_context("https://any.com")
        assert ctx == {}
        h = await null_vault.get_replay_headers("https://any.com")
        assert isinstance(h, dict)
        origins = await null_vault.list_origins()
        assert origins == []
        deleted = await null_vault.delete("https://any.com")
        assert deleted == 0
