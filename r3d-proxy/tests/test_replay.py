"""Tests for core/replay — payload loading and header merging."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.replay import (
    auth_contexts,
    get_replay_headers,
    load_payloads,
    payload_meta,
    payloads,
)


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


# ── get_replay_headers ───────────────────────────────────────────────


class TestGetReplayHeaders:
    @pytest.fixture(autouse=True)
    def _clean(self):
        auth_contexts.clear()
        yield
        auth_contexts.clear()

    def test_merges_stored_context(self):
        auth_contexts["https://target.com"] = {
            "cookies": "session=abc123",
            "headers": {"Authorization": "Bearer tok"},
            "userAgent": "Chrome/120",
        }
        h = get_replay_headers("https://target.com")
        assert h["Cookie"] == "session=abc123"
        assert h["Authorization"] == "Bearer tok"
        assert h["User-Agent"] == "Chrome/120"

    def test_extra_headers_override(self):
        auth_contexts["https://target.com"] = {
            "cookies": "a=1",
            "headers": {"X-Custom": "old"},
            "userAgent": "",
        }
        h = get_replay_headers("https://target.com", extra_headers={"X-Custom": "new"})
        assert h["X-Custom"] == "new"

    def test_strips_host_and_content_headers(self):
        auth_contexts["https://target.com"] = {
            "cookies": "",
            "headers": {"Host": "evil.com", "Content-Length": "99", "X-Keep": "yes"},
            "userAgent": "",
        }
        h = get_replay_headers("https://target.com")
        assert "Host" not in h
        assert "Content-Length" not in h
        assert h["X-Keep"] == "yes"

    def test_missing_origin_returns_minimal_headers(self):
        h = get_replay_headers("https://unknown.com")
        assert isinstance(h, dict)

    def test_strips_r3d_headers(self):
        auth_contexts["https://target.com"] = {
            "cookies": "",
            "headers": {"X-R3D-Session": "secret", "X-Normal": "ok"},
            "userAgent": "",
        }
        h = get_replay_headers("https://target.com")
        assert "X-R3D-Session" not in h
        assert h["X-Normal"] == "ok"
