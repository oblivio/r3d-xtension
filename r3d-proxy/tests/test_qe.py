"""Queryable Encryption integration tests — require Docker + MongoDB Atlas Local.

Run via: docker compose -f docker-compose.test.yml run --rm test
These are skipped during normal `pytest` runs (no -m qe).
"""

import base64
import json
import os

import pytest
from bson.binary import Binary
from pymongo import AsyncMongoClient, MongoClient

from core.db import bootstrap_qe

pytestmark = pytest.mark.qe

MDB_URI = os.environ.get("MDB_URI", "")
LOCAL_MASTER_KEY = os.environ.get("LOCAL_MASTER_KEY", "")

needs_docker = pytest.mark.skipif(
    not MDB_URI or not LOCAL_MASTER_KEY,
    reason="QE tests require MDB_URI and LOCAL_MASTER_KEY (run via docker-compose.test.yml)",
)


# ── bootstrap_qe unit-level tests (no Docker needed) ─────────────────


class TestBootstrapQENoDocker:
    def test_disabled_when_no_key(self, monkeypatch):
        monkeypatch.delenv("LOCAL_MASTER_KEY", raising=False)
        monkeypatch.delenv("KMS_PROVIDER", raising=False)
        opts, info = bootstrap_qe("mongodb://localhost:27017/test")
        assert opts is None
        assert info["status"] == "disabled"

    def test_rejects_bad_key_length(self, monkeypatch):
        monkeypatch.delenv("KMS_PROVIDER", raising=False)
        bad_key = base64.b64encode(b"tooshort").decode()
        monkeypatch.setenv("LOCAL_MASTER_KEY", bad_key)
        opts, info = bootstrap_qe("mongodb://localhost:27017/test")
        assert opts is None
        assert info["status"] == "error"
        assert "bad key length" in info["reason"]

    def test_aws_provider_missing_arn(self, monkeypatch):
        monkeypatch.setenv("KMS_PROVIDER", "aws")
        monkeypatch.delenv("AWS_KMS_KEY_ARN", raising=False)
        opts, info = bootstrap_qe("mongodb://localhost:27017/test")
        assert opts is None
        assert info["status"] == "error"
        assert "missing KMS key ARN" in info["reason"]

    def test_provider_selection_aws(self, monkeypatch):
        monkeypatch.setenv("KMS_PROVIDER", "aws")
        monkeypatch.delenv("AWS_KMS_KEY_ARN", raising=False)
        opts, info = bootstrap_qe("mongodb://localhost:27017/test")
        assert info["status"] == "error"

    def test_provider_selection_local_fallback(self, monkeypatch):
        monkeypatch.delenv("KMS_PROVIDER", raising=False)
        monkeypatch.delenv("LOCAL_MASTER_KEY", raising=False)
        opts, info = bootstrap_qe("mongodb://localhost:27017/test")
        assert opts is None
        assert info["status"] == "disabled"


# ── Full QE integration tests (Docker required) ──────────────────────


@needs_docker
class TestQEBootstrap:
    def test_bootstrap_returns_enabled(self):
        opts, info = bootstrap_qe(MDB_URI)
        assert opts is not None
        assert info["status"] == "enabled"
        assert "origin" in info["encrypted_fields"]
        assert "cookies" in info["encrypted_fields"]
        assert "headers_json" in info["encrypted_fields"]
        assert "userAgent" in info["encrypted_fields"]

    def test_key_vault_has_data_keys(self):
        bootstrap_qe(MDB_URI)
        client = MongoClient(MDB_URI)
        kv = client["encryption"]["__r3dKeyVault"]
        keys = list(kv.find({"keyAltNames": {"$exists": True}}))
        client.close()
        alt_names = {n for doc in keys for n in doc.get("keyAltNames", [])}
        assert "r3d-origin" in alt_names
        assert "r3d-cookies" in alt_names
        assert "r3d-headers_json" in alt_names
        assert "r3d-userAgent" in alt_names

    def test_encrypted_collection_exists(self):
        bootstrap_qe(MDB_URI)
        client = MongoClient(MDB_URI)
        db = client.get_default_database(default="r3d_test")
        names = db.list_collection_names()
        client.close()
        assert "r3d_credentials" in names

    def test_schema_version_stored(self):
        """Verify schema version metadata is written after bootstrap."""
        from core.db import _QE_SCHEMA_VERSION

        bootstrap_qe(MDB_URI)
        client = MongoClient(MDB_URI)
        meta = client["encryption"]["__r3d_meta"].find_one({"_id": "qe_schema_version"})
        client.close()
        assert meta is not None
        assert meta["version"] == _QE_SCHEMA_VERSION


@needs_docker
class TestQERoundTrip:
    @pytest.fixture(autouse=True)
    def _setup(self):
        """Bootstrap QE and provide encrypting + raw clients."""
        opts, self.info = bootstrap_qe(MDB_URI)
        assert opts is not None

        self.enc_client = MongoClient(MDB_URI, auto_encryption_opts=opts)
        self.enc_col = self.enc_client.get_default_database(default="r3d_test")["r3d_credentials"]

        self.raw_client = MongoClient(MDB_URI)
        self.raw_col = self.raw_client.get_default_database(default="r3d_test")["r3d_credentials"]

        self.enc_col.delete_many({})
        yield
        self.enc_col.delete_many({})
        self.enc_client.close()
        self.raw_client.close()

    def test_write_and_read_decrypted(self):
        doc = {
            "origin": "https://hr.corp.com",
            "cookies": "session=abc123; csrf=xyz",
            "headers_json": json.dumps({"Authorization": "Bearer tok123"}),
            "userAgent": "Mozilla/5.0 R3D-Test",
        }
        self.enc_col.insert_one(doc)

        found = self.enc_col.find_one({"origin": "https://hr.corp.com"})
        assert found is not None
        assert found["origin"] == "https://hr.corp.com"
        assert found["cookies"] == "session=abc123; csrf=xyz"
        assert "Bearer tok123" in found["headers_json"]
        assert found["userAgent"] == "Mozilla/5.0 R3D-Test"

    def test_raw_read_is_ciphertext(self):
        doc = {
            "origin": "https://payroll.corp.com",
            "cookies": "sid=secret_value",
            "headers_json": "{}",
            "userAgent": "Chrome/120",
        }
        self.enc_col.insert_one(doc)

        raw = self.raw_col.find_one({"_id": doc["_id"]})
        assert raw is not None
        assert isinstance(raw["cookies"], Binary) or raw["cookies"] != "sid=secret_value"
        assert isinstance(raw["headers_json"], Binary) or raw["headers_json"] != "{}"
        assert isinstance(raw["userAgent"], Binary) or raw["userAgent"] != "Chrome/120"

    def test_equality_query_on_encrypted_origin(self):
        self.enc_col.insert_one({
            "origin": "https://alpha.com",
            "cookies": "a=1",
            "headers_json": "{}",
            "userAgent": "UA-A",
        })
        self.enc_col.insert_one({
            "origin": "https://beta.com",
            "cookies": "b=2",
            "headers_json": "{}",
            "userAgent": "UA-B",
        })

        result = self.enc_col.find_one({"origin": "https://alpha.com"})
        assert result is not None
        assert result["cookies"] == "a=1"

        result_beta = self.enc_col.find_one({"origin": "https://beta.com"})
        assert result_beta is not None
        assert result_beta["cookies"] == "b=2"

    def test_idempotent_bootstrap(self):
        opts1, info1 = bootstrap_qe(MDB_URI)
        opts2, info2 = bootstrap_qe(MDB_URI)
        assert opts1 is not None
        assert opts2 is not None
        assert info1["status"] == info2["status"] == "enabled"

    def test_compaction_runs_without_error(self):
        """Verify compactStructuredEncryptionData succeeds on the encrypted collection."""
        self.enc_col.insert_one({
            "origin": "https://compact-test.com",
            "cookies": "c=3",
            "headers_json": "{}",
            "userAgent": "UA-compact",
        })
        db = self.enc_client.get_default_database(default="r3d_test")
        result = db.command("compactStructuredEncryptionData", "r3d_credentials")
        assert result.get("ok") == 1


@needs_docker
class TestQEAPIRoundTrip:
    """Full-stack test: push credentials via API, read them back."""

    async def test_push_and_list_credentials(self):
        from contextlib import asynccontextmanager
        from httpx import ASGITransport, AsyncClient
        from app import app
        from core.vault import CredentialVault

        @asynccontextmanager
        async def _qe_lifespan(a):
            from core.replay import load_payloads
            load_payloads()

            opts, qe_info = bootstrap_qe(MDB_URI)
            client = AsyncMongoClient(MDB_URI, auto_encryption_opts=opts)
            db = client.get_default_database(default="r3d_test")
            a.state.sessions_col = db["r3d_sessions"]
            a.state.overflow_col = db["r3d_event_overflow"]
            a.state.specs_col = db["r3d_specs"]
            a.state.graphs_col = db["r3d_attack_graphs"]
            a.state.credentials_col = db["r3d_credentials"]
            a.state.users_col = db["r3d_users"]
            a.state.audit_col = db["r3d_audit_log"]
            a.state.qe_info = qe_info
            a.state.credential_vault = CredentialVault(db["r3d_credentials"])
            yield

        app.router.lifespan_context = _qe_lifespan
        api_key = os.environ.get("R3D_API_KEY", "test-key")
        headers = {"Authorization": f"Bearer {api_key}"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/r3d/auth-context", headers=headers, json={
                "origin": "https://api-test.corp.com",
                "cookies": "session=qe_test_cookie",
                "headers": {"Authorization": "Bearer secret_jwt_token"},
                "userAgent": "R3D-QE-Test",
            })
            assert resp.status_code == 200
            assert resp.json()["ok"] is True

            resp2 = await c.get("/r3d/auth-context/https://api-test.corp.com", headers=headers)
            assert resp2.status_code == 200
            ctx = resp2.json()["context"]
            assert ctx["cookies"] == "session=qe_test_cookie"
