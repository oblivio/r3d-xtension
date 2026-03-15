"""MongoDB client helpers and CSFLE bootstrap."""

import base64
import json
import os
from datetime import datetime
from typing import Any

from bson.binary import STANDARD
from bson.codec_options import CodecOptions
from fastapi import HTTPException, Request
from pymongo import MongoClient
from pymongo.encryption import AutoEncryptionOpts, ClientEncryption


def bootstrap_csfle(mdb_uri: str) -> tuple[AutoEncryptionOpts | None, dict]:
    """Sync one-time setup: key vault, data key, encrypted collection.

    Returns (auto_encryption_opts, info_dict).  When LOCAL_MASTER_KEY is unset
    the function returns (None, {"status": "disabled"}) and everything works
    without encryption — perfect for running outside Docker.
    """
    master_key_b64 = os.environ.get("LOCAL_MASTER_KEY", "")
    if not master_key_b64:
        return None, {"status": "disabled"}

    local_master_key = base64.b64decode(master_key_b64)
    if len(local_master_key) != 96:
        print(f"CSFLE: LOCAL_MASTER_KEY must decode to 96 bytes (got {len(local_master_key)})")
        return None, {"status": "error", "reason": "bad key length"}

    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "encryption.__r3dKeyVault"
    crypt_shared_lib_path = os.environ.get("CRYPT_SHARED_LIB_PATH", "")

    setup_client = MongoClient(mdb_uri)
    kv_db, kv_coll = key_vault_namespace.split(".", 1)
    kv = setup_client[kv_db][kv_coll]
    kv.create_index(
        "keyAltNames",
        unique=True,
        partialFilterExpression={"keyAltNames": {"$exists": True}},
    )

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        setup_client,
        CodecOptions(uuid_representation=STANDARD),
    )

    field_defs = [
        ("origin",       True),
        ("cookies",      False),
        ("headers_json", False),
    ]
    key_ids = {}
    for name, _ in field_defs:
        alt = f"r3d-{name}"
        existing = kv.find_one({"keyAltNames": alt})
        key_ids[name] = (
            existing["_id"]
            if existing
            else client_encryption.create_data_key("local", key_alt_names=[alt])
        )

    encrypted_fields = {
        "fields": [
            {
                "path": "origin",
                "bsonType": "string",
                "keyId": key_ids["origin"],
                "queries": {"queryType": "equality"},
            },
            {"path": "cookies", "bsonType": "string", "keyId": key_ids["cookies"]},
            {"path": "headers_json", "bsonType": "string", "keyId": key_ids["headers_json"]},
        ]
    }

    db = setup_client.get_default_database(default="r3d")
    if "r3d_credentials" not in db.list_collection_names():
        try:
            client_encryption.create_encrypted_collection(
                db, "r3d_credentials", encrypted_fields, "local", local_master_key,
            )
            print("CSFLE: Created encrypted collection r3d.r3d_credentials")
        except Exception as e:
            print(f"CSFLE: Warning during collection setup: {e}")

    client_encryption.close()
    setup_client.close()

    opts_kwargs: dict[str, Any] = {
        "kms_providers": kms_providers,
        "key_vault_namespace": key_vault_namespace,
        "encrypted_fields_map": {"r3d.r3d_credentials": encrypted_fields},
    }
    if crypt_shared_lib_path:
        opts_kwargs["crypt_shared_lib_path"] = crypt_shared_lib_path

    return AutoEncryptionOpts(**opts_kwargs), {
        "status": "enabled",
        "collection": "r3d.r3d_credentials",
        "encrypted_fields": ["origin", "cookies", "headers_json"],
    }


def get_sessions_col(request: Request):
    """Return the sessions collection or raise 503 if MongoDB is not configured."""
    col = request.app.state.sessions_col
    if col is None:
        raise HTTPException(status_code=503, detail="MDB_URI not configured — session persistence unavailable")
    return col


def get_overflow_col(request: Request):
    """Return the event overflow collection."""
    return request.app.state.overflow_col


def serialize_dates(doc: dict[str, Any]):
    """Convert datetime objects to ISO strings for JSON serialization."""
    for key in ("startedAt", "endedAt"):
        if isinstance(doc.get(key), datetime):
            doc[key] = doc[key].isoformat()
