"""MongoDB client helpers and CSFLE bootstrap."""

import base64
import json
import os
import ssl
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from bson.binary import STANDARD
from bson.codec_options import CodecOptions
from fastapi import HTTPException, Request
from pymongo import MongoClient
from pymongo.encryption import Algorithm, AutoEncryptionOpts, ClientEncryption

_FIELD_DEFS = [
    ("origin",       True),
    ("cookies",      False),
    ("headers_json", False),
]

_MAX_BOOTSTRAP_RETRIES = 5


def _build_aws_kms_config() -> tuple[str, str, dict, dict, str, dict] | None:
    """Parse AWS KMS configuration from environment. Returns None on missing ARN.

    Returns (key_arn, region, kms_providers, master_key, kms_endpoint, kms_tls_options).
    """
    key_arn = os.environ.get("AWS_KMS_KEY_ARN", "")
    if not key_arn:
        arn_file = Path("/kms-config/arn.txt")
        if arn_file.exists():
            key_arn = arn_file.read_text().strip()
        else:
            return None

    try:
        region = key_arn.split(":")[3]
    except IndexError:
        region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    aws_config: dict[str, Any] = {}
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    if access_key and secret_key:
        aws_config["accessKeyId"] = access_key
        aws_config["secretAccessKey"] = secret_key

    master_key: dict[str, Any] = {"region": region, "key": key_arn}
    kms_endpoint = os.environ.get("AWS_KMS_ENDPOINT", "")
    if kms_endpoint:
        master_key["endpoint"] = kms_endpoint

    kms_tls_options: dict = {}
    if kms_endpoint:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        kms_tls_options = {"aws": ssl_context}

    return key_arn, region, {"aws": aws_config}, master_key, kms_endpoint, kms_tls_options


def _csfle_smoke_test(client_encryption: ClientEncryption, key_ids: dict) -> None:
    """Encrypt + decrypt a test value to verify the full KMS -> DEK chain works."""
    sentinel = "r3d-smoke-test"
    encrypted = client_encryption.encrypt(
        sentinel,
        Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random,
        key_id=key_ids["cookies"],
    )
    decrypted = client_encryption.decrypt(encrypted)
    if decrypted != sentinel:
        raise RuntimeError(
            f"Smoke test failed: expected '{sentinel}', got '{decrypted}'"
        )


def _bootstrap_aws_kms(mdb_uri: str) -> tuple[AutoEncryptionOpts | None, dict]:
    """Bootstrap CSFLE with AWS KMS provider.

    Retries up to _MAX_BOOTSTRAP_RETRIES times with exponential backoff to
    handle transient KMS/TLS issues (especially with LocalStack HTTPS).
    After bootstrap, runs a smoke test that encrypts and decrypts a test
    value to prove the full chain works end-to-end.

    Development (LocalStack):
      - Reads key ARN from /kms-config/arn.txt (written by kms-init sidecar)
      - Uses hardcoded test credentials (AWS_ACCESS_KEY_ID=test)
      - Points to LocalStack endpoint (AWS_KMS_ENDPOINT=localstack:4566)
      - Disables TLS verification for LocalStack's self-signed cert

    Production (Real AWS KMS):
      - AWS_KMS_KEY_ARN env var contains the CMK ARN
      - IAM role-based authentication (no AWS_ACCESS_KEY_ID needed)
      - AWS_KMS_ENDPOINT should be UNSET (defaults to real AWS)
      - TLS verification ENABLED (secure by default)
    """
    config = _build_aws_kms_config()
    if config is None:
        print("CSFLE: AWS_KMS_KEY_ARN not set and /kms-config/arn.txt not found")
        return None, {"status": "error", "reason": "missing KMS key ARN"}

    key_arn, region, kms_providers, master_key, kms_endpoint, kms_tls_options = config
    key_vault_namespace = "encryption.__r3dKeyVault"
    crypt_shared_lib_path = os.environ.get("CRYPT_SHARED_LIB_PATH", "")

    last_error: Exception | None = None
    for attempt in range(1, _MAX_BOOTSTRAP_RETRIES + 1):
        setup_client = None
        client_encryption = None
        try:
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
                kms_tls_options=kms_tls_options if kms_tls_options else None,
            )

            key_ids = {}
            for name, _ in _FIELD_DEFS:
                alt = f"r3d-{name}"
                existing = kv.find_one({"keyAltNames": alt})
                key_ids[name] = (
                    existing["_id"]
                    if existing
                    else client_encryption.create_data_key(
                        "aws", master_key=master_key, key_alt_names=[alt]
                    )
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
                        db, "r3d_credentials", encrypted_fields, "aws", master_key,
                    )
                except Exception as e:
                    print(f"CSFLE: Warning during collection setup: {e}")

            _csfle_smoke_test(client_encryption, key_ids)

            client_encryption.close()
            setup_client.close()

            opts_kwargs: dict[str, Any] = {
                "kms_providers": kms_providers,
                "key_vault_namespace": key_vault_namespace,
                "encrypted_fields_map": {"r3d.r3d_credentials": encrypted_fields},
            }
            if crypt_shared_lib_path:
                opts_kwargs["crypt_shared_lib_path"] = crypt_shared_lib_path
            if kms_tls_options:
                opts_kwargs["kms_tls_options"] = kms_tls_options

            print(f"CSFLE: ✓ AWS KMS verified — round-trip encrypt/decrypt passed "
                  f"({len(key_ids)} DEKs, {len(encrypted_fields['fields'])} encrypted fields)")
            return AutoEncryptionOpts(**opts_kwargs), {
                "status": "enabled",
                "provider": "aws",
                "region": region,
                "keyArn": key_arn,
                "collection": "r3d.r3d_credentials",
                "encrypted_fields": ["origin", "cookies", "headers_json"],
                "verified": True,
            }

        except Exception as e:
            last_error = e
            for obj in (client_encryption, setup_client):
                if obj is not None:
                    try:
                        obj.close()
                    except Exception:
                        pass
            if attempt < _MAX_BOOTSTRAP_RETRIES:
                delay = 2 ** attempt
                print(f"CSFLE: Attempt {attempt}/{_MAX_BOOTSTRAP_RETRIES} failed "
                      f"({e}), retrying in {delay}s...")
                time.sleep(delay)

    print(f"CSFLE: ✗ All {_MAX_BOOTSTRAP_RETRIES} attempts failed: {last_error}")
    return None, {"status": "error", "reason": str(last_error)}


def bootstrap_csfle(mdb_uri: str) -> tuple[AutoEncryptionOpts | None, dict]:
    """Sync one-time setup: key vault, data key, encrypted collection.

    Returns (auto_encryption_opts, info_dict).

    KMS Provider Selection (via KMS_PROVIDER env var):
      - "aws": AWS KMS with IAM authentication (recommended for production)
      - "local": Local master key (insecure, dev/test only)
      - unset/empty: CSFLE disabled, no encryption

    AWS KMS PRODUCTION SETUP:
      1. Create a CMK in AWS KMS:
           aws kms create-key --description "R3D CSFLE Master Key"

      2. Enable automatic key rotation:
           aws kms enable-key-rotation --key-id <key-id>

      3. Create a restrictive key policy (only your service's IAM role):
           {
             "Version": "2012-10-17",
             "Statement": [{
               "Sid": "Allow R3D service to use the key",
               "Effect": "Allow",
               "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/R3DServiceRole"},
               "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
               "Resource": "*"
             }]
           }

      4. Assign an IAM role to your service (EC2/ECS/EKS):
           - EC2: Instance profile with kms:Encrypt/Decrypt/GenerateDataKey
           - ECS: Task role with same permissions
           - EKS: IRSA (IAM Roles for Service Accounts)

      5. Environment variables for production:
           KMS_PROVIDER=aws
           AWS_KMS_KEY_ARN=arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID
           AWS_DEFAULT_REGION=us-east-1
           # NO AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY — use IAM role!
           # NO AWS_KMS_ENDPOINT — defaults to real AWS KMS
    """
    kms_provider = os.environ.get("KMS_PROVIDER", "").lower()

    # ─── AWS KMS Provider ────────────────────────────────────────────────
    if kms_provider == "aws":
        return _bootstrap_aws_kms(mdb_uri)

    # ─── Local Provider (Legacy) ─────────────────────────────────────────
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

    key_ids = {}
    for name, _ in _FIELD_DEFS:
        alt = f"r3d-{name}"
        existing = kv.find_one({"keyAltNames": alt})
        key_ids[name] = (
            existing["_id"]
            if existing
            else client_encryption.create_data_key(
                "local",
                master_key=None,
                key_alt_names=[alt]
            )
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
        except Exception as e:
            print(f"CSFLE: Warning during collection setup: {e}")

    _csfle_smoke_test(client_encryption, key_ids)

    client_encryption.close()
    setup_client.close()

    opts_kwargs: dict[str, Any] = {
        "kms_providers": kms_providers,
        "key_vault_namespace": key_vault_namespace,
        "encrypted_fields_map": {"r3d.r3d_credentials": encrypted_fields},
    }
    if crypt_shared_lib_path:
        opts_kwargs["crypt_shared_lib_path"] = crypt_shared_lib_path

    print(f"CSFLE: ✓ Local provider verified — round-trip encrypt/decrypt passed "
          f"({len(key_ids)} DEKs, {len(encrypted_fields['fields'])} encrypted fields)")
    return AutoEncryptionOpts(**opts_kwargs), {
        "status": "enabled",
        "provider": "local",
        "collection": "r3d.r3d_credentials",
        "encrypted_fields": ["origin", "cookies", "headers_json"],
        "verified": True,
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
