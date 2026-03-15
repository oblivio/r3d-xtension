"""Centralised configuration — all env vars and shared constants."""

import os
from datetime import datetime, timezone

MDB_URI = os.environ.get("MDB_URI", "")
DEFAULT_MODEL = os.environ.get("LITELLM_MODEL", "gemini/gemini-2.5-pro")
R3D_API_KEY = os.environ.get("R3D_API_KEY", "")

_DEFAULT_CORS = "http://localhost:4000,http://127.0.0.1:4000"
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("CORS_ORIGINS", _DEFAULT_CORS).split(",")
    if o.strip()
]

SSL_VERIFY: bool = os.environ.get("R3D_SSL_VERIFY", "true").lower() != "false"

EVENT_OVERFLOW_THRESHOLD = 1000

OPEN_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "*",
}


def now() -> datetime:
    return datetime.now(timezone.utc)
