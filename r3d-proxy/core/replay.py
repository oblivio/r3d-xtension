"""Payload loading and HTTP client helpers.

Credential replay is handled by core.vault.CredentialVault (on-demand CSFLE
decrypt). This module retains only payload management and the HTTP client
factory — no credential state lives here.
"""

import json
from pathlib import Path

import httpx

from core.config import SSL_VERIFY

payloads: dict[str, list[str]] = {}
payload_meta: dict[str, dict] = {}


def load_payloads():
    payload_dir = Path(__file__).parent.parent / "payloads"
    if not payload_dir.is_dir():
        return
    for f in payload_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, dict) and "payloads" in data:
                payloads[f.stem] = data["payloads"]
                payload_meta[f.stem] = {
                    k: v for k, v in data.items() if k != "payloads"
                }
            elif isinstance(data, list):
                payloads[f.stem] = data
        except Exception:
            pass


def get_http_client(stealth: bool = True, **kwargs) -> httpx.AsyncClient:
    """Return an httpx client with optional stealth fingerprint randomization.

    Args:
        stealth: Enable TLS + HTTP/2 fingerprint randomization (default: True)
        **kwargs: Additional httpx.AsyncClient parameters

    When stealth=True:
        - Randomizes TLS cipher suite ordering (evades JA3/JA4 detection)
        - Normalizes HTTP header ordering to match browsers
        - Enables HTTP/2 with browser-like SETTINGS frames
        - Adds connection pooling limits to avoid "automated tool" patterns

    When stealth=False:
        - Uses default httpx behavior (for testing/debugging)
    """
    if stealth:
        from core.stealth import create_stealth_client
        return create_stealth_client(**kwargs)

    kwargs.setdefault("verify", SSL_VERIFY)
    return httpx.AsyncClient(**kwargs)
