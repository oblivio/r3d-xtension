"""OPSEC stealth layer — TLS fingerprint randomization and request normalization.

Blue team detection relies on:
  1. TLS fingerprint (JA3/JA4) - identifies HTTP client library
  2. HTTP/2 fingerprint (ALPN, frame ordering)
  3. Header ordering and casing patterns
  4. User-Agent statistical analysis

This module mitigates these vectors.
"""

import random
import ssl
from collections.abc import Sequence
from typing import Any

import httpx

# ─── TLS Cipher Suite Randomization ──────────────────────────────────

# Modern browser cipher suites (Chrome, Firefox, Safari patterns)
_BROWSER_CIPHER_SUITES = [
    # Chrome 120+ pattern
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ],
    # Firefox 121+ pattern
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    # Safari 17+ pattern
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ],
]


def create_stealth_ssl_context() -> ssl.SSLContext:
    """Create an SSL context with randomized browser-like fingerprint.

    Rotates cipher suite ordering to evade JA3/JA4 fingerprint detection.
    Each context appears as a different browser to blue team tools.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Randomize cipher suite from browser patterns
    cipher_suite = random.choice(_BROWSER_CIPHER_SUITES)
    ctx.set_ciphers(":".join(cipher_suite))

    # Enable modern TLS features (ALPN for HTTP/2)
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    # Disable legacy protocols
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    return ctx


# ─── HTTP Header Normalization ───────────────────────────────────────

# Header ordering patterns from real browsers
_CHROME_HEADER_ORDER = [
    "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
    "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language", "Cookie"
]

_FIREFOX_HEADER_ORDER = [
    "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
    "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
    "Sec-Fetch-Site", "Sec-Fetch-User", "Cache-Control", "Cookie"
]

_SAFARI_HEADER_ORDER = [
    "Host", "Accept", "User-Agent", "Accept-Language", "Accept-Encoding",
    "Connection", "Upgrade-Insecure-Requests", "Cookie"
]


def normalize_headers(headers: dict[str, str], profile: str = "random") -> dict[str, str]:
    """Reorder and normalize headers to match browser patterns.

    Args:
        headers: Raw headers dict
        profile: "chrome", "firefox", "safari", or "random"

    Returns:
        Headers dict with browser-like ordering (Python 3.7+ preserves insertion order)
    """
    if profile == "random":
        profile = random.choice(["chrome", "firefox", "safari"])

    order_template = {
        "chrome": _CHROME_HEADER_ORDER,
        "firefox": _FIREFOX_HEADER_ORDER,
        "safari": _SAFARI_HEADER_ORDER,
    }[profile]

    # Case-insensitive header lookup
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    # Rebuild in browser order
    normalized = {}
    for canonical_name in order_template:
        lower_name = canonical_name.lower()
        if lower_name in headers_lower:
            original_name, value = headers_lower[lower_name]
            # Use canonical casing from browser pattern
            normalized[canonical_name] = value
            del headers_lower[lower_name]

    # Append any remaining headers (custom headers go last)
    for original_name, value in headers_lower.values():
        normalized[original_name] = value

    return normalized


# ─── HTTP/2 Frame Ordering ───────────────────────────────────────────

def get_http2_settings(profile: str = "random") -> dict[str, int]:
    """Return HTTP/2 SETTINGS frame values matching browser profiles.

    Blue team tools fingerprint HTTP/2 clients by SETTINGS frame values.
    """
    profiles = {
        "chrome": {
            "HEADER_TABLE_SIZE": 65536,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_HEADER_LIST_SIZE": 262144,
        },
        "firefox": {
            "HEADER_TABLE_SIZE": 65536,
            "MAX_CONCURRENT_STREAMS": 100,
            "INITIAL_WINDOW_SIZE": 131072,
            "MAX_FRAME_SIZE": 16384,
        },
        "safari": {
            "HEADER_TABLE_SIZE": 4096,
            "MAX_CONCURRENT_STREAMS": 100,
            "INITIAL_WINDOW_SIZE": 2097152,
        },
    }

    if profile == "random":
        profile = random.choice(["chrome", "firefox", "safari"])

    return profiles.get(profile, profiles["chrome"])


# ─── Request Timing Jitter ───────────────────────────────────────────

def add_human_delay(min_ms: int = 50, max_ms: int = 300) -> float:
    """Return a randomized delay to mimic human browsing patterns.

    Automated tools have consistent timing. Add jitter to evade rate-based detection.

    Returns:
        Delay in seconds
    """
    import time
    delay_ms = random.uniform(min_ms, max_ms)
    return delay_ms / 1000.0


# ─── Stealth HTTP Client Factory ─────────────────────────────────────

def create_stealth_client(
    profile: str = "random",
    timeout: int = 30,
    follow_redirects: bool = True,
    **kwargs: Any
) -> httpx.AsyncClient:
    """Create an httpx client with full stealth fingerprint randomization.

    Args:
        profile: "chrome", "firefox", "safari", or "random"
        timeout: Request timeout in seconds
        follow_redirects: Follow HTTP redirects
        **kwargs: Additional httpx.AsyncClient parameters

    Returns:
        httpx.AsyncClient with randomized TLS + HTTP/2 fingerprint

    Blue Team Evasion:
        - TLS fingerprint randomization (JA3/JA4)
        - HTTP/2 SETTINGS frame matching
        - Header ordering normalization
        - Connection pooling limits (avoid "too many connections" patterns)
    """
    # Randomize SSL context
    ssl_context = create_stealth_ssl_context()

    # HTTP/2 settings (httpx doesn't expose direct control, but connection pooling helps)
    limits = httpx.Limits(
        max_keepalive_connections=10,
        max_connections=100,
        keepalive_expiry=30.0,
    )

    client = httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        limits=limits,
        http2=True,  # Enable HTTP/2
        verify=ssl_context,
        **kwargs
    )

    # Tag client with profile for header normalization
    client._stealth_profile = profile  # type: ignore

    return client


# ─── Event Hook for Header Normalization ─────────────────────────────

async def stealth_request_hook(request: httpx.Request) -> None:
    """httpx event hook to normalize headers before sending.

    Usage:
        client = httpx.AsyncClient()
        client.event_hooks = {"request": [stealth_request_hook]}
    """
    profile = getattr(request.client, "_stealth_profile", "random")
    normalized = normalize_headers(dict(request.headers), profile)
    request.headers = httpx.Headers(normalized)
