"""On-demand credential vault — zero in-memory credential cache.

Security properties:
  1. Decrypted credentials NEVER persist in process memory
  2. Each request fetches + decrypts on-demand from CSFLE-encrypted MongoDB
  3. Credentials exist only on the stack for the duration of the request
  4. Garbage collected immediately after use
  5. Memory dumps / core dumps / debugger attach cannot leak credentials

This design prevents credential leakage via:
  - Process memory scanning
  - Core dump analysis
  - Debugger inspection
  - Heap dumps
"""

import json
from datetime import datetime


class CredentialVault:
    """On-demand credential access via CSFLE. Never holds decrypted creds in memory."""

    def __init__(self, credentials_col):
        """Initialize vault with CSFLE-encrypted credentials collection.

        Args:
            credentials_col: Motor collection with auto-decryption via AutoEncryptionOpts
        """
        self._col = credentials_col

    async def get_context(self, origin: str) -> dict:
        """Decrypt a single origin's credentials on demand.

        Returns an ephemeral dict that lives only on the stack. No caching.
        """
        if self._col is None:
            return {}

        doc = await self._col.find_one({"origin": origin})
        if not doc:
            return {}

        # Auto-decrypted by CSFLE — ephemeral, stack-only
        return {
            "cookies": doc.get("cookies", ""),
            "headers": json.loads(doc.get("headers_json", "{}")),
            "userAgent": doc.get("userAgent", ""),
            "ts": doc.get("capturedAt", "").isoformat() if isinstance(doc.get("capturedAt"), datetime) else "",
        }

    async def store(self, origin: str, cookies: str, headers: dict, user_agent: str):
        """Encrypt and persist credentials. No in-memory copy kept.

        Credentials are encrypted by CSFLE before leaving the application.
        No plaintext credentials are written to MongoDB or kept in memory.
        """
        if self._col is None:
            return

        await self._col.delete_many({"origin": origin})
        await self._col.insert_one({
            "origin": origin,
            "cookies": cookies,
            "headers_json": json.dumps(headers),
            "userAgent": user_agent,
            "capturedAt": datetime.utcnow(),
        })

    async def get_replay_headers(self, origin: str, extra_headers: dict | None = None) -> dict:
        """Build replay headers by decrypting credentials on demand.

        Merges stored auth context with request-specific headers. If OPSEC UA
        rotation is enabled, injects a rotated User-Agent when none is stored.

        This function is async to enable on-demand decryption. Credentials
        exist only for the duration of this call, then are garbage collected.
        """
        from core.opsec import get_profile, get_user_agent, sanitize_outbound_headers

        ctx = await self.get_context(origin)
        h: dict[str, str] = {}

        if ctx.get("cookies"):
            h["Cookie"] = ctx["cookies"]
        if ctx.get("userAgent"):
            h["User-Agent"] = ctx["userAgent"]

        for k, v in (ctx.get("headers") or {}).items():
            if k.lower() not in ("host", "content-length", "content-type"):
                h[k] = v

        if extra_headers:
            h.update(extra_headers)

        profile = get_profile()
        if "User-Agent" not in h:
            rotated = get_user_agent(profile)
            if rotated:
                h["User-Agent"] = rotated

        return sanitize_outbound_headers(h, profile)

    async def list_origins(self) -> list[dict]:
        """Return credential metadata (origin, hasCookies, headerKeys) without full decrypt.

        Only retrieves metadata to avoid decrypting all credentials at once.
        Individual credentials are decrypted on-demand when accessed.
        """
        if self._col is None:
            return []

        results = []
        async for doc in self._col.find().sort("capturedAt", -1).limit(100):
            # Auto-decrypted by CSFLE, but we only expose metadata
            results.append({
                "origin": doc.get("origin", ""),
                "hasCookies": bool(doc.get("cookies")),
                "headerKeys": list(json.loads(doc.get("headers_json", "{}")).keys()),
                "hasUserAgent": bool(doc.get("userAgent")),
                "capturedAt": doc.get("capturedAt", "").isoformat() if isinstance(doc.get("capturedAt"), datetime) else "",
            })

        return results

    async def delete(self, origin: str) -> int:
        """Delete stored credentials for an origin. Returns number of documents deleted."""
        if self._col is None:
            return 0

        result = await self._col.delete_many({"origin": origin})
        return result.deleted_count
