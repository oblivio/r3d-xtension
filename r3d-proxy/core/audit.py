"""Audit logging — records security-relevant actions to r3d_audit_log."""

from datetime import datetime, timezone

from fastapi import Request


async def audit_log(request: Request, action: str, resource: str = "", detail: dict | None = None):
    """Write an audit log entry. Silently no-ops if the audit collection is unavailable."""
    user = getattr(request.state, "user", None)
    doc = {
        "ts": datetime.now(timezone.utc),
        "userId": user["_id"] if user else "anonymous",
        "username": user["username"] if user else "api-key",
        "action": action,
        "resource": resource,
        "detail": detail or {},
        "ip": request.client.host if request.client else "",
        "userAgent": request.headers.get("user-agent", ""),
    }
    col = getattr(request.app.state, "audit_col", None)
    if col is not None:
        try:
            await col.insert_one(doc)
        except Exception:
            pass
