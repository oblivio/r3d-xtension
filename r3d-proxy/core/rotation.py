"""Secret rotation for JWT tokens and API keys.

Implements automatic key rotation with zero-downtime transitions.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

# ─── Rotation State ──────────────────────────────────────────────────

_rotation_state = {
    "current_secret": None,
    "previous_secret": None,
    "rotation_time": None,
}

ROTATION_INTERVAL_HOURS = int(os.environ.get("JWT_ROTATION_HOURS", "168"))  # 7 days default


def _load_or_generate_secret(key_name: str) -> str:
    """Load secret from file or generate new one."""
    secret_file = Path(f"/tmp/r3d/{key_name}.key")
    secret_file.parent.mkdir(parents=True, exist_ok=True)

    if secret_file.exists():
        return secret_file.read_text().strip()

    new_secret = secrets.token_urlsafe(48)
    secret_file.write_text(new_secret)
    secret_file.chmod(0o600)
    return new_secret


def initialize_rotation():
    """Initialize or load rotation state on startup."""
    _rotation_state["current_secret"] = _load_or_generate_secret("jwt_current")
    _rotation_state["previous_secret"] = _load_or_generate_secret("jwt_previous")

    rotation_file = Path("/tmp/r3d/last_rotation.txt")
    if rotation_file.exists():
        timestamp = rotation_file.read_text().strip()
        _rotation_state["rotation_time"] = datetime.fromisoformat(timestamp)
    else:
        _rotation_state["rotation_time"] = datetime.now(timezone.utc)
        rotation_file.write_text(_rotation_state["rotation_time"].isoformat())


def should_rotate() -> bool:
    """Check if secrets should be rotated."""
    if not _rotation_state["rotation_time"]:
        return False

    elapsed = datetime.now(timezone.utc) - _rotation_state["rotation_time"]
    return elapsed > timedelta(hours=ROTATION_INTERVAL_HOURS)


def rotate_secrets():
    """Rotate JWT signing keys with zero-downtime transition."""
    _rotation_state["previous_secret"] = _rotation_state["current_secret"]
    _rotation_state["current_secret"] = secrets.token_urlsafe(48)
    _rotation_state["rotation_time"] = datetime.now(timezone.utc)

    # Persist to disk
    Path("/tmp/r3d/jwt_current.key").write_text(_rotation_state["current_secret"])
    Path("/tmp/r3d/jwt_previous.key").write_text(_rotation_state["previous_secret"])
    Path("/tmp/r3d/last_rotation.txt").write_text(_rotation_state["rotation_time"].isoformat())


def get_current_secret() -> str:
    """Get current JWT signing secret."""
    if not _rotation_state["current_secret"]:
        initialize_rotation()
    return _rotation_state["current_secret"]


def verify_token_with_rotation(token: str, algorithm: str = "HS256") -> dict:
    """Verify JWT token, trying current secret then previous (for rotation grace period)."""
    # Try current secret first
    try:
        return jwt.decode(token, get_current_secret(), algorithms=[algorithm])
    except jwt.InvalidSignatureError:
        pass

    # Try previous secret (allows tokens signed before rotation to still work)
    if _rotation_state["previous_secret"]:
        try:
            return jwt.decode(token, _rotation_state["previous_secret"], algorithms=[algorithm])
        except jwt.InvalidSignatureError:
            pass

    raise jwt.InvalidTokenError("Token signature invalid with current and previous secrets")
