"""Security event monitoring and alerting.

Tracks anomalous behavior patterns without triggering blue team alerts:
  - Credential access spikes
  - Failed handshake attempts
  - Rate limit hits
  - JWT verification failures
  - KMS decrypt errors

Metrics are exposed internally only (no external metrics endpoints).
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Literal

# ─── Event Tracking ──────────────────────────────────────────────────

SecurityEventType = Literal[
    "credential_access",
    "handshake_attempt",
    "handshake_denied",
    "rate_limit_hit",
    "jwt_verification_failed",
    "kms_decrypt_error",
    "suspicious_pattern"
]

# Rolling window event storage (last 1000 events)
_security_events: deque = deque(maxlen=1000)

# Counters by event type and time window
_event_counters: dict[str, list[float]] = defaultdict(list)

# Anomaly detection thresholds
THRESHOLDS = {
    "credential_access": {"window_minutes": 5, "max_count": 50},
    "handshake_denied": {"window_minutes": 5, "max_count": 10},
    "rate_limit_hit": {"window_minutes": 10, "max_count": 5},
    "jwt_verification_failed": {"window_minutes": 5, "max_count": 20},
    "kms_decrypt_error": {"window_minutes": 10, "max_count": 3},
}


def track_event(
    event_type: SecurityEventType,
    ip: str = "",
    user: str = "",
    detail: dict | None = None
):
    """Track a security event for monitoring and anomaly detection."""
    event = {
        "type": event_type,
        "timestamp": datetime.now(timezone.utc),
        "ip": ip,
        "user": user,
        "detail": detail or {},
    }

    _security_events.append(event)
    _event_counters[event_type].append(event["timestamp"].timestamp())

    # Clean old counters (keep last hour only)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
    _event_counters[event_type] = [
        ts for ts in _event_counters[event_type] if ts > cutoff
    ]

    # Check for anomalies
    if _is_anomalous(event_type):
        _alert_anomaly(event_type, event)


def _is_anomalous(event_type: SecurityEventType) -> bool:
    """Check if event rate exceeds threshold."""
    threshold = THRESHOLDS.get(event_type)
    if not threshold:
        return False

    window_start = (
        datetime.now(timezone.utc) - timedelta(minutes=threshold["window_minutes"])
    ).timestamp()

    recent_count = sum(
        1 for ts in _event_counters[event_type] if ts >= window_start
    )

    return recent_count > threshold["max_count"]


def _alert_anomaly(event_type: SecurityEventType, event: dict):
    """Handle anomaly detection (internal logging only, no external alerts)."""
    print(f"⚠️  SECURITY ANOMALY: {event_type} rate exceeded threshold")
    print(f"   Event: {event}")
    # In production, send to internal SIEM or log aggregator
    # DO NOT expose external metrics endpoints (would reveal to blue team)


def get_security_metrics() -> dict:
    """Get current security metrics (internal use only)."""
    now = datetime.now(timezone.utc)

    # Calculate rates for different time windows
    windows = {
        "1m": timedelta(minutes=1),
        "5m": timedelta(minutes=5),
        "1h": timedelta(hours=1),
    }

    metrics = {}
    for event_type in _event_counters:
        metrics[event_type] = {}
        for window_name, window_delta in windows.items():
            cutoff = (now - window_delta).timestamp()
            count = sum(1 for ts in _event_counters[event_type] if ts >= cutoff)
            metrics[event_type][window_name] = count

    return {
        "timestamp": now.isoformat(),
        "rates": metrics,
        "total_events": len(_security_events),
        "anomalies_detected": sum(1 for e in _security_events if e.get("detail", {}).get("anomaly")),
    }


def get_recent_events(count: int = 100) -> list[dict]:
    """Get recent security events (internal use only)."""
    return list(_security_events)[-count:]
