"""Shared in-memory state used across multiple routers."""

from typing import Any

pending_tests: dict = {}
test_log: dict = {}
active_scans: dict[str, dict] = {}
active_plans: dict = {}
phish_sites: dict[str, dict] = {}
relay_sessions: dict[str, dict] = {}
webhooks: list[dict] = []

extension_heartbeat: dict[str, Any] = {
    "lastSeen": None,
    "sessionId": None,
    "sessionName": None,
    "sessionState": None,
    "pendingEvents": 0,
    "counters": {},
}
