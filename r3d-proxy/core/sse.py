"""Server-Sent Events broadcast bus."""

import asyncio
import json

subscribers: list[asyncio.Queue] = []


def broadcast(event_type: str, payload: dict):
    msg = json.dumps({"type": event_type, **payload}, default=str)
    for q in list(subscribers):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass
