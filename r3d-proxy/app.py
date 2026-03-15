"""R3D Proxy Server — FastAPI application factory.

Assembles the app from core modules and routers, runs lifespan setup
(MongoDB, CSFLE, payloads), and mounts static files.
"""

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo import AsyncMongoClient

from core.config import CORS_ORIGINS, MDB_URI
from core.db import bootstrap_csfle
from core.replay import auth_contexts, load_payloads
from routers import (
    attacks,
    auth,
    auth_context,
    dashboard,
    graphs,
    llm,
    opsec,
    plans,
    proofs,
    reports,
    scans,
    sessions,
    specs,
    tests,
    tools,
    webhooks,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_payloads()
    if MDB_URI:
        auto_enc_opts, csfle_info = bootstrap_csfle(MDB_URI)
        app.state.csfle_info = csfle_info

        client = AsyncMongoClient(MDB_URI, auto_encryption_opts=auto_enc_opts)
        db = client.get_default_database(default="r3d")
        app.state.sessions_col = db["r3d_sessions"]
        app.state.overflow_col = db["r3d_event_overflow"]
        app.state.specs_col = db["r3d_specs"]
        app.state.graphs_col = db["r3d_attack_graphs"]
        app.state.credentials_col = db["r3d_credentials"]
        app.state.users_col = db["r3d_users"]
        app.state.audit_col = db["r3d_audit_log"]
        await app.state.sessions_col.create_index("startedAt", background=True)
        await app.state.overflow_col.create_index(
            [("sessionId", 1), ("seq", 1)], background=True
        )
        await app.state.specs_col.create_index("importedAt", background=True)
        await app.state.graphs_col.create_index("sessionId", background=True)
        await app.state.users_col.create_index("username", unique=True, background=True)
        await app.state.audit_col.create_index("ts", background=True)

        try:
            async for doc in app.state.credentials_col.find():
                auth_contexts[doc["origin"]] = {
                    "cookies": doc.get("cookies", ""),
                    "headers": json.loads(doc.get("headers_json", "{}")),
                    "userAgent": doc.get("userAgent", ""),
                    "ts": str(doc.get("capturedAt", "")),
                }
        except Exception:
            pass
    else:
        app.state.sessions_col = None
        app.state.overflow_col = None
        app.state.specs_col = None
        app.state.graphs_col = None
        app.state.credentials_col = None
        app.state.users_col = None
        app.state.audit_col = None
        app.state.csfle_info = {"status": "disabled"}
    yield


app = FastAPI(title="R3D Proxy", version="5.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Include Routers ─────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(llm.router)
app.include_router(sessions.router)
app.include_router(tests.router)
app.include_router(opsec.router)
app.include_router(auth_context.router)
app.include_router(attacks.router)
app.include_router(scans.router)
app.include_router(specs.router)
app.include_router(tools.router)
app.include_router(graphs.router)
app.include_router(plans.router)
app.include_router(proofs.router)
app.include_router(reports.router)
app.include_router(webhooks.router)
app.include_router(dashboard.router)

# ─── Static Files ────────────────────────────────────────────────────

_static_dir = Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# ─── Dev Entrypoint ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "4000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
