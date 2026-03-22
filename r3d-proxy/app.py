"""R3D Proxy Server — FastAPI application factory.

Assembles the app from core modules and routers, runs lifespan setup
(MongoDB, Queryable Encryption, payloads), and mounts static files.
"""

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo import AsyncMongoClient

from core.config import CORS_ORIGINS, MDB_URI
from core.db import bootstrap_qe, compact_qe_metadata
from core.replay import load_payloads
from core.vault import CredentialVault
from routers import (
    attacks,
    auth,
    auth_context,
    dashboard,
    graphs,
    llm,
    opsec,
    phish,
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
    # Initialize JWT secret rotation
    if not os.environ.get("R3D_JWT_SECRET"):
        from core.rotation import initialize_rotation
        initialize_rotation()
        print("JWT secret rotation initialized")

    load_payloads()
    if MDB_URI:
        auto_enc_opts, qe_info = bootstrap_qe(MDB_URI)
        app.state.qe_info = qe_info

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

        # Initialize on-demand credential vault (zero in-memory credential cache)
        app.state.credential_vault = CredentialVault(app.state.credentials_col)
    else:
        app.state.sessions_col = None
        app.state.overflow_col = None
        app.state.specs_col = None
        app.state.graphs_col = None
        app.state.credentials_col = None
        app.state.users_col = None
        app.state.audit_col = None
        app.state.qe_info = {"status": "disabled"}
        app.state.credential_vault = CredentialVault(None)
    yield
    # Graceful shutdown: compact QE metadata to prevent ECOC bloat
    if MDB_URI and getattr(app.state, "sessions_col", None) is not None:
        db = app.state.sessions_col.database
        await compact_qe_metadata(db)


app = FastAPI(title="R3D Proxy", version="5.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicit methods only
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "User-Agent"],  # Explicit headers only
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
app.include_router(phish.router)
app.include_router(proofs.router)
app.include_router(reports.router)
app.include_router(webhooks.router)
app.include_router(dashboard.router)

# ─── Static Files ────────────────────────────────────────────────────

_static_dir = Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# ─── Dependencies ────────────────────────────────────────────────────


def get_vault(request: Request) -> CredentialVault:
    """FastAPI dependency to access the on-demand credential vault."""
    return request.app.state.credential_vault


# ─── Dev Entrypoint ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "4000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
