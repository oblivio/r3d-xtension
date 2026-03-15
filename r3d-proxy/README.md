# R3D Proxy Server

FastAPI backend that provides MongoDB-backed session persistence and LLM routing via [LiteLLM](https://github.com/BerriAI/litellm) for the R3D Chrome extension.

## Prerequisites

- Python 3.10+
- MongoDB 6.0+ (required for session persistence)
- A Gemini, OpenAI, or Azure OpenAI API key (for LLM routing)

## Quick Start

```bash
cd r3d-proxy

# Install dependencies
pip install -r requirements.txt

# Set required environment variables
export MDB_URI="mongodb://localhost:27017/r3d"
export GEMINI_API_KEY="your-gemini-key"      # or OPENAI_API_KEY / AZURE_API_KEY

# Start the server
uvicorn app:app --host 0.0.0.0 --port 4000
```

The server starts on `http://0.0.0.0:4000`.

## Docker (Recommended)

Spins up [MongoDB Atlas Local](https://hub.docker.com/r/mongodb/mongodb-atlas-local) (8.0) + the proxy in one command with a stable local API key:

```bash
cd r3d-proxy
cp .env.example .env          # add your LLM provider key (Gemini, OpenAI, or Azure)
docker compose up --build
```

The proxy auto-generates a unique `R3D_API_KEY` on each startup and prints it to the console. Override it in `.env` if you want a stable key across restarts.

The Atlas Local image includes a full single-node replica set with Atlas Search and Atlas Vector Search support out of the box. Data is persisted in Docker named volumes (`mongodb_db`, `mongodb_configdb`, `mongodb_mongot`).

To tear down containers only (data preserved):

```bash
docker compose down
```

To fully reset (containers + data volumes):

```bash
docker compose down -v
```

## API Docs

All request/response schemas are auto-generated from Pydantic models. Once the server is running:

- **Swagger UI** — [http://localhost:4000/docs](http://localhost:4000/docs)
- **ReDoc** — [http://localhost:4000/redoc](http://localhost:4000/redoc)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MDB_URI` | Yes (for persistence) | MongoDB connection string. Database defaults to `r3d` if not in the URI. |
| `GEMINI_API_KEY` | For Gemini models | Google Gemini API key |
| `OPENAI_API_KEY` | For OpenAI models | OpenAI API key |
| `AZURE_API_KEY` | For Azure OpenAI | Azure OpenAI API key |
| `AZURE_API_BASE` | For Azure OpenAI | Azure endpoint URL (e.g. `https://your-resource.openai.azure.com`) |
| `AZURE_API_VERSION` | For Azure OpenAI | Azure API version (e.g. `2024-08-01-preview`) |
| `LITELLM_MODEL` | No | Default model (default: `gemini/gemini-2.5-pro`). Prefix determines provider: `gemini/...`, `gpt-4o`, `azure/deployment-name`. |
| `PORT` | No | Server port (default: `4000`) |
| `R3D_API_KEY` | No | When set, all non-health endpoints require `Authorization: Bearer <key>`. Local Docker defaults to `r3d-local-dev-key`. |
| `CORS_ORIGINS` | No | Comma-separated allowed origins (default: `http://localhost:4000,http://127.0.0.1:4000`). Set to your extension origin for production. |

## Endpoints

### LLM Proxy

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/chat/completions` | OpenAI-compatible chat completions via LiteLLM |

### Session CRUD

| Method | Path | Description |
|--------|------|-------------|
| POST | `/r3d/sessions/start` | Create a new monitoring session |
| POST | `/r3d/sessions/{sid}/events` | Append buffered events |
| POST | `/r3d/sessions/{sid}/flush` | Acknowledge flush |
| POST | `/r3d/sessions/{sid}/end` | End session, store summary |
| GET | `/r3d/sessions` | List sessions (newest first, max 100) |
| GET | `/r3d/sessions/{sid}` | Get single session with events |

See `/docs` for full request body schemas, field types, and defaults.

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server status, MongoDB connectivity, default model |

## MongoDB Schema

Sessions are stored in the `r3d_sessions` collection:

```json
{
  "_id": "session-uuid",
  "name": "Internal Audit Q1",
  "startedAt": "2025-03-14T10:00:00Z",
  "endedAt": "2025-03-14T11:30:00Z",
  "status": "active | ended",
  "notes": "Testing RBAC controls",
  "scope": ["app.example.com", "sso.example.com"],
  "aiEnabled": true,
  "events": [
    { "type": "finding", "ts": 1710414000000, "data": {...} },
    { "type": "request", "ts": 1710414001000, "data": {...} }
  ],
  "summary": {
    "counters": { "findings": 42, "systems": 5, "requests": 312 },
    "riskLevel": "HIGH",
    "overallRisk": 85
  }
}
```

## Deployment

For production, use a process manager:

```bash
uvicorn app:app --host 0.0.0.0 --port 4000 --workers 2
```

Update the R3D extension's Settings to point the Proxy Endpoint to your deployed URL.

> **Security:** Local Docker auto-generates a unique `R3D_API_KEY` on each startup (printed to the console). CORS defaults to localhost only. For production, set a stable `R3D_API_KEY` in `.env` and `CORS_ORIGINS` to restrict allowed origins (e.g. `chrome-extension://your-extension-id`). The extension auto-discovers the key via `/r3d/handshake` — no manual config needed.
