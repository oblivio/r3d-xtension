# R3D — Technical Review

## TLDR

R3D is an offensive security intelligence platform that combines a Chrome Manifest V3 extension with a FastAPI/MongoDB backend to intercept live browser traffic, run 16 passive detection modules in real time, generate and inject LLM-powered exploits, replay stolen credentials server-side, fuzz endpoints, build directed attack graphs with BFS pathfinding, and persist everything in MongoDB with client-side field-level encryption. Built by a single developer. The MongoDB integration is not incidental — it is load-bearing. The document model, atomic `$push`, schema-free evolution, and CSFLE are fundamental to how the system works, not bolted-on features. The accompanying blog post is one of the better "why we chose MongoDB" pieces in recent memory.

**Score: 8 / 10**

---

## Executive Analysis

R3D is a full-stack offensive security tool built for a specific and underserved niche: testing internal web applications that live behind SSO, Okta, and corporate auth — environments where the browser is already authenticated and the challenge is proving what that access can reach. The architecture is a Chrome extension that passively (and actively) analyzes traffic, paired with a proxy server that handles persistence, LLM routing, credential replay, scanning, fuzzing, report generation, and a real-time web dashboard.

The project makes a genuinely compelling case for MongoDB as the backing store. This is not a CRUD app where any database would do. The data is polymorphic (16+ event types with different schemas), append-heavy (buffered `$push` every 15 seconds), hierarchically nested (attack graphs, AI responses), and schema-volatile (new detector shapes appear without migrations). The CSFLE implementation addresses a real and serious concern — the tool captures live weaponized credentials, and encrypting them at the application boundary before they reach the database is a non-negotiable architectural decision, not a nice-to-have.

The blog post (`blog.md`) stands on its own as a persuasive technical narrative. It walks through concrete data shapes, shows real code, explains the overflow pattern, and builds to the CSFLE argument with genuine urgency. It reads like a senior engineer explaining a decision to peers, not a marketing brief.

The scope of what has been built — 15+ backend routers, 16 browser-side analysis modules, attack graph engine, scan/fuzz infrastructure, Burp/Nuclei/SARIF integrations, 4 report templates, proof page generator, SSE live updates, Docker one-command setup with auto-bootstrapped encryption — is staggering for a single-developer project.

---

## Key Points & Value

### What works exceptionally well

**The MongoDB fit is authentic.** Every major design decision — the session document model, the `$push` write path, the overflow pattern, the attack graph as a single document, the `response_format: json_object` → MongoDB pipeline — demonstrates a genuine understanding of when and why a document database is the right choice. The project doesn't just *use* MongoDB; it *needs* it in ways that would be painful to replicate in a relational system.

**CSFLE is the standout feature.** The `bootstrap_csfle()` function in `core/db.py` is production-grade: it creates a key vault, generates per-field data encryption keys with alt-name lookup for idempotency, builds the encrypted collection schema, and wires up `AutoEncryptionOpts` for the async client — all automatically on first `docker compose up`. The reasoning in the blog is airtight: R3D captures HttpOnly cookies, Bearer tokens, OAuth credentials, and exploit outputs. Without field-level encryption, the security tool becomes the highest-value target. This is the single strongest argument in the entire project.

**The event pipeline is well-designed.** The Chrome extension buffers events in memory, flushes every 15 seconds via `SessionClient.appendEvents`, and the server appends with a single `$push`. The overflow pattern (spill to a companion collection after 1,000 events, merge transparently on read) is a clean solution to the 16MB document limit that most sessions never hit. The sync health tracking (`synced` / `degraded` / `disconnected`) gives the analyst visibility into data integrity.

**The attack graph engine is substantive.** `graph_builder.py` implements a real directed graph with BFS pathfinding, confidence-weighted edge traversal, risk scoring, entry point / crown jewel identification, and automatic edge inference from OAuth/SSO findings, token reuse patterns, and IDOR chains. The AI enrichment endpoint (`/r3d/graph/{sid}/enrich`) sends the graph topology to an LLM and merges inferred lateral movement edges back into MongoDB as a single document update. This is the kind of feature that separates a proof-of-concept from a tool someone could actually use in an engagement.

**The blog is publication-quality.** It opens with a concrete problem (the data shape), walks through the write path with actual code, addresses the 16MB ceiling honestly, shows the attack graph document in full, and builds to the CSFLE section with real urgency. The comparison to relational alternatives is specific and fair — it counts the tables, names the JOINs, and explains why each one adds friction. The "schema evolution at the speed of AI" section captures a real operational pain point that MongoDB solves cleanly.

**Tool integrations are practical.** Burp Suite XML import/export, Nuclei scan execution and JSONL import, SARIF 2.1.0 export, OpenAPI spec import with automatic sensitive endpoint flagging, coverage diffing against observed traffic, and auto-generated scan probes from untested endpoints. These are the integrations a security practitioner would actually want.

**One-command setup works.** `docker compose up --build` spins up MongoDB Atlas Local (8.0) with the CSFLE `crypt_shared` library, auto-generates an API key, bootstraps the key vault and encrypted collection, loads fuzzing payload libraries, and starts the proxy with auto-discovery. The extension connects without manual configuration. This is the right developer experience for a tool like this.

### Where it could be stronger

**Bare exception handling in several paths.** The extension's service worker and several proxy routers use `except: pass` or `except Exception: pass` without logging. For a security tool, silent failure in credential capture or event persistence could mean lost engagement data. Adding structured logging (even just `print` statements to the Docker log) would improve operational confidence.

**Hardcoded proxy URL in the extension.** `sidepanel.js` hardcodes `DASHBOARD_BASE = 'http://0.0.0.0:4000'`. The auto-discovery mechanism in the service worker handles proxy detection dynamically, but the side panel's dashboard links don't benefit from it. A minor inconsistency.

**API authentication is API-key only.** The `r3d_users` collection and user auth infrastructure exist (`routers/auth.py`), but the primary access control is a single Bearer token. For a tool that handles live credentials for internal systems, the auth surface could be tighter — especially if the proxy is exposed beyond localhost.

**No input sanitization on proof page endpoints.** The `/r3d/prove` endpoint renders user-supplied URLs directly into HTML responses. While the audience is security professionals and the endpoint is behind API key auth, the proof pages could be a vector for stored XSS if shared. The `esc()` helper in `sidepanel.js` exists but the server-side proof templates inline values without equivalent escaping.

**Report generation could be richer.** The 4 report templates (executive, technical, compliance, narrative) are a good start, but the Jinja2 templates are relatively basic. For a tool targeting enterprise security teams, polished PDF output with charts, severity breakdowns, and branded headers would increase the deliverable value.

---

## Architecture Assessment

| Layer | Technology | Notes |
|-------|-----------|-------|
| Browser | Chrome MV3 Extension | Service worker + MAIN world content scripts + side panel. 16 analysis modules loaded via `importScripts`. |
| Transport | HTTP/JSON + SSE | Extension flushes events every 15s. Dashboard receives real-time updates via SSE. Test execution uses polling (2s interval). |
| Backend | FastAPI (Python 3.10+) | 15 routers, Pydantic models, async throughout. LiteLLM for multi-provider LLM routing. |
| Database | MongoDB 8.0 (Atlas Local) | 3 core collections + overflow + encrypted credentials + users + audit log. CSFLE with local master key (dev) / KMS (prod). |
| AI | LiteLLM → Gemini / OpenAI / Azure | `response_format: json_object` → MongoDB. System profiling, triage, attack chains, executive briefs, graph enrichment. |
| DevOps | Docker Compose | Single-command setup. Named volumes for persistence. Auto-generated API keys. |

### Data Flow

```
Browser Tab
  → Chrome webRequest API (headers)
  → Chrome debugger API (response bodies, opt-in)
  → Content scripts (DOM, storage, WebSockets, CSP violations)
  → Service worker (16 analysis modules, dedup, enrichment)
  → Event buffer (in-memory, 15s flush)
  → FastAPI proxy (/r3d/sessions/{sid}/events)
  → MongoDB ($push into session document, overflow after 1000 events)

Dashboard ← SSE ← FastAPI (real-time broadcast of all events)

AI pipeline:
  Findings/Systems → LLM (structured JSON) → MongoDB (direct insert, no ORM)

Attack helpers:
  Extension pushes auth context → Proxy stores (CSFLE-encrypted)
  Dashboard triggers server-side fetch/validate/fuzz → Proxy replays with stored credentials
```

---

## MongoDB Integration Depth

This is not a "we store JSON so we use MongoDB" project. The integration is deep and intentional:

1. **Polymorphic events** — 16+ event types with different schemas coexist in the same `events` array. No discriminator columns, no UNION views, no wide nullable tables.

2. **Atomic `$push`** — The hottest write path is a single `update_one` with `$push` + `$each`. No multi-table transactions, no foreign key checks, no contention.

3. **Overflow pattern** — Sessions spill to `r3d_event_overflow` after 1,000 events, merged transparently on read. 15 lines of code, no schema migration.

4. **Attack graphs as documents** — Nodes, edges, paths, and AI enrichment in a single document. Queryable at every nesting level.

5. **`response_format: json_object` → BSON** — LLM responses drop straight into MongoDB. Zero transformation, zero mapping, zero impedance mismatch.

6. **CSFLE** — `origin`, `cookies`, and `headers_json` encrypted client-side with AES-256-CBC. Database stores ciphertext. Keys never touch the server. Auto-bootstrapped on first run.

7. **Schema evolution** — New detector types, new AI response shapes, new import formats — all stored without migration. Old and new documents coexist.

---

## Scoring Breakdown

| Category | Score | Rationale |
|----------|-------|-----------|
| **Architecture & Design** | 9/10 | Clean separation (extension / proxy / DB). Event pipeline is elegant. Overflow pattern is practical. CSFLE integration is production-grade. |
| **MongoDB Integration** | 10/10 | This is the best demonstration of MongoDB's document model advantages in the project set. Every feature — polymorphic events, atomic append, graph documents, AI JSON pipeline, CSFLE — maps to a genuine MongoDB strength. |
| **Feature Completeness** | 9/10 | 16 passive detectors, active exploit injection, credential replay, scan/fuzz engine, attack graphs, Burp/Nuclei/SARIF, OpenAPI import, proof pages, 4 report templates, webhooks, SSE dashboard. The surface area is enormous. |
| **Code Quality** | 7/10 | Well-structured modules, good use of Pydantic, async throughout. Loses points for bare `except: pass` blocks, some hardcoded values, and inconsistent error reporting. |
| **Blog / Content** | 9/10 | Exceptional technical writing. Concrete data shapes, real code, honest tradeoff analysis, compelling CSFLE argument. Publication-ready. |
| **Developer Experience** | 8/10 | `docker compose up --build` works. Auto-discovery. Auto-generated API keys. Auto-bootstrapped encryption. Swagger/ReDoc docs. Could improve with better logging and error visibility. |
| **Security Posture** | 8/10 | CSFLE is outstanding. API key auth is functional. Audit logging exists. Loses a point for proof page XSS surface and the inherent risk of a tool that captures live credentials. |
| **Practical Value** | 8/10 | Genuinely useful for internal security assessments behind corporate auth. The "browser is already authenticated" insight is the right framing for the problem. Tool integrations (Burp, Nuclei, SARIF) make it composable with existing workflows. |

### Overall: **8 / 10**

A remarkably ambitious and well-executed single-developer project that makes an authentic, compelling case for MongoDB across every dimension — document model, write performance, schema flexibility, and client-side encryption. The blog alone is worth the read. The code delivers on what the README promises. The CSFLE implementation is the strongest individual feature and the strongest argument for MongoDB in the entire project. The points lost are mostly in operational polish (error handling, logging, input validation) rather than in architecture or capability — which is the right set of problems to have at this stage.
