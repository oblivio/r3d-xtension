# Why We Chose MongoDB for R3D (And Never Looked Back)

When we started building R3D — an offensive security intelligence platform for internal web applications behind SSO and corporate auth — we had a data problem before we had a product.

The tool intercepts HTTP requests, WebSocket messages, CSP violations, JWTs, cookies, and PII exposure across dozens of internal SaaS systems simultaneously. It generates and executes browser-injectable exploit tests against live targets. It replays stolen credentials server-side to prove what authenticated access can reach. It fuzzes endpoints with payload libraries. It builds attack graphs that map lateral movement paths between systems. It imports findings from Burp Suite and Nuclei. And it routes everything through LLMs that return richly structured security assessments.

Every one of those artifacts looks different. An IDOR finding has an endpoint pattern, a list of user IDs, and a confidence score. A test execution artifact has a snippet, a target origin, a verdict, and captured console output. An attack graph has nodes, edges, paths, and AI-enriched annotations. An AI-generated system profile has nested sub-objects for tech stack, auth model, attack surface, and red team verdict. All of these belong to the same session, and the analyst expects to see them together.

We needed a database that could keep up.

## The shape of the data

Here is what a single R3D session looks like when persisted:

```json
{
  "_id": "session-uuid",
  "name": "Silent Falcon-042",
  "startedAt": "2026-03-14T10:00:00Z",
  "endedAt": "2026-03-14T11:30:00Z",
  "status": "ended",
  "notes": "Testing RBAC controls on internal HR portal",
  "scope": ["hr.internal.example.com", "sso.example.com"],
  "aiEnabled": true,
  "eventCount": 847,
  "events": [
    { "type": "finding", "ts": 1741950000000, "data": { "title": "Missing HSTS", "severity": "MEDIUM", "cwe": "CWE-523", "systemId": "hr.internal.example.com", "confidence": "high" } },
    { "type": "request", "ts": 1741950001000, "data": { "url": "https://hr.internal.example.com/api/users", "method": "GET", "status": 200, "systemId": "hr.internal.example.com" } },
    { "type": "ai", "ts": 1741950500000, "data": { "type": "system_profile", "targetSystem": "hr.internal.example.com", "model": "gemini-2.5-pro" } },
    { "type": "test_artifact", "ts": 1741951000000, "data": { "testId": "test_143022_8821", "findingTitle": "JWT in localStorage", "verdict": "vulnerable", "output": "[R3D TEST] VULNERABLE: token valid — user=admin@example.com", "snippet": "(async()=>{ ... })()" } },
    { "type": "imported_finding", "ts": 1741951500000, "data": { "source": "nuclei", "title": "CVE-2025-1234", "severity": "CRITICAL", "templateId": "CVE-2025-1234", "status": "confirmed" } }
  ],
  "summary": {
    "counters": { "findings": 42, "systems": 5, "requests": 312 },
    "riskLevel": "HIGH",
    "overallRisk": 85
  }
}
```

A session has scalar metadata at the top, a variable-length array of domain scopes, an `events` array that grows throughout the session's lifetime and contains objects of completely different shapes, an `eventCount` that tracks the total for overflow management, and a nested summary object computed at session close.

The events array is where it gets interesting. Look at those five events — each one has a different internal structure. A finding has severity, CWE, and confidence fields. A request has URL, method, and status. An AI analysis has a model name and target system. A test artifact has a snippet, verdict, and captured console output. An imported finding has a source tool, template ID, and confirmation status. And these are just five of the dozen-plus event types R3D produces.

Ask yourself: how many tables would this require in a relational database?

At minimum five. A `sessions` table for the scalars. A `session_scope` join table for the many-to-many domain list. A `session_events` table with a foreign key back to sessions. But that `data` column on events? Every event type has a different structure — findings have severity and CWE codes, requests have URLs and status codes, AI events have model names, test artifacts have snippets and verdicts, imported findings have source tools and template IDs. You either create a separate table per event type (and a UNION ALL view to read them back), park everything in a JSON column (at which point you are fighting your schema instead of using it), or flatten into a single wide table with dozens of nullable columns that are mostly NULL.

Then there is the summary, which is itself a nested object with counters, risk assessments, and top-system rankings. Another table, another JOIN.

In MongoDB, it is one document. One collection. One read to get everything.

## The write path that made the decision for us

R3D's Chrome extension buffers intercepted events in memory and flushes them to the backend every 15 seconds. The proxy appends them to the session with a single atomic operation:

```python
await col.update_one(
    {"_id": sid},
    {"$push": {"events": {"$each": body.events}}},
)
```

That is the entire write path. No transaction spanning multiple tables. No SELECT to check if the session exists before inserting child rows. No row-level locking on a hot events table. The `$push` operator atomically appends the batch to the embedded array. If the session does not exist, `matched_count` comes back as zero and we return a 404. The whole thing is three lines of code.

In a relational system, this flush cycle would involve opening a transaction, inserting N rows into `session_events` with a foreign key constraint check on each, and committing. Under concurrent load from multiple browser tabs or team members, that events table becomes a contention point. With MongoDB, each session is an independent document — writes to different sessions never compete for the same lock.

## What about the 16 MB ceiling?

MongoDB documents cap at 16 MB. An embedded events array that grows for the lifetime of a session will eventually hit that wall — a long-running audit against a busy application can easily generate tens of thousands of intercepted requests, findings, and AI analyses.

We handle this with what amounts to a spillover pattern. The session document tracks an `eventCount`. While the count is below a threshold (we use 1,000 events), the write path is identical to what you saw above — `$push` into the embedded array. Once the session crosses that threshold, new event batches spill into a companion `r3d_event_overflow` collection, each document tagged with the session ID and a sequence number:

```python
if current_count < EVENT_OVERFLOW_THRESHOLD:
    await col.update_one(
        {"_id": sid},
        {
            "$push": {"events": {"$each": body.events}},
            "$inc": {"eventCount": batch_size},
        },
    )
else:
    await overflow.insert_one({
        "sessionId": sid,
        "seq": current_count,
        "events": body.events,
    })
    await col.update_one(
        {"_id": sid},
        {"$inc": {"eventCount": batch_size}},
    )
```

On the read side, `get_session` checks the count and, when overflow exists, merges the buckets back into one flat event list. The caller never knows the difference.

The key insight is that most sessions never reach the threshold. A typical 30-minute assessment generates a few hundred events — well within a single document. The overflow path exists for the outlier: the eight-hour enterprise engagement that produces 15,000 requests across dozens of systems. In a relational system you would need that overflow table from day one because every session writes to the same `session_events` table. With MongoDB, we added the spillover logic only when the data told us to — about fifteen lines of code, no schema migration, no downtime.

## Attack graphs as documents

R3D builds attack graphs from session data — directed graphs of systems, vulnerabilities, and credentials with edges representing exploitation paths, shared authentication, and lateral movement. Here is what one looks like in MongoDB:

```json
{
  "_id": "graph-session-uuid",
  "sessionId": "session-uuid",
  "nodes": [
    { "id": "hr.internal.example.com", "type": "system", "name": "HR Portal", "riskScore": 8, "domains": ["hr.internal.example.com"] },
    { "id": "vuln-jwt-001", "type": "vulnerability", "title": "JWT in localStorage", "severity": "HIGH", "cwe": "CWE-922" },
    { "id": "cred-oauth-hr", "type": "credential", "kind": "oauth", "scope": "hr.internal.example.com" }
  ],
  "edges": [
    { "from": "vuln-jwt-001", "to": "hr.internal.example.com", "label": "exploits: JWT in localStorage", "confidence": "confirmed" },
    { "from": "hr.internal.example.com", "to": "cred-oauth-hr", "label": "issues OAuth token", "confidence": "confirmed" },
    { "from": "cred-oauth-hr", "to": "payroll.internal.example.com", "label": "may authenticate via SSO", "confidence": "hypothesis" }
  ],
  "entryPoints": ["hr.internal.example.com"],
  "crownJewels": ["payroll.internal.example.com"],
  "paths": [
    { "path": ["hr.internal.example.com", "cred-oauth-hr", "payroll.internal.example.com"], "length": 2, "minConfidence": "hypothesis", "maxSeverity": 8, "riskScore": 2.67 }
  ],
  "enrichment": {
    "additionalEdges": [{ "from": "hr.internal.example.com", "to": "payroll.internal.example.com", "label": "shared VPN segment", "confidence": "likely" }],
    "attackPaths": [{ "name": "SSO pivot to payroll", "steps": ["hr.internal.example.com", "cred-oauth-hr", "payroll.internal.example.com"], "risk": "HIGH" }],
    "crownJewels": [{ "nodeId": "payroll.internal.example.com", "reasoning": "Contains compensation data, SSNs" }],
    "executiveSummary": "Stolen JWT from HR portal can pivot to payroll system via shared SSO."
  },
  "builtAt": "2026-03-14T11:35:00Z",
  "enrichedAt": "2026-03-14T11:35:30Z"
}
```

That is a single document with nested arrays of heterogeneous nodes, typed edges with confidence levels, computed paths with risk scores, and an AI-generated enrichment layer with inferred edges and exploitation instructions. It is the complete topology of an attack surface, queryable at every level.

What would the relational alternative look like? At minimum: a `graph_nodes` table (with a discriminator column for system vs. vulnerability vs. credential), a `graph_edges` table with two foreign keys, a `graph_paths` table with a junction table for ordered path members, an `enrichment_edges` table, an `enrichment_paths` table, an `enrichment_crown_jewels` table. Six to eight tables for one graph. And when the AI enrichment schema changes — when we add `lateralMovementPaths` or `dataExfiltrationRisk` — each new key is a migration.

In MongoDB, the graph is one document. The enrichment is one nested object. The AI returns JSON, we store JSON, and we query JSON. Zero impedance mismatch.

## Phishing and the filesystem escape hatch

R3D's phishing site cloner is the feature that most clearly illustrates where MongoDB fits and where it does not.

When an analyst clicks PHISH on a system card in the dashboard, the proxy fetches the target's login page using captured auth context (HttpOnly cookies, Authorization headers, User-Agent — all of it), parses the HTML with BeautifulSoup, crawls every sub-resource (CSS, JS, images, fonts), rewrites all URLs to point to locally cached copies, and injects a comprehensive credential capture script. The result is a pixel-perfect clone served at a clean victim-facing URL like `/p/a1b2c3d4/`.

The capture script is a fixed template — no LLM generates any of the injection JavaScript. It hooks form submissions, password field blur events, fetch/XHR request bodies, and uses a MutationObserver to catch dynamically added login forms (React, Angular, Vue SPAs that render after page load). After any credential interaction, it takes a snapshot of `document.cookie` and scans localStorage/sessionStorage for keys containing `token`, `session`, `auth`, `jwt`. Everything beacons back to the proxy via `navigator.sendBeacon`, which fires even if the page navigates away during a form submission.

This is the one place where MongoDB is deliberately absent from the persistence layer. The cloned assets — HTML, CSS, JavaScript, images, fonts — are binary files served from disk. Storing them in GridFS would add latency and complexity for no benefit. The metadata and captured credentials live in a Python dict (`state.phish_sites`) because phish sites are inherently ephemeral: they exist for the duration of a demo, and the interesting data (captured credentials) is broadcast in real-time via SSE the moment a victim enters anything. If the proxy restarts, the phish sites are gone, and that is fine.

The architectural takeaway: MongoDB is not a religion. It is the right tool for session documents, attack graphs, encrypted credentials, and AI analysis artifacts — data that is richly structured, polymorphic, and needs to survive restarts. For ephemeral binary caches, the filesystem is simpler and faster. Using the right tool at each layer is not a compromise; it is the point.

## Attack plans as living documents

The AI attack planner generates multi-step plans that chain browser injection, server-side credential replay, and phishing clones across systems. The LLM returns a JSON plan with steps — each typed as `"browser"`, `"server"`, or `"phish"` — and the proxy executes them sequentially, resolving output placeholders between steps so earlier results feed into later ones.

The `"phish"` step type is the most interesting from an architecture perspective. When the LLM says `"type": "phish"`, it only provides a target URL. The entire clone-inject-serve pipeline runs from a fixed server-side template. Zero LLM-generated JavaScript. Zero room for the model to hallucinate incorrect CSP relay usage, wrong endpoint URLs, or broken capture logic. The LLM decides *what* to phish; the template handles *how*.

Plans live in-memory during execution. When complete, the execution results — per-step status, output, HTTP responses, and an AI-generated verdict — flow back into the session document as an `attack_plan_result` event via `$push`. The plan's verdict (CRITICAL, HIGH, MEDIUM, LOW, or INCONCLUSIVE) becomes part of the session's permanent record in MongoDB, alongside the findings that prompted the plan in the first place.

This is the same pattern as everything else in R3D: the transient, operational state lives where it is cheapest (memory, filesystem), and the durable analytical artifacts land in MongoDB where they can be queried, reported on, and encrypted.

## Schema evolution at the speed of AI

R3D ships with 16 analysis modules: JWT analysis, PII scanning, IDOR detection, RBAC matrix generation, header auditing, cookie auditing, system fingerprinting, pattern detection, policy enforcement, and more. Each module emits findings with different fields. When we added the advanced detectors — SSRF, open redirect, GraphQL introspection, rate-limit bypass — each one introduced a new event shape with new fields.

We changed zero lines of database code.

The same held when we added test execution artifacts (snippet, verdict, console output), imported findings from Burp Suite (source, remediation, issue type), imported findings from Nuclei (template ID, tags, references), and OpenAPI spec documents (endpoints, sensitive flags, coverage stats). Each new data shape dropped into the existing collections without conflict. Old sessions kept their old shape. New sessions got the new fields. Both coexist in the same collection.

No migration file. No `ALTER TABLE ADD COLUMN`. No DBA review ticket. No staging environment rollout to verify the migration runs cleanly. No downtime window.

In a relational world, adding a new event type means a cross-functional conversation. The backend team writes a migration. The DBA reviews it for index impact. QA verifies it against staging data. The release coordinator schedules the deployment. For a single new column. Multiply that by the pace at which AI-powered analysis evolves — where new detection patterns emerge weekly — and the migration overhead becomes a genuine drag on velocity.

## The data R3D captures is a liability

Stop and think about what flows through R3D in a single 30-minute session.

HttpOnly cookies stolen from target pages via the Debugger API. Bearer tokens extracted from Authorization headers. OAuth access tokens and refresh tokens pulled from localStorage. CSRF tokens captured from hidden form fields. Full request/response bodies from internal APIs — employee records, salary data, org charts, PII. AI-generated exploit snippets designed to prove account takeover. Console output from those exploits confirming which tokens are valid and which user accounts they unlock. Credential pivot results showing which stolen cookies grant access to which internal systems.

This is not abstract security telemetry. This is live weaponized material. A stolen `okta-token-storage` JWT that validates against the userinfo endpoint is a working session hijack. A credential pivot result confirming that an HR portal cookie also authenticates to the payroll system is a lateral movement proof. An AI-generated test snippet that reads `document.cookie` and exfiltrates it through the proxy relay is an actual exploit.

If someone gains read access to R3D's database — whether through a misconfigured network, a compromised backup, an insider with DBA privileges, or a supply chain breach in the infrastructure — they get all of it. Every credential. Every token. Every exploit. Every proof of what those credentials can reach.

Encryption at rest does not solve this. Full-disk encryption protects against someone physically stealing the hard drive, but a database admin, a backup operator, or anyone with a connection string and valid credentials can still run `db.r3d_sessions.find()` and read every intercepted token in plaintext.

This is where Client-Side Field Level Encryption changes the threat model entirely.

## CSFLE: the database cannot read its own secrets

MongoDB's Client-Side Field Level Encryption (CSFLE) encrypts sensitive fields *before* they leave the application. The database server stores ciphertext. It indexes ciphertext. It returns ciphertext. Only the application — holding the encryption keys — can decrypt the values.

R3D uses CSFLE to protect the most dangerous artifacts it captures:

```python
encrypted_fields = {
    "fields": [
        {"path": "cookies",       "bsonType": "object", "keyId": dek_id, "queries": {"queryType": "equality"}},
        {"path": "headers",       "bsonType": "object", "keyId": dek_id},
        {"path": "tokens",        "bsonType": "array",  "keyId": dek_id},
        {"path": "authContext",    "bsonType": "object", "keyId": dek_id},
    ]
}
```

When the proxy captures an auth context push from the Chrome extension — cookies, authorization headers, CSRF tokens, OAuth tokens — it writes them to the `r3d_credentials` collection through an encryption-aware MongoClient. The fields are encrypted client-side with AES-256-CBC before the write operation reaches the server. The database stores opaque binary blobs.

The practical consequence: a DBA with `root` access on the MongoDB deployment, reading the `r3d_credentials` collection directly, sees this:

```
cookies: Binary(6, "AQFkZQAAAAAAAAAAAAECY2...")
headers: Binary(6, "AQFkZQAAAAAAAAAAAAEFZ3...")
tokens: Binary(6, "AQFkZQAAAAAAAAAAAAEJaX...")
```

Not `{"Cookie": "sid=eyJhbGciOiJSUzI1NiIs..."}`. Not `{"Authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."}`. Binary ciphertext. The keys never touch the server — they live in the application process, derived from a master key that the operator controls.

For R3D's local Docker setup, the master key is a hardcoded 96-byte value in `docker-compose.yml` — good enough for a single-developer local deployment. In production, that key comes from a KMS (AWS KMS, Azure Key Vault, GCP KMS, or HashiCorp Vault) so that even the application binary cannot be reverse-engineered to extract it.

The entire CSFLE setup — key vault bootstrap, data encryption key creation, encrypted collection creation with field definitions — runs automatically on first `docker compose up`. Zero config for local dev. Zero excuses for leaving credentials in plaintext.

## Why this matters more than you think

Consider the alternative. A security assessment tool that stores captured credentials in plaintext. The tool lives on an analyst's laptop, or maybe a shared team server. The database has a connection string in a `.env` file. The MongoDB instance is on the same Docker network. The backups go to an S3 bucket. The CI pipeline has access to restore those backups for testing.

Every one of those touchpoints is a place where a stolen credential from a security engagement can leak. Not through a vulnerability in the target system — through a vulnerability in the security tooling itself. The tool designed to find credential theft becomes a credential theft target.

CSFLE collapses that attack surface. The credentials are encrypted at the application boundary. The network sees ciphertext. The disk stores ciphertext. The backups contain ciphertext. The DBA sees ciphertext. The CI pipeline restoring from backup sees ciphertext. The only process that can read the actual cookies and tokens is the R3D proxy process holding the decryption key.

This is not defense in depth. This is a single architectural decision that removes an entire class of data exposure risk. For a tool that captures live session tokens for internal corporate systems, it is not optional.

## Beyond CSFLE: defense at every layer

CSFLE handles the most toxic data. MongoDB provides the rest of the security stack without aftermarket solutions:

**Encryption everywhere.** TLS encrypts data in transit by default. Encryption at rest protects data on disk. CSFLE protects individual fields even from infrastructure operators.

**Authentication that scales with your org.** The local Docker setup uses basic username/password auth. Atlas layers on SCRAM-SHA-256, X.509 certificates, LDAP, and OIDC federation. A solo developer and a 500-person enterprise use the same database engine with different auth configurations, not different products.

**Auditing.** When your tool captures vulnerability data about production systems, you need to know who queried what and when. Atlas audit logs provide that trail without custom logging middleware.

These are not features you bolt on later. They are defaults you inherit by choosing the right foundation.

## Where the AI story gets interesting

R3D routes findings through LLMs for deep analysis — system profiling, attack chain mapping, executive briefings, red team engagement verdicts, automated triage, and attack graph enrichment. The critical design choice is how we talk to the model:

```python
response = await litellm.acompletion(
    model=DEFAULT_MODEL,
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ],
    response_format={"type": "json_object"},
)
```

`response_format={"type": "json_object"}`. Not `response_format=SQL_JOINS_TABLES`. That line is not a throwaway API parameter — it is an architectural decision that ripples through the entire stack.

When R3D asks an LLM to assess a system, the model returns something like this:

```json
{
  "executiveSummary": "This internal HR portal exposes sensitive PII...",
  "tldr": "Unpatched admin panel with default credentials on internal HR system.",
  "businessImpact": "Regulatory fines under GDPR Article 83, potential class-action...",
  "systemProfile": {
    "description": "Internal HR management portal",
    "techStack": "React SPA, Node.js API, PostgreSQL",
    "authModel": "JWT with RS256, refresh tokens in httpOnly cookies",
    "dataClassification": "PII, compensation data, SSNs"
  },
  "redTeamVerdict": {
    "engage": true,
    "confidence": "HIGH",
    "reasoning": "Internal app with PII and weak session controls — high-value target",
    "priorityRank": "P0"
  },
  "attackSurface": {
    "entryPoints": ["/api/admin", "/api/users/export"],
    "interestingEndpoints": ["/api/users/me", "/api/reports/salary"],
    "quickWins": ["Test IDOR on /api/users/{id}", "Check admin panel for default creds"]
  },
  "sampleCurl": "curl -H 'Authorization: Bearer <token>' https://hr.internal.example.com/api/users/1",
  "attackVectors": [{"vector": "IDOR on user endpoints", "test": "Swap user ID in path"}],
  "hardeningRecs": ["Enforce object-level authorization", "Rotate default admin credentials"],
  "complianceGaps": [{"framework": "GDPR", "gap": "No data minimization on /users/export"}]
}
```

That is a richly nested object. It has scalar fields, nested sub-objects with their own keys, arrays of strings, arrays of objects. It mirrors how a security analyst actually thinks about an engagement — hierarchical, contextual, everything related to this system grouped together.

Now consider where that JSON goes. In R3D, the answer is: straight into MongoDB. The Python dict from `json.loads(response)` becomes a BSON document. No transformation. No decomposition. No mapping layer.

The same pattern holds for attack graph enrichment. When the LLM analyzes a graph, it returns inferred edges, exploitation paths, crown jewel reasoning, and fix priorities — all as nested JSON. That response merges directly into the graph document in MongoDB. One `replace_one`, one document, done.

What would the relational alternative look like? To store that single AI response, you would need:

- An `ai_analyses` table for the top-level scalars (`executiveSummary`, `tldr`, `businessImpact`, `sampleCurl`) with a foreign key to sessions
- A `system_profiles` table for the nested profile object (or a JSON column, which means you have given up on your schema)
- A `red_team_verdicts` table for the verdict sub-object
- An `attack_surface_entry_points` table, an `attack_surface_interesting_endpoints` table, an `attack_surface_quick_wins` table — or one `attack_surface_items` table with a discriminator column
- An `attack_vectors` table with vector and test columns
- A `hardening_recs` table (one row per recommendation)
- A `compliance_gaps` table with framework and gap columns

That is seven to nine tables for one AI response. Multiply by the number of systems analyzed per session, add the finding-level analyses, the executive briefs, the attack chain mappings, the graph enrichments, and you are looking at a schema with dozens of tables — most of which exist solely to satisfy normalization rules that add no value for this workload.

And here is the thing that makes this particularly painful in a relational world: LLM output schemas evolve constantly. Last week R3D returned `riskSummary` and `attackVectors`. This week we added `systemProfile`, `redTeamVerdict`, `attackSurface`, `executiveSummary`, `tldr`, `businessImpact`, and `sampleCurl`. Next week we might add `lateralMovementPaths` or `dataExfiltrationRisk`. Each new field the LLM returns would be an `ALTER TABLE`, a migration file, a DBA review, a staging rollout. In MongoDB, it is zero lines of database code. The new fields appear in the document. Old documents keep their old shape. Both coexist without conflict.

The entire pipeline is JSON, end to end:

1. **Browser** — JavaScript objects captured from web traffic, auth context, test results
2. **Wire** — JSON over HTTP from extension to proxy
3. **LLM** — `response_format: json_object` produces structured JSON
4. **Application** — Python dicts, no ORM, no mapping
5. **Database** — BSON documents in MongoDB, queryable at every level of nesting

There is no impedance mismatch at any boundary. The data never changes shape. It never gets flattened into rows, decomposed into join tables, or stuffed into TEXT blobs. The document model is not a convenience — it is the only model that does not fight the natural structure of LLM output.

And with Atlas Vector Search available on the same deployment (R3D already runs on `mongodb/mongodb-atlas-local:8.0`, which ships with the `mongot` search engine), the natural next step is semantic search over findings. Imagine asking "show me all sessions where we found authentication bypass patterns similar to this one" and getting results ranked by vector similarity, not just keyword match. The database already supports it. No additional infrastructure, no external search service, no ETL pipeline.

## Seven collections and a filesystem, zero impedance

R3D uses seven MongoDB collections for persistent state:

| Collection | What it stores |
|------------|----------------|
| `r3d_sessions` | Session documents with embedded events, summaries, and metadata. The companion `r3d_event_overflow` handles long-running sessions that exceed the embedded array threshold. |
| `r3d_credentials` | CSFLE-encrypted auth contexts — cookies, headers, tokens captured by the extension. Encrypted client-side with AES-256-CBC before reaching the server. |
| `r3d_attack_graphs` | Attack graph documents with nodes, edges, BFS-computed paths, AI enrichment, and credential pivot results. |
| `r3d_specs` | Imported OpenAPI/Swagger specifications with extracted endpoints, sensitive flags, and coverage stats. |
| `r3d_users` | Multi-user authentication — usernames, bcrypt password hashes, roles (admin/operator/viewer). |
| `r3d_audit_log` | Authentication events and administrative actions with timestamps for compliance trails. |

Seven collections. No junction tables. No foreign key constraints. No migration framework. Each collection stores self-contained documents that map directly to application-level objects. The session document is the session. The graph document is the graph. The spec document is the spec. There is no assembly step where you join five tables to reconstruct the object the application actually works with.

Not everything belongs in MongoDB, and R3D does not pretend otherwise. Phishing site clones — HTML pages with rewritten asset URLs and injected credential capture hooks — live on the filesystem at `phish_cache/{site_id}/` and are served directly by FastAPI. Binary assets (images, fonts, stylesheets) are better on disk than in GridFS. Phish sites are ephemeral by nature — they exist for the duration of a demo or engagement, and the captured credentials are exfiltrated in real-time via SSE, so persistence across restarts is unnecessary. Attack plans and active scan state live in Python dicts for the same reason. MongoDB handles the data that matters long-term; the rest uses whatever is simplest.

## One person, days not months

R3D was built by a single developer in days. The Chrome extension with 16 analysis modules, the FastAPI proxy with 17 route modules, the MongoDB integration with CSFLE, the LLM routing through LiteLLM, the attack graph engine with BFS pathfinding, the scan/fuzz engine with six payload libraries, the phishing site cloner with SPA-aware credential capture, the AI attack planner with credential pivots, the multi-user auth system with JWT and RBAC, the OPSEC profile engine, the Burp/Nuclei integration, the SARIF export, the OpenAPI spec importer, the PDF report generator, the web dashboard with SSE-powered live updates, the Docker setup with auto-generated API keys and CSFLE bootstrap — all of it.

That is not a statement about heroics. It is a statement about what happens when your data layer does not fight you. The document model eliminated an entire category of engineering decisions. There was no schema design phase. No entity-relationship diagram. No migration framework to configure. No ORM to map between the application's natural objects and the database's tabular structure. The Python dictionaries in the application became BSON documents in the database. The JavaScript objects in the browser became JSON on the wire became documents at rest. The impedance mismatch was zero.

When we added the phishing cloner, we added zero database tables — phish sites live on the filesystem and in memory. When we added the attack planner, plan execution results flowed into the existing session document via `$push` — no new collection, no migration. When we added multi-user auth, `r3d_users` and `r3d_audit_log` appeared as new collections with zero impact on existing data. When the credential pivot engine needed to store results, they merged into the existing attack graph document. Each feature shipped in hours, not sprints.

A relational approach would have demanded a different kind of team. A DBA to design and maintain the schema. A backend engineer to write and test migrations. A discussion about whether to use an ORM or raw SQL. A decision about how to handle the polymorphic events (single-table inheritance? class-table inheritance? JSON columns?). Another decision about how to represent attack graphs (adjacency list? nested sets? recursive CTEs?). Each of these decisions is reasonable in isolation. Together, they add weeks and headcount to a project that should be about the analysis, not the plumbing.

The database got out of the way. We focused on catching vulnerabilities.

---

*R3D is offensive security intelligence built on MongoDB. For the full source and setup instructions, see the [README](README.md).*
