# R3D Extension

Chrome extension that intercepts live browser traffic and maps the attack surface of internal web apps in real time. 16 detection modules run against every request. AI generates exploit tests and injects them into target pages with full session context. Auth credentials are pushed to the proxy for server-side replay.

## Prerequisites

- Chrome 120+ (Manifest V3 required)
- [R3D Proxy Server](../r3d-proxy/) running locally or on a reachable host (for session persistence and AI features)

## Install

Since this is an unpacked extension, load it directly from this directory:

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `r3d-extension/` folder (this directory)
5. The R3D icon appears in your toolbar

To update after pulling changes, return to `chrome://extensions` and click the reload button on the R3D card.

## Configuration

Click the R3D toolbar icon to open the side panel, then go to the **Settings** tab:

| Setting | Description |
|---------|-------------|
| **Proxy Endpoint** | URL of your R3D proxy (default: `http://localhost:4000/v1/chat/completions`) |
| **API Key** | Bearer token for proxy authentication. Must match the `R3D_API_KEY` env var on the proxy server. Leave blank if the proxy has no key set. |
| **Model** | LLM model to use for AI analysis (default: `gemini/gemini-2.5-pro`) |
| **Auto-analyze critical** | Automatically send CRITICAL findings to the LLM for triage |
| **Allowed Domains** | Restrict monitoring to specific domains (empty = monitor all) |

## Usage

1. Open the side panel by clicking the R3D toolbar icon
2. Click **Start Session** — give it a name, optional notes, and target scope
3. Browse your target application normally
4. Findings appear in real-time in the side panel and DevTools panel
5. Use the **AI** tab to request attack chain analysis, executive briefs, or per-finding deep dives
6. Click **End Session** to finalize — the session summary is persisted to MongoDB via the proxy

## Architecture

```
r3d-extension/
├── background/
│   └── service-worker.js    # Core engine: request interception, analysis pipeline,
│                             # session state machine, AI dispatch, event buffering
├── content/
│   ├── content.js           # Injected into pages: DOM scanning, storage/cookie
│   │                         # extraction, WebSocket monitoring, CSP violation capture
│   └── page-world.js        # MAIN world script: fetch/XHR interception, storage
│                             # scanning, framework detection, CSP violation relay
├── sidepanel/
│   ├── sidepanel.html/css   # Primary UI: session controls, findings list,
│   └── sidepanel.js         # AI chat, settings, session history,
│                             # "Phish This Page" + "Scan DOM XSS" action buttons,
│                             # phish tab with relay toggle and capture feed
├── lib/                     # Shared analysis modules (loaded by service worker & panel)
│   ├── severity.js          # Severity/confidence enums, finding factory, dedup
│   ├── cwe-mapper.js        # CWE/OWASP classification
│   ├── request-store.js     # In-memory request log
│   ├── jwt-analyzer.js      # JWT decode, expiry, algorithm checks
│   ├── pii-scanner.js       # PII pattern detection in response bodies
│   ├── idor-detector.js     # IDOR endpoint catalog and detection
│   ├── rbac-analyzer.js     # Permission matrix and privilege escalation
│   ├── header-auditor.js    # Security header scoring per domain
│   ├── cookie-auditor.js    # Cookie flag analysis (HttpOnly, Secure, SameSite)
│   ├── report-generator.js  # Structured report builder
│   ├── system-fingerprinter.js  # SaaS/system identification and risk scoring
│   ├── pattern-detector.js  # Cross-request behavioral pattern detection
│   ├── evidence-collector.js    # Evidence packaging for findings
│   ├── policy-engine.js     # Custom security policy evaluation
│   ├── advanced-detectors.js    # SSRF, open redirect, GraphQL, rate limit checks
│   ├── dom-xss-scanner.js   # Active DOM XSS detection — source-to-sink tracing,
│   │                         # reflection scanning, DOM clobbering, postMessage audit
│   └── ai-client.js         # LLM client + SessionClient for proxy communication
├── icons/                   # Extension icons (16/48/128px)
└── manifest.json            # Chrome MV3 manifest
```

## Permissions

The extension requests these Chrome permissions:

| Permission | Why |
|------------|-----|
| `webRequest` | Intercept HTTP request/response headers for security analysis |
| `cookies` | Audit cookie flags and extract JWTs from cookies |
| `activeTab` | Access the current tab for content script injection |
| `storage` | Persist session state, config, and history locally |
| `scripting` | Inject content scripts for DOM and storage analysis |
| `sidePanel` | Render the primary side panel UI |
| `tabs` | Query active tab info for debugger attachment |
| `debugger` | Optional: attach Chrome DevTools Protocol to capture response bodies |
| `<all_urls>` | Monitor traffic across all domains (scoped at runtime by session/allowlist) |
