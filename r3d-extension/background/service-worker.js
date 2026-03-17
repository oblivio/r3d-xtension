/**
 * Background Service Worker v5 — R3D offensive security engine.
 *
 * All capture and analysis is gated behind an explicit monitoring session.
 * Nothing is captured until the analyst starts a session.
 * Sessions are persisted through the LiteLLM proxy (MDB_URI-backed).
 *
 * Includes: CWE classification, evidence collection, policy evaluation,
 * advanced detectors, domain allowlist, dedup pipeline, LiteLLM AI,
 * editable prompt templates, and proxy-backed session persistence.
 */

importScripts(
  '../lib/severity.js',
  '../lib/cwe-mapper.js',
  '../lib/detector-registry.js',
  '../lib/request-store.js',
  '../lib/jwt-analyzer.js',
  '../lib/pii-scanner.js',
  '../lib/idor-detector.js',
  '../lib/rbac-analyzer.js',
  '../lib/header-auditor.js',
  '../lib/cookie-auditor.js',
  '../lib/report-generator.js',
  '../lib/system-fingerprinter.js',
  '../lib/pattern-detector.js',
  '../lib/evidence-collector.js',
  '../lib/policy-engine.js',
  '../lib/advanced-detectors.js',
  '../lib/ai-client.js'
);

// All identifiers (Severity, CWEMapper, AIClient, etc.) are already in the
// global scope via importScripts above and on globalThis.__R3D for lib interop.

// ─── Session State Machine ──────────────────────────────────────────

const session = {
  state: 'idle',  // idle | starting | active | paused | ending | ended
  id: null,
  name: null,
  startedAt: null,
  endedAt: null,
  notes: '',
  scope: [],
  aiEnabled: true,
  counters: { requests: 0, findings: 0, systems: 0, patterns: 0, aiAnalyses: 0 },
  summary: null,
};

const eventBuffer = [];
let flushTimer = null;
const FLUSH_INTERVAL_MS = 15000;

const syncHealth = {
  status: 'unknown',
  lastFlushOk: null,
  lastFlushTs: null,
  pendingEvents: 0,
  consecutiveFailures: 0,
};

function isSessionActive() { return session.state === 'active'; }

function bufferEvent(type, data) {
  if (!isSessionActive()) return;
  eventBuffer.push({ type, ts: Date.now(), data });
  syncHealth.pendingEvents = eventBuffer.length;
}

async function flushEventBuffer() {
  if (eventBuffer.length === 0 || !session.id) return;
  const batch = eventBuffer.splice(0);
  const result = await SessionClient.appendEvents(session.id, batch);
  if (result.error) {
    eventBuffer.unshift(...batch);
    syncHealth.consecutiveFailures++;
    syncHealth.lastFlushOk = false;
    syncHealth.status = syncHealth.consecutiveFailures >= 3 ? 'disconnected' : 'degraded';
  } else {
    syncHealth.consecutiveFailures = 0;
    syncHealth.lastFlushOk = true;
    syncHealth.lastFlushTs = Date.now();
    syncHealth.status = 'synced';
  }
  syncHealth.pendingEvents = eventBuffer.length;
}

function startFlushTimer() {
  stopFlushTimer();
  flushTimer = setInterval(flushEventBuffer, FLUSH_INTERVAL_MS);
}

function stopFlushTimer() {
  if (flushTimer) { clearInterval(flushTimer); flushTimer = null; }
}

async function persistSession() {
  await chrome.storage.local.set({ r3d_session: {
    state: session.state, id: session.id, name: session.name,
    startedAt: session.startedAt, endedAt: session.endedAt,
    notes: session.notes, scope: session.scope, aiEnabled: session.aiEnabled,
    counters: session.counters, summary: session.summary,
  }});
}

async function restoreSession() {
  try {
    const data = await chrome.storage.local.get('r3d_session');
    if (!data.r3d_session) return;
    const s = data.r3d_session;
    Object.assign(session, s);
    if (s.state === 'active' || s.state === 'paused') {
      startFlushTimer();
    }
    if (s.state === 'starting' || s.state === 'ending') {
      session.state = 'ended';
      session.endedAt = session.endedAt || Date.now();
    }
  } catch {}
}

async function saveSessionToHistory(summary) {
  try {
    const data = await chrome.storage.local.get('r3d_session_history');
    const history = data.r3d_session_history || [];
    history.unshift(summary);
    if (history.length > 50) history.length = 50;
    await chrome.storage.local.set({ r3d_session_history: history });
  } catch {}
}

async function getSessionHistory() {
  try {
    const data = await chrome.storage.local.get('r3d_session_history');
    return data.r3d_session_history || [];
  } catch { return []; }
}

// ─── Analysis State ─────────────────────────────────────────────────

const store = new RequestStore();
const idorCatalog = new IDORDetector.EndpointCatalog();
const rbacMatrix = new RBACAnalyzer.PermissionMatrix();
const headerScorecard = new HeaderAuditor.DomainScorecard();
const systemRegistry = new SystemFingerprinter.SystemRegistry();
const patternEngine = new PatternDetector.PatternEngine();
const evidenceStore = new EvidenceCollector.EvidenceStore();
const policyManager = new PolicyEngine.PolicyManager();

const state = {
  allFindings: [],
  tokens: [],
  piiFindings: [],
  idorFindings: [],
  rbacFindings: [],
  headerFindings: [],
  cookieFindings: [],
  patternFindings: [],
  advancedFindings: [],
  policyFindings: [],
  contentScriptData: [],
  currentUserId: null,
  pendingRequests: new Map(),
  activityLog: [],
  allowedDomains: [],
  phishSites: [],
};

const MAX_ACTIVITY_LOG = 200;
const aiAnalyses = new Map();
const aiAutoAnalyzed = new Set();

// Load persistent config on startup, then auto-discover proxy
policyManager.loadFromStorage();
AIClient.loadConfig();
restoreSession();

(async () => {
  await AIClient.loadConfig();
  const cfg = AIClient.getConfig();
  const needsDiscovery = !cfg.apiKey || cfg.apiKey === 'r3d-local-dev-key' || !cfg.endpoint;
  if (needsDiscovery || true) {
    const result = await AIClient.autoDiscover();
    if (result.ok) {
      console.log(`[R3D] Auto-connected to proxy at port ${result.port} (v${result.version})`);
      broadcastUpdate();
    }
  }
})();

chrome.storage.local.get('r3d_allowed_domains', (data) => {
  if (data.r3d_allowed_domains) state.allowedDomains = data.r3d_allowed_domains;
});

// ─── Helpers ────────────────────────────────────────────────────────

function logActivity(type, summary, systemId) {
  state.activityLog.unshift({ ts: Date.now(), type, summary, systemId });
  if (state.activityLog.length > MAX_ACTIVITY_LOG) state.activityLog.pop();
}

function isSelfTraffic(url) {
  if (url.startsWith('chrome-extension://') || url.startsWith('chrome://')) return true;
  try {
    const u = new URL(url);
    const proxyBase = AIClient.getConfig().endpoint || '';
    if (proxyBase) {
      const proxy = new URL(proxyBase);
      if (u.hostname === proxy.hostname && u.port === proxy.port) return true;
    }
    if ((u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '0.0.0.0') && u.port === '4000') return true;
  } catch {}
  return false;
}

function isDomainAllowed(url) {
  const domains = session.scope.length > 0 ? session.scope : state.allowedDomains;
  if (domains.length === 0) return true;
  try {
    const domain = new URL(url).hostname;
    return domains.some(d => domain === d || domain.endsWith('.' + d));
  } catch { return false; }
}

function enrichFinding(finding, entry) {
  if (!finding.cwe) {
    const classification = CWEMapper.classify(finding.module, finding.title);
    finding.cwe = classification.cwe;
    finding.owasp = classification.owasp;
    if (!finding.compliance || finding.compliance.length === 0) finding.compliance = classification.compliance;
    if (finding.confidence === 'medium' && classification.confidence !== 'medium') finding.confidence = classification.confidence;
  }
  if (entry) evidenceStore.capture(finding, entry);
  return finding;
}

const _seenFingerprints = new Map();

function pushFindings(findings, entry, sysId) {
  for (const f of findings) {
    enrichFinding(f, entry);
    if (sysId) {
      f.systemId = sysId;
      const sys = systemRegistry.getSystem(sysId);
      if (sys) f.systemName = sys.name;
      systemRegistry.addFinding(sysId, f);
    }

    const fp = f.fingerprint;
    if (fp && _seenFingerprints.has(fp)) {
      const existing = _seenFingerprints.get(fp);
      existing.occurrences = (existing.occurrences || 1) + 1;
      existing.lastSeen = Date.now();
      session.counters.findings++;
      continue;
    }

    state.allFindings.push(f);
    if (fp) _seenFingerprints.set(fp, f);
    session.counters.findings++;
    logActivity('finding', f.title, sysId);
    bufferEvent('finding', {
      id: f.id, title: f.title, severity: f.severity, cwe: f.cwe,
      systemId: sysId, confidence: f.confidence,
      status: f.status || 'hypothesis',
      evidenceSummary: f.detail ? f.detail.substring(0, 300) : null,
      headerContext: f.evidence?.headerContext || f.evidence?.cspAnalysis ? JSON.stringify(f.evidence.cspAnalysis || {}).substring(0, 300) : null,
    });

    // Keep collection/rendering deterministic in local dev. Manual AI actions
    // from the dashboard still work, but we avoid background fan-out requests
    // that can overload the proxy while a session is actively recording.
    const shouldAutoValidate = false && AIClient.isEnabled() &&
      (f.severity === 'CRITICAL' || f.severity === 'HIGH') &&
      !aiAutoAnalyzed.has(fp);

    if (shouldAutoValidate) {
      aiAutoAnalyzed.add(fp);

      const doValidateAndAnalyze = async () => {
        // Step 1: Validate the finding (lightweight classification)
        if (typeof AIClient.validateFinding === 'function') {
          const vResult = await AIClient.validateFinding(f);
          if (!vResult.error && vResult.structured) {
            const v = vResult.structured;
            if (v.status) {
              const raw = v.status.toLowerCase().replace(/[^a-z_]/g, '');
              const canonical = { confirmed: 'confirmed', likely: 'likely', hypothesis: 'hypothesis', possible: 'hypothesis', false_positive: 'false_positive', fp: 'false_positive' };
              f.status = canonical[raw] || raw;
            }
            if (v.adjustedSeverity && v.adjustedSeverity !== f.severity) f.severity = v.adjustedSeverity;
            if (v.reasoning) f.validationReasoning = v.reasoning;
            if (v.validationSteps) f.validationSteps = v.validationSteps;
            broadcastUpdate();
          }
        }

        // Step 2: Full analysis only for confirmed/likely findings
        if (f.status === 'confirmed' || f.status === 'likely' || f.severity === 'CRITICAL') {
          const result = await AIClient.analyzeFinding(f);
          if (!result.error) {
            aiAnalyses.set(`finding:${f.id}`, { type: 'finding', targetId: f.id, targetTitle: f.title, result: result.content, structured: result.structured, ts: Date.now(), model: result.model, auto: true, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
            session.counters.aiAnalyses++;
            logActivity('ai', `Auto-analyzed: ${f.title}`, sysId);
            bufferEvent('ai', { type: 'finding', targetTitle: f.title, model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
            broadcastUpdate();
          }
        }

        // Step 3: Auto-generate probes for hypothesis findings
        if (f.status === 'hypothesis' && typeof AIClient.generateProbes === 'function') {
          const probeResult = await AIClient.generateProbes([f], f.url || '');
          if (!probeResult.error && probeResult.structured?.probes?.length) {
            const base = proxyBaseUrl();
            if (base) {
              try {
                await fetch(`${base}/r3d/scan/run`, {
                  method: 'POST',
                  headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
                  body: JSON.stringify({
                    sessionId: session.id,
                    probes: probeResult.structured.probes,
                    useAuthContext: true,
                  }),
                });
                logActivity('scan', `Auto-probing hypothesis: ${f.title}`, sysId);
              } catch {}
            }
          }
        }
      };
      doValidateAndAnalyze().catch(() => {});
    }
  }
}

// ─── Panel connections ──────────────────────────────────────────────

const connectedPanels = new Set();

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'r3d-panel' || port.name === 'r3d-sidepanel') {
    connectedPanels.add(port);
    port.onDisconnect.addListener(() => connectedPanels.delete(port));
    port.postMessage({ type: 'state-snapshot', state: getStateSnapshot() });
  }
});

function broadcast(msg) {
  for (const port of connectedPanels) { try { port.postMessage(msg); } catch {} }
}

function getStateSnapshot() {
  const deduplicated = dedup(state.allFindings);
  return {
    session: {
      state: session.state, id: session.id, name: session.name,
      startedAt: session.startedAt, endedAt: session.endedAt,
      notes: session.notes, scope: session.scope, aiEnabled: session.aiEnabled,
      counters: { ...session.counters }, summary: session.summary,
    },
    findings: deduplicated,
    tokens: state.tokens.map(t => ({ source: t.source, header: t.header, payload: t.payload })),
    systems: systemRegistry.getSystems(),
    executiveSummary: systemRegistry.getExecutiveSummary(),
    patterns: patternEngine.getDetectedPatterns(),
    activityLog: state.activityLog,
    requestCount: store.size(),
    domainCount: store.getDomains().length,
    sessionStart: session.startedAt || Date.now(),
    currentUserId: state.currentUserId,
    headerScores: headerScorecard.getDomainScores(),
    idorEndpoints: idorCatalog.getEndpoints(),
    rbacSurface: rbacMatrix.getSurfaceReport(),
    piiFindings: state.piiFindings,
    idorFindings: state.idorFindings,
    rbacFindings: state.rbacFindings,
    headerFindings: state.headerFindings,
    cookieFindings: state.cookieFindings,
    patternFindings: state.patternFindings,
    advancedFindings: state.advancedFindings,
    policyFindings: state.policyFindings,
    evidencePacks: evidenceStore.getAll(),
    policyStatus: policyManager.getStatus(),
    policies: policyManager.getPolicies(),
    allowedDomains: state.allowedDomains,
    aiConfig: AIClient.getConfig(),
    aiAnalyses: Object.fromEntries(aiAnalyses),
    syncHealth: { ...syncHealth, pendingEvents: eventBuffer.length },
    promptKeys: AIClient.getPromptKeys(),
    promptVariables: AIClient.getPromptVariables(),
    promptLabels: AIClient.getPromptLabels(),
    promptOverrides: AIClient.getPromptOverrides(),
    debuggerAttached: !!debuggerTabId,
    phishSites: state.phishSites,
  };
}

// ─── Side panel activation ──────────────────────────────────────────

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// ─── Session Handlers ───────────────────────────────────────────────

async function handleSessionStart(opts) {
  if (session.state === 'active') return { error: 'Session already active' };

  clearAnalysisState();

  session.state = 'starting';
  session.id = crypto.randomUUID();
  session.name = opts.name || `Session ${new Date().toLocaleString()}`;
  session.startedAt = Date.now();
  session.endedAt = null;
  session.notes = opts.notes || '';
  session.scope = opts.scope || state.allowedDomains;
  session.aiEnabled = true;
  session.counters = { requests: 0, findings: 0, systems: 0, patterns: 0, aiAnalyses: 0 };
  session.summary = null;

  const persistResult = await SessionClient.startSession({
    sessionId: session.id, name: session.name, startedAt: session.startedAt,
    notes: session.notes, scope: session.scope, aiEnabled: session.aiEnabled,
  });

  if (persistResult.error) {
    syncHealth.status = 'disconnected';
    syncHealth.consecutiveFailures++;
    logActivity('warning', `Proxy unreachable — session is local-only: ${persistResult.error}`, null);
  } else {
    syncHealth.status = 'synced';
    syncHealth.consecutiveFailures = 0;
    syncHealth.lastFlushTs = Date.now();
  }

  session.state = 'active';
  await persistSession();
  startFlushTimer();
  logActivity('session', `Session started: ${session.name}`, null);
  broadcastUpdate();

  return { ok: true, sessionId: session.id, synced: !persistResult.error };
}

async function handleSessionEnd() {
  if (session.state !== 'active' && session.state !== 'paused') return { error: 'No active session' };

  session.state = 'ending';
  broadcastUpdate();

  await flushEventBuffer();
  stopFlushTimer();

  const exec = systemRegistry.getExecutiveSummary();
  session.endedAt = Date.now();
  session.counters.systems = exec.systemCount || 0;
  session.summary = {
    id: session.id, name: session.name,
    startedAt: session.startedAt, endedAt: session.endedAt,
    duration: session.endedAt - session.startedAt,
    notes: session.notes, scope: session.scope, aiEnabled: session.aiEnabled,
    counters: { ...session.counters },
    riskLevel: exec.riskLevel, overallRisk: exec.overallRisk,
    systemCount: exec.systemCount, totalFindings: exec.totalFindings,
    bySeverity: exec.bySeverity,
    topSystems: (exec.topRiskSystems || []).map(s => ({ name: s.name, riskScore: s.riskScore })),
    promptOverrides: Object.keys(AIClient.getPromptOverrides()),
  };

  const endResult = await SessionClient.endSession(session.id, session.summary).catch(() => ({ error: 'unreachable' }));
  if (endResult?.error) {
    syncHealth.status = 'disconnected';
    logActivity('warning', `Session end not persisted to proxy: ${endResult.error}`, null);
  } else {
    syncHealth.status = 'synced';
  }
  await saveSessionToHistory(session.summary);

  session.state = 'ended';
  await persistSession();
  logActivity('session', `Session ended: ${session.name}`, null);
  broadcastUpdate();

  /* AI Auto-Analysis Disabled by User Request - Too slow for long sessions
  if (AIClient.isEnabled() && state.allFindings.length > 0) {
    const snap = getStateSnapshot();

    function storeAI(key, type, targetTitle, r) {
      if (r.error) return;
      const entry = { type, targetTitle, result: r.content, structured: r.structured, ts: Date.now(), model: r.model, promptKey: r.promptKey, promptCustomized: r.promptCustomized };
      aiAnalyses.set(key, entry);
      session.counters.aiAnalyses++;
      bufferEvent('ai', { type, targetTitle, result: r.content, structured: r.structured, model: r.model, promptKey: r.promptKey, promptCustomized: r.promptCustomized });
      broadcastUpdate();
    }

    const analyses = [
      AIClient.generateExecutiveBrief(snap).then(r => storeAI('executive-brief', 'brief', null, r)),
      AIClient.analyzeAttackChains(snap.findings, snap.systems).then(r => storeAI('attack-chains', 'chains', null, r)),
      AIClient.triageFindings(snap.findings).then(r => storeAI('triage', 'triage', null, r)),
    ];

    for (const sys of (snap.systems || []).slice(0, 10)) {
      analyses.push(
        AIClient.analyzeSystem(sys).then(r => storeAI(`system:${sys.id}`, 'system', sys.name, r))
      );
    }

    await Promise.allSettled(analyses);
    await flushEventBuffer();
    broadcastUpdate();
  }
  */

  return { ok: true, summary: session.summary };
}

// ─── Message handling ───────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ─── Session control ────────────────────────────────────────────
  if (message.type === 'r3d-session-start') {
    handleSessionStart(message).then(sendResponse);
    return true;
  }
  if (message.type === 'r3d-session-end') {
    handleSessionEnd().then(sendResponse);
    return true;
  }
  if (message.type === 'r3d-session-pause') {
    if (session.state === 'active') { session.state = 'paused'; persistSession(); broadcastUpdate(); }
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-session-resume') {
    if (session.state === 'paused') { session.state = 'active'; persistSession(); broadcastUpdate(); }
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-session-get-history') {
    getSessionHistory().then(sendResponse);
    return true;
  }

  // ─── Prompt management ──────────────────────────────────────────
  if (message.type === 'r3d-prompt-save') {
    AIClient.savePromptOverride(message.key, message.text).then(() => { broadcastUpdate(); sendResponse({ ok: true }); });
    return true;
  }
  if (message.type === 'r3d-prompt-reset') {
    AIClient.resetPrompt(message.key).then(() => { broadcastUpdate(); sendResponse({ ok: true }); });
    return true;
  }
  if (message.type === 'r3d-prompt-get') {
    const k = message.key;
    sendResponse({
      key: k,
      text: AIClient.getPrompt(k),
      defaultText: AIClient.getDefaultPrompt(k),
      variables: (AIClient.getPromptVariables()[k] || []),
      isCustom: !!(AIClient.getPromptOverrides()[k]),
    });
    return false;
  }

  // ─── Debugger capture control ────────────────────────────────────
  if (message.type === 'r3d-enable-debugger') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) attachDebugger(tabs[0].id);
      sendResponse({ ok: true, tabId: tabs[0]?.id });
    });
    return true;
  }
  if (message.type === 'r3d-disable-debugger') {
    detachDebugger();
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-debugger-status') {
    sendResponse({ attached: !!debuggerTabId, tabId: debuggerTabId });
    return false;
  }

  // ─── CSP-safe proxy relay ────────────────────────────────────────
  if (message.type === 'r3d-proxy-relay') {
    const base = proxyBaseUrl();
    if (!base) { sendResponse({ error: 'Proxy not configured' }); return false; }
    const endpoint = (message.endpoint || '').replace(/^\/+/, '');
    const url = `${base}/${endpoint}`;
    (async () => {
      try {
        const resp = await fetch(url, {
          method: 'POST',
          headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify(message.body || {}),
        });
        const text = await resp.text();
        let data;
        try { data = JSON.parse(text); } catch { data = { raw: text }; }
        sendResponse({ data: { ok: resp.ok, status: resp.status, body: data } });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  // ─── Existing handlers ──────────────────────────────────────────
  if (message.type === 'r3d-content-data') {
    if (isSessionActive()) handleContentScriptData(message.data, sender.tab?.url || sender.url);
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-get-cookies') {
    chrome.cookies.getAll({ url: message.url }, (cookies) => sendResponse({ cookies: cookies || [] }));
    return true;
  }
  if (message.type === 'r3d-get-state') {
    sendResponse(getStateSnapshot());
    return false;
  }
  if (message.type === 'r3d-clear') {
    clearAll();
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-set-allowed-domains') {
    state.allowedDomains = message.domains || [];
    chrome.storage.local.set({ r3d_allowed_domains: state.allowedDomains });
    broadcastUpdate();
    sendResponse({ ok: true });
  }
  if (message.type === 'r3d-audit-cookies') {
    if (!isSessionActive()) { sendResponse({ ok: false, error: 'No active session' }); return true; }
    chrome.cookies.getAll({ url: message.url }, (cookies) => {
      if (cookies) {
        let domain; try { domain = new URL(message.url).hostname; } catch { domain = 'unknown'; }
        const findings = CookieAuditor.auditCookies(cookies, domain);
        findings.forEach(f => enrichFinding(f, null));
        state.cookieFindings.push(...findings);
        state.allFindings.push(...findings);
        const cookieMap = {};
        for (const c of cookies) cookieMap[c.name] = c.value;
        const jwtResult = JWTAnalyzer.analyze({ cookies: cookieMap, url: message.url });
        if (jwtResult.tokens.length > 0) state.tokens.push(...jwtResult.tokens);
        jwtResult.findings.forEach(f => enrichFinding(f, null));
        state.allFindings.push(...jwtResult.findings);
        broadcastUpdate();
      }
      sendResponse({ ok: true });
    });
    return true;
  }
  if (message.type === 'r3d-build-report') {
    const report = ReportGenerator.buildReport({
      findings: state.allFindings,
      tokens: state.tokens,
      endpoints: idorCatalog.getEndpoints(),
      domainScores: headerScorecard.getDomainScores(),
      surfaceReport: rbacMatrix.getSurfaceReport(),
      systems: systemRegistry.getSystems(),
      evidencePacks: evidenceStore.getAll(),
      policyStatus: policyManager.getStatus(),
      session: {
        id: session.id, name: session.name,
        startedAt: session.startedAt, endedAt: session.endedAt || Date.now(),
        duration: (session.endedAt || Date.now()) - (session.startedAt || Date.now()),
        scope: session.scope, aiEnabled: session.aiEnabled,
      },
      metadata: {
        url: message.url || '', totalRequests: store.size(),
        sessionDuration: (session.endedAt || Date.now()) - (session.startedAt || Date.now()),
        currentUserId: state.currentUserId,
      },
    });
    sendResponse(report);
    return false;
  }

  // ─── AI Analysis messages ─────────────────────────────────────────
  if (message.type === 'r3d-ai-config-save') {
    AIClient.saveConfig(message.config).then(() => { broadcastUpdate(); sendResponse({ ok: true }); });
    return true;
  }
  if (message.type === 'r3d-ai-config-get') {
    sendResponse(AIClient.getConfig());
    return false;
  }
  if (message.type === 'r3d-auto-discover') {
    AIClient.autoDiscover().then(result => {
      if (result.ok) broadcastUpdate();
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-analyze-finding') {
    const finding = message.finding;
    AIClient.analyzeFinding(finding).then(result => {
      if (!result.error) {
        aiAnalyses.set(`finding:${finding.id}`, { type: 'finding', targetId: finding.id, targetTitle: finding.title, result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', `AI analyzed: ${finding.title}`, finding.systemId);
        bufferEvent('ai', { type: 'finding', targetTitle: finding.title, model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-analyze-system') {
    const sys = message.system;
    AIClient.analyzeSystem(sys).then(result => {
      if (!result.error) {
        aiAnalyses.set(`system:${sys.id}`, { type: 'system', targetId: sys.id, targetTitle: sys.name, result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', `AI assessed: ${sys.name}`, sys.id);
        bufferEvent('ai', { type: 'system', targetTitle: sys.name, model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-attack-chains') {
    const snap = getStateSnapshot();
    AIClient.analyzeAttackChains(snap.findings, snap.systems).then(result => {
      if (!result.error) {
        aiAnalyses.set('attack-chains', { type: 'chains', result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', 'AI mapped cross-system attack chains', null);
        bufferEvent('ai', { type: 'chains', model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-executive-brief') {
    const snap = getStateSnapshot();
    AIClient.generateExecutiveBrief(snap).then(result => {
      if (!result.error) {
        aiAnalyses.set('executive-brief', { type: 'brief', result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', 'AI generated executive briefing', null);
        bufferEvent('ai', { type: 'brief', model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-triage') {
    const snap = getStateSnapshot();
    AIClient.triageFindings(snap.findings).then(result => {
      if (!result.error) {
        aiAnalyses.set('triage', { type: 'triage', result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', 'AI triaged all findings', null);
        bufferEvent('ai', { type: 'triage', model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-generate-probes') {
    const findings = message.findings || [];
    const origin = message.targetOrigin || '';
    AIClient.generateProbes(findings, origin).then(result => {
      if (!result.error) {
        logActivity('ai', `AI generated ${result.structured?.probes?.length || 0} active probes`, null);
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }
  if (message.type === 'r3d-ai-lateral-movement') {
    const graphData = message.graphData || {};
    AIClient.analyzeLateralMovement(graphData).then(result => {
      if (!result.error) {
        aiAnalyses.set('lateral-movement', { type: 'lateral', result: result.content, structured: result.structured, ts: Date.now(), model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        session.counters.aiAnalyses++;
        logActivity('ai', 'AI analyzed lateral movement paths', null);
        bufferEvent('ai', { type: 'lateral', model: result.model, promptKey: result.promptKey, promptCustomized: result.promptCustomized });
        broadcastUpdate();
      }
      sendResponse(result);
    });
    return true;
  }

  // ─── Phish handlers ──────────────────────────────────────────────
  if (message.type === 'r3d-phish-this-page') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url || tab.url.startsWith('chrome')) {
          sendResponse({ ok: false, error: 'No valid tab URL' });
          return;
        }
        const base = proxyBaseUrl();
        if (!base) { sendResponse({ ok: false, error: 'Proxy not connected' }); return; }
        const resp = await fetch(`${base}/r3d/attack/phish/clone`, {
          method: 'POST',
          headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ url: tab.url }),
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          sendResponse({ ok: false, error: data.error || 'Clone failed' });
          return;
        }
        const site = {
          siteId: data.siteId,
          targetUrl: tab.url,
          serveUrl: base + (data.serveUrl || `/p/${data.siteId}/`),
          clonedAt: Date.now(),
          captureCount: 0,
          captures: [],
        };
        state.phishSites = state.phishSites.filter(s => s.siteId !== site.siteId);
        state.phishSites.unshift(site);
        logActivity('phish', `Phish cloned: ${tab.url}`, null);
        broadcastUpdate();
        sendResponse({ ok: true, site });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    })();
    return true;
  }
  if (message.type === 'r3d-phish-list') {
    (async () => {
      try {
        const base = proxyBaseUrl();
        if (!base) { sendResponse({ ok: false, error: 'Proxy not connected' }); return; }
        const resp = await fetch(`${base}/r3d/attack/phish/sites`, {
          headers: proxyAuthHeaders(),
        });
        const data = await resp.json();
        if (data.ok && Array.isArray(data.sites)) {
          state.phishSites = data.sites.map(s => ({
            siteId: s.siteId,
            targetUrl: s.targetUrl,
            serveUrl: base + (s.serveUrl || `/p/${s.siteId}/`),
            clonedAt: s.clonedAt || Date.now(),
            captureCount: s.captureCount || 0,
            captures: s.captures || [],
          }));
          broadcastUpdate();
        }
        sendResponse({ ok: true, sites: state.phishSites });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    })();
    return true;
  }
  if (message.type === 'r3d-phish-delete') {
    (async () => {
      try {
        const base = proxyBaseUrl();
        if (!base) { sendResponse({ ok: false, error: 'Proxy not connected' }); return; }
        await fetch(`${base}/r3d/attack/phish/${message.siteId}`, {
          method: 'DELETE',
          headers: proxyAuthHeaders(),
        });
        state.phishSites = state.phishSites.filter(s => s.siteId !== message.siteId);
        logActivity('phish', `Phish site deleted: ${message.siteId}`, null);
        broadcastUpdate();
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    })();
    return true;
  }
  if (message.type === 'r3d-phish-relay-toggle') {
    (async () => {
      try {
        const base = proxyBaseUrl();
        if (!base) { sendResponse({ ok: false, error: 'Proxy not connected' }); return; }
        const resp = await fetch(`${base}/r3d/attack/phish/${message.siteId}/relay`, {
          method: 'POST',
          headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ enabled: message.enabled, loginUrl: message.loginUrl || '', mfaUrl: message.mfaUrl || '' }),
        });
        const data = await resp.json();
        sendResponse(data);
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    })();
    return true;
  }

  // ─── DOM XSS Scanner ─────────────────────────────────────────────
  if (message.type === 'r3d-dom-xss-scan') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url || tab.url.startsWith('chrome')) {
          sendResponse({ ok: false, error: 'No valid tab to scan' });
          return;
        }

        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['lib/dom-xss-scanner.js'],
          });
        } catch {}

        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            if (typeof DOMXSSScanner !== 'undefined') return DOMXSSScanner.scan();
            return { url: location.href, issues: [], error: 'Scanner not loaded' };
          },
        });

        const scanResult = results?.[0]?.result || { issues: [] };
        const issues = scanResult.issues || [];

        let sysId = null;
        try {
          const hostname = new URL(tab.url).hostname;
          const systems = systemRegistry.getSystems();
          const match = systems.find(s => (s.domains || []).some(d => hostname.includes(d) || d.includes(hostname)));
          if (match) sysId = match.id;
        } catch {}

        const sevMap = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', INFO: 'INFO' };
        const newFindings = [];

        for (const issue of issues) {
          if (issue.severity === 'INFO') continue;
          const f = createFinding({
            module: 'dom-xss',
            severity: sevMap[issue.severity] || Severity.MEDIUM,
            title: `DOM XSS: ${issue.type.replace(/-/g, ' ')}`,
            detail: issue.evidence,
            evidence: { type: issue.type, source: issue.source, sink: issue.sink, element: issue.element },
            url: scanResult.url || tab.url,
            recommendation: issue.recommendation,
            confidence: issue.severity === 'CRITICAL' ? Confidence.HIGH : Confidence.MEDIUM,
          });
          newFindings.push(f);
        }

        if (newFindings.length > 0) {
          newFindings.forEach(f => enrichFinding(f, null));
          state.allFindings.push(...newFindings);
          logActivity('scan', `DOM XSS scan: ${newFindings.length} issue(s) on ${scanResult.url || tab.url}`, sysId);
          broadcastUpdate();
        } else {
          logActivity('scan', `DOM XSS scan: clean — ${scanResult.url || tab.url}`, sysId);
        }

        sendResponse({ ok: true, result: scanResult, findingsCreated: newFindings.length });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    })();
    return true;
  }
});

// ─── Web request observation (session-gated) ────────────────────────

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!isSessionActive() || isSelfTraffic(details.url) || !isDomainAllowed(details.url)) return;
    const headerMap = {};
    for (const h of (details.requestHeaders || [])) headerMap[h.name] = h.value;
    state.pendingRequests.set(details.requestId, {
      url: details.url, method: details.method, ts: Date.now(),
      tabId: details.tabId, requestHeaders: headerMap,
    });
  },
  { urls: ['<all_urls>'] }, ['requestHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!isSessionActive() || isSelfTraffic(details.url) || !isDomainAllowed(details.url)) return;
    const pending = state.pendingRequests.get(details.requestId);
    const headerMap = {};
    const setCookieHeaders = [];
    for (const h of (details.responseHeaders || [])) {
      headerMap[h.name.toLowerCase()] = h.value;
      if (h.name.toLowerCase() === 'set-cookie') setCookieHeaders.push(h.value);
    }
    if (pending) {
      pending.status = details.statusCode;
      pending.responseHeaders = headerMap;
      pending.setCookieHeaders = setCookieHeaders;
      pending.responseContentType = headerMap['content-type'] || '';
    }

    const sysId = systemRegistry.identify(details.url, headerMap);

    const headerFindings = headerScorecard.auditResponse(details.url, headerMap, pending?.requestHeaders);
    if (headerFindings.length > 0) {
      pushFindings(headerFindings, pending, sysId);
      state.headerFindings.push(...headerFindings);
    }

    if (setCookieHeaders.length > 0) {
      const cookieFindings = CookieAuditor.auditSetCookieHeaders(setCookieHeaders, details.url);
      if (cookieFindings.length > 0) {
        pushFindings(cookieFindings, pending, sysId);
        state.cookieFindings.push(...cookieFindings);
      }
    }
  },
  { urls: ['<all_urls>'] }, ['responseHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!isSessionActive() || isSelfTraffic(details.url) || !isDomainAllowed(details.url)) return;
    const pending = state.pendingRequests.get(details.requestId);
    state.pendingRequests.delete(details.requestId);
    if (!pending) return;

    pending.status = details.statusCode;
    const entry = store.add(pending);
    const sysId = systemRegistry.identify(entry.url, entry.responseHeaders);
    if (sysId) { systemRegistry.recordRequest(sysId, entry); entry.systemId = sysId; }

    session.counters.requests++;
    bufferEvent('request', { url: entry.url, method: entry.method, status: entry.status, systemId: sysId });

    const rbacFindings = rbacMatrix.addRequest(entry);
    if (rbacFindings.length > 0) { pushFindings(rbacFindings, entry, sysId); state.rbacFindings.push(...rbacFindings); entry.findings.push(...rbacFindings); }

    const idorFindings = idorCatalog.addRequest(entry);
    if (idorFindings.length > 0) { pushFindings(idorFindings, entry, sysId); state.idorFindings.push(...idorFindings); entry.findings.push(...idorFindings); }

    const jwtResult = JWTAnalyzer.analyze({ url: entry.url, requestHeaders: entry.requestHeaders });
    if (jwtResult.tokens.length > 0) {
      state.tokens.push(...jwtResult.tokens);
      if (sysId) jwtResult.tokens.forEach(t => systemRegistry.addToken(sysId, t));
      for (const t of jwtResult.tokens) { if (t.payload) rbacMatrix.setJWTClaims(t.payload); }
    }
    if (jwtResult.findings.length > 0) { pushFindings(jwtResult.findings, entry, sysId); entry.findings.push(...jwtResult.findings); }

    const advFindings = AdvancedDetectors.analyze(entry);
    if (advFindings.length > 0) { pushFindings(advFindings, entry, sysId); state.advancedFindings.push(...advFindings); entry.findings.push(...advFindings); }

    if (sysId) {
      const policyFindings = policyManager.evaluate(sysId, entry);
      if (policyFindings.length > 0) { pushFindings(policyFindings, entry, sysId); state.policyFindings.push(...policyFindings); }
    }

    patternEngine.addRequest(entry);
    const patternFindings = patternEngine.analyze();
    if (patternFindings.length > 0) {
      patternFindings.forEach(f => enrichFinding(f, entry));
      state.patternFindings.push(...patternFindings);
      state.allFindings.push(...patternFindings);
      session.counters.patterns += patternFindings.length;
      for (const f of patternFindings) {
        logActivity('pattern', f.title, null);
        bufferEvent('pattern', { title: f.title, severity: f.severity });
      }
    }

    broadcastUpdate();
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => { state.pendingRequests.delete(details.requestId); },
  { urls: ['<all_urls>'] }
);

// ─── Content script data (session-gated) ────────────────────────────

function handleContentScriptData(data, url) {
  if (!isDomainAllowed(url)) return;
  state.contentScriptData.push(data);
  const sysId = systemRegistry.identify(url, {});

  if (data.type === 'cookies-js-accessible') {
    const jwtResult = JWTAnalyzer.analyze({ cookies: data.cookies, url: data.url });
    if (jwtResult.tokens.length > 0) { state.tokens.push(...jwtResult.tokens); if (sysId) jwtResult.tokens.forEach(t => systemRegistry.addToken(sysId, t)); }
    if (jwtResult.findings.length > 0) pushFindings(jwtResult.findings, null, sysId);
  }

  if (data.type === 'storage-secrets') {
    for (const item of data.items) {
      const f = createFinding({
        module: 'content', severity: item.isJWT ? Severity.HIGH : Severity.MEDIUM,
        title: `${item.storageType}: "${item.key}" contains ${item.isJWT ? 'JWT' : 'potential secret'}`,
        detail: `Found in ${item.storageType}. Value preview: ${item.valuePreview}`,
        evidence: item, url: data.url,
        recommendation: item.isJWT ? 'JWTs in localStorage are vulnerable to XSS theft. Use HttpOnly cookies.' : 'Review whether this value should be stored client-side.',
        confidence: item.isJWT ? Confidence.HIGH : Confidence.MEDIUM,
      });
      pushFindings([f], null, sysId);
    }
  }

  if (data.type === 'inline-script-secrets') {
    for (const finding of data.findings) {
      const f = createFinding({
        module: 'content', severity: Severity.HIGH,
        title: `Inline script contains ${finding.pattern}`,
        detail: `Script #${finding.scriptIndex}: ${finding.matchCount} match(es)`,
        evidence: finding, url: data.url,
        recommendation: 'Never embed secrets in inline JavaScript.',
        confidence: Confidence.HIGH,
      });
      pushFindings([f], null, sysId);
    }
  }

  if (data.type === 'dangerous-sink') {
    const f = createFinding({
      module: 'content', severity: Severity.MEDIUM,
      title: `Dangerous sink: ${data.sink.type}`,
      detail: `${data.sink.type} called with: ${data.sink.argPreview}`,
      evidence: data.sink, url: data.url,
      recommendation: 'Avoid eval(), document.write(), and uncontrolled innerHTML.',
      confidence: Confidence.MEDIUM,
    });
    pushFindings([f], null, sysId);
  }

  if (data.type === 'proto-pollution') {
    const f = createFinding({
      module: 'content', severity: Severity.HIGH,
      title: `Prototype pollution vector: ${data.detail.param}`,
      detail: `URL parameter "${data.detail.param}" contains prototype pollution payload: ${data.detail.value}`,
      evidence: data.detail, url: data.url,
      recommendation: 'Sanitize all user input. Never assign to __proto__ or constructor.prototype.',
      confidence: Confidence.HIGH, cwe: 'CWE-1321', owasp: 'A03:2021', compliance: ['SOC2'],
    });
    pushFindings([f], null, sysId);
  }

  if (data.type === 'websocket-activity') {
    const d = data.detail;
    const wsSysId = systemRegistry.identify(d.url || url, {});

    if (d.event === 'connect') {
      logActivity('recon', `WebSocket opened: ${d.url}`, wsSysId);
      if (d.url && d.url.startsWith('ws://')) {
        const f = createFinding({
          module: 'websocket', severity: Severity.MEDIUM,
          title: `Unencrypted WebSocket: ${d.url}`,
          detail: `WebSocket connection uses ws:// (plaintext) instead of wss://. Traffic can be intercepted on the network.`,
          evidence: { url: d.url, protocols: d.protocols }, url: data.url,
          recommendation: 'Always use wss:// for WebSocket connections.',
          confidence: Confidence.HIGH, cwe: 'CWE-319', owasp: 'A02:2021', compliance: ['SOC2', 'PCI'],
        });
        pushFindings([f], null, wsSysId);
      }
    }

    if (d.event === 'message' && d.preview && d.preview !== '[binary]') {
      const piiFindings = PIIScanner.scan(d.preview, d.url || url);
      if (piiFindings.length > 0) { pushFindings(piiFindings, null, wsSysId); state.piiFindings.push(...piiFindings); }
      const jwtResult = JWTAnalyzer.analyze({ responseBody: d.preview, url: d.url || url });
      if (jwtResult.tokens.length > 0) { state.tokens.push(...jwtResult.tokens); if (wsSysId) jwtResult.tokens.forEach(t => systemRegistry.addToken(wsSysId, t)); }
      if (jwtResult.findings.length > 0) pushFindings(jwtResult.findings, null, wsSysId);
    }
  }

  if (data.type === 'csp-violation') {
    const d = data.detail;
    let severity = Severity.LOW;
    let detail = `CSP violation: directive "${d.effectiveDirective}" blocked "${d.blockedURI}"`;

    if (d.blockedURI) {
      try {
        const blocked = new URL(d.blockedURI);
        const page = new URL(url);
        if (blocked.hostname !== page.hostname) {
          severity = Severity.HIGH;
          detail += ` — external resource blocked, possible data exfiltration attempt`;
        }
      } catch {}
    }
    if (/^script-src/i.test(d.effectiveDirective)) severity = Severity.HIGH;
    else if (/^(connect-src|frame-src|frame-ancestors)/i.test(d.effectiveDirective) && severity < Severity.MEDIUM) severity = Severity.MEDIUM;

    const f = createFinding({
      module: 'csp', severity,
      title: `CSP violation: ${d.effectiveDirective} blocked ${(d.blockedURI || 'inline').substring(0, 60)}`,
      detail, evidence: d, url: data.url,
      recommendation: 'Review whether the blocked resource is legitimate. If not, the CSP is correctly preventing an attack. If it is, update the CSP to allow it explicitly.',
      confidence: Confidence.HIGH, cwe: 'CWE-1021', owasp: 'A05:2021', compliance: ['SOC2'],
    });
    pushFindings([f], null, sysId);
  }

  if (data.type === 'intercepted-fetch' || data.type === 'intercepted-xhr') {
    const detail = data.detail;
    const reqSysId = systemRegistry.identify(detail.url, {});

    if (detail.bodyPreview && detail.contentType?.includes('json')) {
      const piiFindings = PIIScanner.scan(detail.bodyPreview, detail.url);
      if (piiFindings.length > 0) { pushFindings(piiFindings, null, reqSysId); state.piiFindings.push(...piiFindings); }
      const jwtResult = JWTAnalyzer.analyze({ responseBody: detail.bodyPreview, url: detail.url });
      if (jwtResult.tokens.length > 0) { state.tokens.push(...jwtResult.tokens); if (reqSysId) jwtResult.tokens.forEach(t => systemRegistry.addToken(reqSysId, t)); }
      if (jwtResult.findings.length > 0) pushFindings(jwtResult.findings, null, reqSysId);

      if (detail.url.includes('/users/me') && detail.status === 200) {
        try {
          const parsed = JSON.parse(detail.bodyPreview);
          const uid = parsed._id || parsed.id || parsed.user_id;
          if (uid) { state.currentUserId = String(uid); idorCatalog.setCurrentUserId(state.currentUserId); }
        } catch {}
      }
    }

    if (reqSysId) {
      systemRegistry.recordRequest(reqSysId, {
        url: detail.url, method: detail.method, status: detail.status,
        responseContentType: detail.contentType, responseSize: detail.bodySize,
      });
    }
  }

  if (data.type === 'framework-state') {
    for (const fw of data.frameworks) logActivity('recon', `${fw.framework} framework detected`, sysId);
  }

  broadcastUpdate();
}

// ─── Optional: chrome.debugger response body capture ────────────────
// Gated behind user opt-in. Attaches the Chrome debugger to the active
// tab to intercept response bodies that webRequest cannot access.

let debuggerTabId = null;
const _debuggerPendingBodies = new Map();

function attachDebugger(tabId) {
  if (debuggerTabId) detachDebugger();
  chrome.debugger.attach({ tabId }, '1.3', () => {
    if (chrome.runtime.lastError) {
      logActivity('error', `Debugger attach failed: ${chrome.runtime.lastError.message}`, null);
      return;
    }
    debuggerTabId = tabId;
    chrome.debugger.sendCommand({ tabId }, 'Network.enable', {});
    logActivity('recon', 'Response body capture enabled (debugger attached)', null);
    broadcastUpdate();
  });
}

function detachDebugger() {
  if (!debuggerTabId) return;
  try { chrome.debugger.detach({ tabId: debuggerTabId }); } catch {}
  debuggerTabId = null;
  _debuggerPendingBodies.clear();
  broadcastUpdate();
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (source.tabId !== debuggerTabId || !isSessionActive()) return;

  if (method === 'Network.responseReceived') {
    const resp = params.response || {};
    const ct = resp.mimeType || '';
    if (ct.includes('json') || ct.includes('text') || ct.includes('javascript')) {
      _debuggerPendingBodies.set(params.requestId, { url: resp.url, status: resp.status, contentType: ct });
    }
  }

  if (method === 'Network.loadingFinished') {
    const meta = _debuggerPendingBodies.get(params.requestId);
    if (!meta) return;
    _debuggerPendingBodies.delete(params.requestId);

    chrome.debugger.sendCommand({ tabId: debuggerTabId }, 'Network.getResponseBody', { requestId: params.requestId }, (result) => {
      if (chrome.runtime.lastError || !result?.body) return;
      const body = result.body.substring(0, 5000);
      if (!isDomainAllowed(meta.url)) return;
      const dbgSysId = systemRegistry.identify(meta.url, {});

      const piiFindings = PIIScanner.scan(body, meta.url);
      if (piiFindings.length > 0) { pushFindings(piiFindings, null, dbgSysId); state.piiFindings.push(...piiFindings); }

      const jwtResult = JWTAnalyzer.analyze({ responseBody: body, url: meta.url });
      if (jwtResult.tokens.length > 0) { state.tokens.push(...jwtResult.tokens); if (dbgSysId) jwtResult.tokens.forEach(t => systemRegistry.addToken(dbgSysId, t)); }
      if (jwtResult.findings.length > 0) pushFindings(jwtResult.findings, null, dbgSysId);
    });
  }
});

chrome.debugger.onDetach.addListener((source) => {
  if (source.tabId === debuggerTabId) {
    debuggerTabId = null;
    _debuggerPendingBodies.clear();
    logActivity('recon', 'Response body capture disabled (debugger detached)', null);
    broadcastUpdate();
  }
});

// ─── Broadcast (throttled) ──────────────────────────────────────────

let broadcastTimer = null;
function broadcastUpdate() {
  if (broadcastTimer) return;
  broadcastTimer = setTimeout(() => {
    broadcastTimer = null;
    broadcast({ type: 'state-update', state: getStateSnapshot() });
  }, 300);
}

// ─── Clear / Reset ──────────────────────────────────────────────────

function clearAnalysisState() {
  store.clear();
  _seenFingerprints.clear();
  state.allFindings = [];
  state.tokens = [];
  state.piiFindings = [];
  state.idorFindings = [];
  state.rbacFindings = [];
  state.headerFindings = [];
  state.cookieFindings = [];
  state.patternFindings = [];
  state.advancedFindings = [];
  state.policyFindings = [];
  state.contentScriptData = [];
  state.activityLog = [];
  state.pendingRequests.clear();
  state.currentUserId = null;
  systemRegistry.clear();
  patternEngine.clear();
  evidenceStore.clear();
  policyManager.clear();
  AdvancedDetectors.clear();
  aiAnalyses.clear();
  aiAutoAnalyzed.clear();
  eventBuffer.length = 0;
}

function clearAll() {
  clearAnalysisState();
  session.state = 'idle';
  session.id = null;
  session.name = null;
  session.startedAt = null;
  session.endedAt = null;
  session.notes = '';
  session.scope = [];
  session.aiEnabled = true;
  session.counters = { requests: 0, findings: 0, systems: 0, patterns: 0, aiAnalyses: 0 };
  session.summary = null;
  state.phishSites = [];
  stopFlushTimer();
  persistSession();
  broadcastUpdate();
}

// ─── Test Execution Engine ────────────────────────────────────────────
// Polls the proxy for pending tests and injects them into the active tab
// via chrome.scripting.executeScript. Reports results back to the proxy.

let _testPollInterval = null;

function proxyBaseUrl() {
  const ep = AIClient.getConfig().endpoint || '';
  const idx = ep.indexOf('/v1/');
  return idx !== -1 ? ep.substring(0, idx) : ep.replace(/\/+$/, '');
}

function proxyAuthHeaders(extra) {
  const h = Object.assign({}, extra || {});
  const key = AIClient.getConfig().apiKey;
  if (key) h['Authorization'] = `Bearer ${key}`;
  return h;
}

async function pollPendingTests() {
  const base = proxyBaseUrl();
  if (!base) return;
  try {
    const resp = await fetch(`${base}/r3d/test/pending`, { headers: proxyAuthHeaders() });
    if (!resp.ok) return;
    const tests = await resp.json();
    for (const test of tests) {
      if (test.snippet) await executeTestOnActiveTab(test);
    }
  } catch {}
}

async function findTargetTab(targetOrigin) {
  if (targetOrigin) {
    const tabs = await chrome.tabs.query({ currentWindow: true });
    for (const tab of tabs) {
      try {
        if (tab.url && new URL(tab.url).origin === targetOrigin) return tab;
      } catch {}
    }
  }
  const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
  return active || null;
}

async function executeTestOnActiveTab(test) {
  const testId = test.testId || 'unknown';
  const base = proxyBaseUrl();
  const targetOrigin = test.targetOrigin || '';

  try {
    const tab = await findTargetTab(targetOrigin);
    if (!tab?.id) {
      await reportTestResultEx(base, testId, false, '', 'No matching tab found' + (targetOrigin ? ` for ${targetOrigin}` : ''), '', null);
      return;
    }

    let executedOrigin = '';
    try { executedOrigin = new URL(tab.url).origin; } catch {}

    if (targetOrigin && executedOrigin !== targetOrigin) {
      logActivity('test', `Target mismatch: wanted ${targetOrigin}, got ${executedOrigin}. Running anyway.`, null);
    }

    const proxyBase = base;
    const proxyKey = AIClient.getConfig().apiKey || '';

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content/content.js'],
      });
    } catch (_injectErr) {}

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: async (snippet, _proxyBase, _proxyKey) => {
        const output = [];
        const origLog = console.log;
        console.log = function(...args) {
          const msg = args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
          if (msg.includes('[R3D TEST]')) output.push(msg);
          origLog.apply(console, args);
        };

        if (typeof window.__r3d_proxy !== 'function') {
          let _seq = 0;
          window.__r3d_proxy = function(endpoint, body) {
            const id = '__r3d_relay_' + (++_seq) + '_' + Date.now();
            return new Promise((resolve, reject) => {
              const timeout = setTimeout(() => {
                window.removeEventListener('__r3d_relay_response', handler);
                reject(new Error('R3D proxy relay timeout (10s)'));
              }, 10000);
              function handler(e) {
                if (e.detail && e.detail._relayId === id) {
                  clearTimeout(timeout);
                  window.removeEventListener('__r3d_relay_response', handler);
                  if (e.detail.error) reject(new Error(e.detail.error));
                  else resolve(e.detail.data);
                }
              }
              window.addEventListener('__r3d_relay_response', handler);
              window.dispatchEvent(new CustomEvent('__r3d_relay_request', {
                detail: { _relayId: id, endpoint, body }
              }));
            });
          };
        }

        try {
          const fn = new Function(`return (async () => { ${snippet} })();`);
          await Promise.race([
            fn(),
            new Promise(r => setTimeout(r, 10000)),
          ]);
        } catch(e) {
          output.push('[R3D TEST] ERROR: ' + e.message);
        }
        await new Promise(r => setTimeout(r, 500));
        console.log = origLog;
        return { output: output.join('\n'), error: null };
      },
      args: [test.snippet, proxyBase, proxyKey],
      world: 'MAIN',
    });

    const result = results?.[0]?.result;
    const outputStr = result?.output || '(no output captured)';
    const hasVuln = outputStr.includes('VULNERABLE');
    const hasSafe = outputStr.includes('SAFE');

    await reportTestResultEx(base, testId, true, outputStr, result?.error || null, executedOrigin, tab.id);
    logActivity('test', `Test executed: ${test.findingTitle || testId} → ${hasVuln ? 'VULNERABLE' : hasSafe ? 'SAFE' : 'executed'} on ${executedOrigin}`, null);
    broadcastUpdate();

  } catch (err) {
    await reportTestResultEx(base, testId, false, '', err.message, '', null);
  }
}

async function reportTestResultEx(base, testId, success, output, error, executedOn, tabId) {
  if (!base) return;
  try {
    await fetch(`${base}/r3d/test/result`, {
      method: 'POST',
      headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ testId, success, output, error, executedOn: executedOn || '', tabId: tabId || null }),
    });
  } catch {}
}

// Legacy wrapper removed — all callers use reportTestResultEx

function startTestPoller() {
  if (_testPollInterval) return;
  _testPollInterval = setInterval(pollPendingTests, 2000);
}

function stopTestPoller() {
  if (_testPollInterval) {
    clearInterval(_testPollInterval);
    _testPollInterval = null;
  }
}

// ─── Extension Heartbeat ────────────────────────────────────────────
let _heartbeatInterval = null;

async function sendHeartbeat() {
  const base = proxyBaseUrl();
  if (!base) return;
  try {
    await fetch(`${base}/r3d/extension/heartbeat`, {
      method: 'POST',
      headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        sessionId: session.id,
        sessionName: session.name,
        sessionState: session.state,
        pendingEvents: eventBuffer.length,
        counters: session.counters,
      }),
    });
  } catch {}
}

function startHeartbeat() {
  if (_heartbeatInterval) return;
  _heartbeatInterval = setInterval(sendHeartbeat, 5000);
  sendHeartbeat();
}

function stopHeartbeat() {
  if (_heartbeatInterval) { clearInterval(_heartbeatInterval); _heartbeatInterval = null; }
}

// ─── Auth Context Pusher ────────────────────────────────────────────
// Periodically gathers cookies (including HttpOnly) and observed auth
// headers for active tab origins, then pushes to the proxy so attack
// helpers can replay with full credentials.

let _authContextInterval = null;
const _lastPushedOrigins = new Map();

async function pushAuthContext() {
  if (!isSessionActive()) return;
  const base = proxyBaseUrl();
  if (!base) return;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || tab.url.startsWith('chrome')) return;

    let origin;
    try { origin = new URL(tab.url).origin; } catch { return; }

    const lastPush = _lastPushedOrigins.get(origin) || 0;
    if (Date.now() - lastPush < 30000) return;

    const cookies = await new Promise(resolve => {
      chrome.cookies.getAll({ url: tab.url }, c => resolve(c || []));
    });
    const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join('; ');

    const observedHeaders = {};
    for (const [, req] of state.pendingRequests) {
      if (!req.url) continue;
      try {
        if (new URL(req.url).origin === origin && req.requestHeaders) {
          for (const [k, v] of Object.entries(req.requestHeaders)) {
            const lk = k.toLowerCase();
            if (lk === 'authorization' || lk === 'x-csrf-token' || lk === 'x-xsrf-token') {
              observedHeaders[k] = v;
            }
          }
        }
      } catch {}
    }

    await fetch(`${base}/r3d/auth-context`, {
      method: 'POST',
      headers: proxyAuthHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        origin,
        cookies: cookieStr,
        headers: observedHeaders,
        userAgent: navigator.userAgent,
      }),
    });
    _lastPushedOrigins.set(origin, Date.now());
  } catch {}
}

function startAuthContextPusher() {
  if (_authContextInterval) return;
  _authContextInterval = setInterval(pushAuthContext, 10000);
  pushAuthContext();
}

function stopAuthContextPusher() {
  if (_authContextInterval) { clearInterval(_authContextInterval); _authContextInterval = null; }
  _lastPushedOrigins.clear();
}

startTestPoller();
startAuthContextPusher();
startHeartbeat();

console.log('[R3D] Service worker v5.3 initialized');
