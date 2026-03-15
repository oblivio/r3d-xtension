/**
 * Side Panel Controller — Streamlined mission control surface.
 * Live findings, activity feed, systems, tokens, headers, session deep links.
 */
(() => {
  'use strict';

  const SEV_COLOR = { CRITICAL: '#ff1744', HIGH: '#ff9100', MEDIUM: '#ffea00', LOW: '#00e5ff', INFO: '#69f0ae', CLEAN: '#69f0ae' };
  const SEV_W = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const DASHBOARD_BASE = 'http://0.0.0.0:4000';

  let snapshot = null;
  let lastSessionState = null;
  let timerInterval = null;
  let activeTab = 'activity';

  // ─── Connection ────────────────────────────────────────────────────

  let port = null;
  function connect() {
    port = chrome.runtime.connect({ name: 'r3d-sidepanel' });
    port.onMessage.addListener(msg => {
      if (msg.type === 'state-snapshot' || msg.type === 'state-update') { snapshot = msg.state; render(); }
    });
    port.onDisconnect.addListener(() => setTimeout(connect, 1000));
  }
  connect();
  setTimeout(() => { chrome.runtime.sendMessage({ type: 'r3d-get-state' }, r => { if (r && !snapshot) { snapshot = r; render(); } }); }, 500);

  // ─── Tab switching ─────────────────────────────────────────────────

  document.querySelectorAll('.sp-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sp-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.sp-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const panel = document.getElementById('panel-' + tab.dataset.tab);
      if (panel) panel.classList.add('active');
      activeTab = tab.dataset.tab;
      renderTabContent();
    });
  });

  // ─── Dashboard deep link ───────────────────────────────────────────

  function getDashboardUrl() {
    const sid = snapshot?.session?.id;
    if (sid && snapshot?.session?.state !== 'idle') {
      return DASHBOARD_BASE + '/#session=' + sid;
    }
    return DASHBOARD_BASE;
  }

  document.getElementById('btn-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: getDashboardUrl() });
  });

  // ─── Codename generator ────────────────────────────────────────────

  const _ADJ = ['Silent','Shadow','Crimson','Phantom','Iron','Midnight','Neon','Obsidian','Rapid','Stealth','Arctic','Venom','Ghost','Rogue','Ember','Cobalt','Onyx','Frost','Apex','Storm'];
  const _NOUN = ['Falcon','Viper','Sentinel','Hydra','Phoenix','Reaper','Spectre','Titan','Cipher','Wolf','Mantis','Jackal','Raptor','Serpent','Warden','Raven','Lynx','Kraken','Sabre','Talon'];

  function generateCodename() {
    const a = _ADJ[Math.floor(Math.random() * _ADJ.length)];
    const n = _NOUN[Math.floor(Math.random() * _NOUN.length)];
    return `${a} ${n}-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`;
  }

  // ─── Session actions ───────────────────────────────────────────────

  function doStartSession() {
    const name = generateCodename();
    const notes = document.getElementById('session-notes-input')?.value.trim();
    chrome.runtime.sendMessage({ type: 'r3d-session-start', name, notes });
  }

  function doEndSession() {
    if (!confirm('End the current audit session?')) return;
    chrome.runtime.sendMessage({ type: 'r3d-session-end' });
  }

  // ─── Timer ─────────────────────────────────────────────────────────

  function startTimer() { stopTimer(); timerInterval = setInterval(updateTimer, 1000); }
  function stopTimer() { if (timerInterval) { clearInterval(timerInterval); timerInterval = null; } }

  function updateTimer() {
    const s = snapshot?.session;
    if (!s?.startedAt || s.state !== 'active') { stopTimer(); return; }
    const el = document.getElementById('session-timer');
    if (el) el.textContent = fmtDuration(Date.now() - s.startedAt);
  }

  // ─── Main render ───────────────────────────────────────────────────

  function render() {
    if (!snapshot) return;
    renderSessionCard();
    renderTabContent();
  }

  // ─── Session Card ──────────────────────────────────────────────────

  function renderSessionCard() {
    const card = document.getElementById('session-card');
    const s = snapshot?.session;
    const newState = s?.state || 'idle';

    if (newState === 'idle' && lastSessionState === 'idle') {
      const focused = document.activeElement;
      if (focused && (focused.id === 'session-notes-input')) return;
    }

    if (newState === 'active' && lastSessionState === 'active') {
      updateSessionCounters();
      return;
    }

    lastSessionState = newState;

    if (!s || newState === 'idle') {
      const proxyReady = snapshot?.aiConfig?.endpoint && snapshot?.aiConfig?.apiKey;

      if (!proxyReady) {
        card.innerHTML = `
          <div class="session-idle">
            <div class="setup-prompt">
              <div class="notice-title">Connecting to R3D proxy...</div>
              <div class="notice-sub" id="setup-status">Looking for proxy at ${DASHBOARD_BASE}</div>
              <button class="btn-start-session" id="btn-setup-retry" style="display:none;margin-top:8px">Retry</button>
            </div>
          </div>`;
        const statusEl = document.getElementById('setup-status');
        const retryBtn = document.getElementById('btn-setup-retry');
        function tryAutoConnect() {
          if (statusEl) statusEl.textContent = 'Connecting...';
          if (retryBtn) retryBtn.style.display = 'none';
          chrome.runtime.sendMessage({ type: 'r3d-auto-discover' }, (r) => {
            if (r && r.ok) {
              if (statusEl) statusEl.innerHTML = '<span style="color:var(--green)">Connected (v' + (r.version || '?') + ')</span>';
              setTimeout(() => { chrome.runtime.sendMessage({ type: 'r3d-get-state' }, st => { if (st) { snapshot = st; render(); } }); }, 300);
            } else {
              if (statusEl) statusEl.innerHTML = 'Proxy not found. Run <code>docker compose up --build</code>';
              if (retryBtn) retryBtn.style.display = 'inline-block';
            }
          });
        }
        retryBtn.addEventListener('click', tryAutoConnect);
        tryAutoConnect();
        stopTimer();
        return;
      }

      card.innerHTML = `
        <div class="session-idle">
          <div class="onboarding-steps">
            <div class="onboarding-step"><span class="step-num">1</span> Launch</div>
            <span class="step-arrow">\u2192</span>
            <div class="onboarding-step"><span class="step-num">2</span> Browse</div>
            <span class="step-arrow">\u2192</span>
            <div class="onboarding-step"><span class="step-num">3</span> Review</div>
          </div>
          <div class="session-form">
            <textarea id="session-notes-input" placeholder="Mission brief (optional)" rows="1"></textarea>
            <button class="btn-start-session" id="btn-start-session">Launch Audit</button>
          </div>
        </div>`;
      document.getElementById('btn-start-session').addEventListener('click', doStartSession);
      stopTimer();
      return;
    }

    if (newState === 'active' || newState === 'paused') {
      const badge = newState === 'active' ? 'active' : 'paused';
      const label = newState === 'active' ? 'AUDITING' : 'PAUSED';
      const sh = snapshot?.syncHealth || {};
      const syncColor = sh.status === 'synced' ? 'var(--green)' : sh.status === 'degraded' ? 'var(--orange)' : sh.status === 'disconnected' ? 'var(--red)' : 'var(--txt-dim)';
      const syncLabel = sh.status === 'synced' ? 'SYNCED' : sh.status === 'degraded' ? 'DEGRADED' : sh.status === 'disconnected' ? 'LOCAL' : '...';
      card.innerHTML = `
        <div class="session-active">
          <div class="session-top-row">
            <span class="session-badge ${badge}">${label}</span>
            <span class="session-timer" id="session-timer">${fmtDuration(Date.now() - s.startedAt)}</span>
            <span class="session-name-display">${esc(s.name)}</span>
            <div class="session-actions">
              ${newState === 'active'
                ? '<button class="btn btn-sm" id="btn-pause-session">Pause</button>'
                : '<button class="btn btn-sm btn-primary" id="btn-resume-session">Resume</button>'}
              <button class="btn-end-session" id="btn-end-session">End</button>
            </div>
          </div>
          <div class="session-meta-row">
            <span class="sync-indicator"><span class="sync-dot" style="background:${syncColor}"></span>${syncLabel}</span>
          </div>
        </div>
        <div class="session-counters" id="session-counters-bar">${renderCounters(s)}</div>`;
      document.getElementById('btn-end-session').addEventListener('click', doEndSession);
      const pb = document.getElementById('btn-pause-session');
      if (pb) pb.addEventListener('click', () => chrome.runtime.sendMessage({ type: 'r3d-session-pause' }));
      const rb = document.getElementById('btn-resume-session');
      if (rb) rb.addEventListener('click', () => chrome.runtime.sendMessage({ type: 'r3d-session-resume' }));
      startTimer();
      return;
    }

    if (newState === 'ending') {
      card.innerHTML = '<div class="session-idle" style="padding:14px;"><div class="ai-loading">Analyzing session...</div></div>';
      return;
    }

    if (newState === 'ended') {
      const c = s.summary || s.counters;
      card.innerHTML = `
        <div class="session-ended">
          <span class="session-badge ended">COMPLETE</span>
          <div style="font-size:10px;color:var(--txt-dim);margin:4px 0;">${esc(s.name)} \u2014 ${fmtDuration((s.endedAt || Date.now()) - (s.startedAt || Date.now()))}</div>
          <div class="summary-row">
            <div><div class="summary-val" style="color:var(--orange)">${c.findings || c.totalFindings || 0}</div><div class="summary-lbl">Findings</div></div>
            <div><div class="summary-val" style="color:var(--accent)">${c.systems || c.systemCount || 0}</div><div class="summary-lbl">Systems</div></div>
            <div><div class="summary-val" style="color:var(--txt)">${c.requests || 0}</div><div class="summary-lbl">Requests</div></div>
          </div>
          <div class="toolbar" style="justify-content:center;margin-top:8px;gap:8px">
            <button class="btn btn-primary btn-sm" id="btn-new-session">New Audit</button>
            <button class="btn btn-sm" id="btn-view-dashboard">View in Dashboard</button>
          </div>
        </div>`;
      document.getElementById('btn-new-session').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'r3d-clear' }));
      document.getElementById('btn-view-dashboard').addEventListener('click', () => chrome.tabs.create({ url: getDashboardUrl() }));
      stopTimer();
    }
  }

  function renderCounters(s) {
    return `
      <span><span class="counter-val">${s.counters.findings}</span> findings</span>
      <span><span class="counter-val">${s.counters.systems}</span> systems</span>
      <span><span class="counter-val">${s.counters.requests}</span> reqs</span>`;
  }

  function updateSessionCounters() {
    const s = snapshot?.session;
    if (!s) return;
    const bar = document.getElementById('session-counters-bar');
    if (bar) bar.innerHTML = renderCounters(s);
  }

  // ─── Tab Content Renderers ─────────────────────────────────────────

  function renderTabContent() {
    if (!snapshot) return;
    switch (activeTab) {
      case 'activity': renderActivity(); break;
      case 'findings': renderFindings(); break;
      case 'systems': renderSystems(); break;
      case 'tokens': renderTokens(); break;
      case 'headers': renderHeaders(); break;
    }
  }

  function renderActivity() {
    const el = document.getElementById('panel-activity');
    const log = snapshot.activityLog || [];
    if (!log.length) {
      el.innerHTML = '<div class="empty-hint"><strong>No activity yet</strong>Start an audit and browse your target app.</div>';
      return;
    }
    el.innerHTML = log.slice(0, 100).map(a => {
      const t = a.ts ? new Date(a.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
      const cls = a.type || 'session';
      return `<div class="feed-item"><span class="feed-time">${t}</span><span class="feed-type ${cls}">${esc(a.type || '?')}</span><span class="feed-msg">${esc(a.summary || '')}</span></div>`;
    }).join('');
  }

  function renderFindings() {
    const el = document.getElementById('panel-findings');
    const findings = snapshot.findings || [];
    if (!findings.length) {
      el.innerHTML = '<div class="empty-hint"><strong>No findings yet</strong>Findings appear as you browse target apps during an audit.</div>';
      return;
    }
    const sorted = [...findings].sort((a, b) => (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0));
    const sid = snapshot.session?.id;
    el.innerHTML = sorted.map(f => {
      const st = f.status || 'likely';
      const stCls = st === 'confirmed' ? 'status-confirmed' : st === 'likely' ? 'status-likely' : 'status-hypothesis';
      const deepLink = sid ? `${DASHBOARD_BASE}/#session=${sid}` : DASHBOARD_BASE;
      return `<div class="finding-item" data-link="${esc(deepLink)}">
        <span class="sev-dot sev-${f.severity || 'INFO'}"></span>
        <span class="finding-title">${esc(f.title || 'Untitled')}</span>
        <span class="finding-status ${stCls}">${esc(st)}</span>
        <span class="finding-meta">${esc(f.severity || '?')}</span>
      </div>`;
    }).join('');
    el.querySelectorAll('.finding-item').forEach(item => {
      item.addEventListener('click', () => {
        const link = item.dataset.link;
        if (link) chrome.tabs.create({ url: link });
      });
    });
  }

  function renderSystems() {
    const el = document.getElementById('panel-systems');
    const systems = snapshot.systems || [];
    if (!systems.length) {
      el.innerHTML = '<div class="empty-hint"><strong>No systems detected</strong>Systems are identified from the domains and APIs you browse.</div>';
      return;
    }
    el.innerHTML = systems.map(s => {
      const score = s.riskScore || 0;
      const color = score >= 80 ? 'var(--red)' : score >= 50 ? 'var(--orange)' : score >= 25 ? 'var(--yellow)' : 'var(--green)';
      return `<div class="system-card">
        <div style="flex:1;min-width:0">
          <div class="system-name">${esc(s.name || s.id)}</div>
          <div class="system-stats">
            <span>${s.findingCount || 0} findings</span>
            <span>${s.requestCount || 0} requests</span>
            <span>${s.endpointCount || 0} endpoints</span>
          </div>
        </div>
        <div class="system-score" style="color:${color}">${score}</div>
      </div>`;
    }).join('');
  }

  function renderTokens() {
    const el = document.getElementById('panel-tokens');
    const tokens = snapshot.tokens || [];
    if (!tokens.length) {
      el.innerHTML = '<div class="empty-hint"><strong>No tokens captured</strong>JWTs and auth tokens are captured from request/response headers and localStorage.</div>';
      return;
    }
    el.innerHTML = tokens.map(t => {
      const p = t.payload || {};
      const claims = [];
      if (p.sub) claims.push(`<strong>sub:</strong> ${esc(p.sub)}`);
      if (p.email) claims.push(`<strong>email:</strong> ${esc(p.email)}`);
      if (p.iss) claims.push(`<strong>iss:</strong> ${esc(p.iss)}`);
      if (p.exp) claims.push(`<strong>exp:</strong> ${esc(new Date(p.exp * 1000).toLocaleString())}`);
      const alg = t.header?.alg || '?';
      return `<div class="token-card">
        <div class="token-source">${esc(t.source || 'unknown')} (${esc(alg)})</div>
        ${claims.map(c => `<div class="token-claim">${c}</div>`).join('')}
      </div>`;
    }).join('');
  }

  function renderHeaders() {
    const el = document.getElementById('panel-headers');
    const scores = snapshot.headerScores || {};
    const domains = Object.keys(scores);
    if (!domains.length) {
      el.innerHTML = '<div class="empty-hint"><strong>No headers audited</strong>Security headers are checked as HTTP responses arrive.</div>';
      return;
    }
    const important = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy'];
    el.innerHTML = domains.map(d => {
      const info = scores[d] || {};
      const present = info.presentHeaders || [];
      return `<div class="header-domain">
        <div class="header-domain-name">${esc(d)}</div>
        ${important.map(h => {
          const has = present.includes(h);
          return `<div class="header-row"><span class="header-name">${esc(h)}</span><span class="header-val ${has ? 'header-present' : 'header-missing'}">${has ? 'PRESENT' : 'MISSING'}</span></div>`;
        }).join('')}
      </div>`;
    }).join('');
  }

  // ─── Helpers ───────────────────────────────────────────────────────

  function esc(s) { const d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }
  function fmtDuration(ms) { const s = Math.floor(ms / 1000); return s < 60 ? s + 's' : s < 3600 ? Math.floor(s / 60) + 'm ' + s % 60 + 's' : Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'; }

})();
