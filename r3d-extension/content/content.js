/**
 * Content Script — DOM inspection, storage scanning, fetch/XHR hooking,
 * framework state extraction, and dangerous-sink monitoring.
 *
 * Injected into every page. Runs in the page's isolated world by default;
 * a page-world script is injected for deep hooks (fetch, XHR, eval).
 */
(() => {
  'use strict';
  const R3D_TAG = '[R3D:content]';

  // ─── Utility ───────────────────────────────────────────────────────

  function _alive() {
    try { return !!chrome.runtime?.id; } catch { return false; }
  }

  function send(data) {
    if (!_alive()) return;
    try {
      chrome.runtime.sendMessage({ type: 'r3d-content-data', data });
    } catch {}
  }

  function safeStringify(obj, maxLen = 2000) {
    try {
      const s = JSON.stringify(obj);
      return s.length > maxLen ? s.substring(0, maxLen) + '...(truncated)' : s;
    } catch { return String(obj).substring(0, maxLen); }
  }

  // ─── 1. Cookie scanning ───────────────────────────────────────────

  function scanCookies() {
    const raw = document.cookie;
    if (!raw) return;
    const cookies = {};
    for (const pair of raw.split(';')) {
      const [name, ...rest] = pair.trim().split('=');
      if (name) cookies[name.trim()] = rest.join('=');
    }
    if (Object.keys(cookies).length > 0) {
      send({ type: 'cookies-js-accessible', cookies, url: location.href });
    }
  }

  // ─── 2. localStorage / sessionStorage scanning ────────────────────

  function scanStorage() {
    const suspicious = [];
    const secretPatterns = [
      /token/i, /key/i, /secret/i, /password/i, /credential/i,
      /jwt/i, /auth/i, /session/i, /api.?key/i, /bearer/i,
    ];
    const jwtPattern = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

    for (const [storageType, storage] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
      try {
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          const value = storage.getItem(key);

          const keyMatch = secretPatterns.some(p => p.test(key));
          const valueIsJWT = jwtPattern.test(value || '');
          const valueLooksSecret = (value || '').length > 20 && /^[A-Za-z0-9_\-+/=.]+$/.test(value || '');

          if (keyMatch || valueIsJWT) {
            suspicious.push({
              storageType,
              key,
              valuePreview: (value || '').substring(0, 100),
              isJWT: valueIsJWT,
              keyMatchedPattern: keyMatch,
            });
          }
        }
      } catch {}
    }

    if (suspicious.length > 0) {
      send({ type: 'storage-secrets', items: suspicious, url: location.href });
    }
  }

  // ─── 3. Framework state extraction ────────────────────────────────

  function scanFrameworkState() {
    const results = [];

    // Next.js
    if (window.__NEXT_DATA__) {
      results.push({
        framework: 'Next.js',
        dataPreview: safeStringify(window.__NEXT_DATA__),
        hasProps: !!window.__NEXT_DATA__?.props,
        keys: Object.keys(window.__NEXT_DATA__),
      });
    }

    // Nuxt.js
    if (window.__NUXT__) {
      results.push({
        framework: 'Nuxt.js',
        dataPreview: safeStringify(window.__NUXT__),
        keys: Object.keys(window.__NUXT__),
      });
    }

    // Angular
    if (window.ng) {
      results.push({ framework: 'Angular', detected: true });
    }

    // Redux DevTools state
    if (window.__REDUX_DEVTOOLS_EXTENSION__) {
      results.push({ framework: 'Redux', devtoolsPresent: true });
    }

    if (results.length > 0) {
      send({ type: 'framework-state', frameworks: results, url: location.href });
    }
  }

  // ─── 4. Inline script scanning ────────────────────────────────────

  function scanInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');
    const secretPatterns = [
      { regex: /["'](?:api[_-]?key|apiKey)["']\s*[:=]\s*["']([^"']{8,})["']/gi, label: 'API key' },
      { regex: /["'](?:secret|password|token)["']\s*[:=]\s*["']([^"']{8,})["']/gi, label: 'Secret/password' },
      { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS key' },
      { regex: /mongodb(\+srv)?:\/\/[^\s"'<>]+/gi, label: 'MongoDB URI' },
    ];

    const findings = [];
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (text.length < 10) return;

      for (const pat of secretPatterns) {
        const matches = text.match(pat.regex);
        if (matches) {
          findings.push({
            scriptIndex: idx,
            pattern: pat.label,
            matchCount: matches.length,
            preview: matches[0].substring(0, 80),
          });
        }
      }
    });

    if (findings.length > 0) {
      send({ type: 'inline-script-secrets', findings, url: location.href });
    }
  }

  // ─── 5. Page-world event listeners ─────────────────────────────────
  // The actual hooks (fetch, XHR, WebSocket, eval, document.write, innerHTML)
  // live in page-world.js which is registered in manifest.json with
  // "world": "MAIN". This avoids CSP inline-script violations entirely.
  // We just listen for the CustomEvents it dispatches.

  function bindPageWorldListeners() {
    window.addEventListener('__r3d_sink', (e) => {
      send({ type: 'dangerous-sink', sink: e.detail, url: location.href });
    });
    window.addEventListener('__r3d_fetch', (e) => {
      send({ type: 'intercepted-fetch', detail: e.detail, url: location.href });
    });
    window.addEventListener('__r3d_xhr', (e) => {
      send({ type: 'intercepted-xhr', detail: e.detail, url: location.href });
    });
    window.addEventListener('__r3d_ws', (e) => {
      send({ type: 'websocket-activity', detail: e.detail, url: location.href });
    });

    window.addEventListener('__r3d_relay_request', (e) => {
      const detail = e.detail || {};
      const relayId = detail._relayId;
      if (!relayId) return;
      if (!_alive()) {
        window.dispatchEvent(new CustomEvent('__r3d_relay_response', {
          detail: { _relayId: relayId, error: 'Extension context invalidated — reload the extension' }
        }));
        return;
      }
      try {
        chrome.runtime.sendMessage(
          { type: 'r3d-proxy-relay', endpoint: detail.endpoint, body: detail.body },
          (response) => {
            window.dispatchEvent(new CustomEvent('__r3d_relay_response', {
              detail: { _relayId: relayId, ...(response || { error: 'No response from service worker' }) }
            }));
          }
        );
      } catch (err) {
        window.dispatchEvent(new CustomEvent('__r3d_relay_response', {
          detail: { _relayId: relayId, error: 'Extension context lost: ' + err.message }
        }));
      }
    });
  }

  // ─── 6b. CSP violation monitoring ──────────────────────────────────

  function monitorCSPViolations() {
    const NOISE_URIS = ['googleadservices.com', 'doubleclick.net', 'googlesyndication.com'];
    let count = 0;
    const MAX_VIOLATIONS = 50;
    document.addEventListener('securitypolicyviolation', (e) => {
      if (count++ >= MAX_VIOLATIONS) return;
      if (NOISE_URIS.some(d => (e.blockedURI || '').includes(d))) return;
      send({
        type: 'csp-violation',
        detail: {
          directive: e.violatedDirective,
          effectiveDirective: e.effectiveDirective,
          blockedURI: e.blockedURI,
          sourceFile: e.sourceFile,
          lineNumber: e.lineNumber,
          columnNumber: e.columnNumber,
          originalPolicy: (e.originalPolicy || '').substring(0, 500),
        },
        url: location.href,
      });
    });
  }

  // ─── 7. Prototype pollution detection (v3) ─────────────────────────

  function scanPrototypePollution() {
    const pollutionPatterns = ['__proto__', 'constructor', 'prototype'];

    try {
      const params = new URLSearchParams(location.search);
      for (const [key, value] of params) {
        for (const pat of pollutionPatterns) {
          if (key.includes(pat) || value.includes(pat)) {
            send({
              type: 'proto-pollution',
              detail: { param: key, value: value.substring(0, 200), source: 'url-param', pattern: pat },
              url: location.href,
            });
          }
        }
      }

      if (location.hash) {
        const hashContent = decodeURIComponent(location.hash.substring(1));
        for (const pat of pollutionPatterns) {
          if (hashContent.includes(pat)) {
            send({
              type: 'proto-pollution',
              detail: { param: '#fragment', value: hashContent.substring(0, 200), source: 'hash', pattern: pat },
              url: location.href,
            });
            break;
          }
        }
      }
    } catch {}

    // Runtime monitor lives in page-world.js; just bind the listener here
    window.addEventListener('__r3d_proto_pollution', (e) => {
      send({
        type: 'proto-pollution',
        detail: { param: e.detail.prop, value: e.detail.value, source: 'runtime' },
        url: location.href,
      });
    });
  }

  // ─── 8. Handle replay requests from the panel ─────────────────────

  try {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'r3d-replay') {
        const config = message.config;
        fetch(config.url, {
          method: config.method || 'GET',
          credentials: 'include',
        })
          .then(async (resp) => {
            const body = await resp.text();
            sendResponse({
              status: resp.status,
              bodyPreview: body.substring(0, 2000),
              bodySize: body.length,
              headers: Object.fromEntries(resp.headers.entries()),
            });
          })
          .catch((err) => {
            sendResponse({ status: -1, error: err.message });
          });
        return true;
      }
    });
  } catch {}

  // ─── Boot ─────────────────────────────────────────────────────────

  function init() {
    scanCookies();
    scanStorage();
    scanInlineScripts();
    scanPrototypePollution();
    bindPageWorldListeners();
    monitorCSPViolations();

    setTimeout(scanFrameworkState, 2000);
    setTimeout(scanFrameworkState, 5000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
