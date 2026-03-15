/**
 * Page-world hooks — runs in the MAIN world (same as the page's own JS).
 *
 * Hooks fetch, XHR, WebSocket, eval, document.write, innerHTML mutations,
 * and prototype-pollution attempts. Communicates back to the isolated-world
 * content script via CustomEvent dispatches on `window`.
 *
 * Registered in manifest.json with "world": "MAIN" so it bypasses CSP
 * restrictions that block inline <script> injection.
 */
(function () {
  'use strict';

  // ─── Dangerous-sink monitoring ──────────────────────────────────────

  const _r3dSinks = [];
  const MAX_SINKS = 50;

  function logSink(type, args) {
    if (_r3dSinks.length >= MAX_SINKS) return;
    const stack = new Error().stack || '';
    _r3dSinks.push({
      type,
      argPreview: String(args[0] || '').substring(0, 200),
      stack: stack.split('\n').slice(1, 4).join('\n'),
      ts: Date.now(),
    });
    window.dispatchEvent(new CustomEvent('__r3d_sink', {
      detail: { type, argPreview: String(args[0] || '').substring(0, 200) }
    }));
  }

  const origEval = window.eval;
  window.eval = function () {
    logSink('eval', arguments);
    return origEval.apply(this, arguments);
  };

  const origWrite = document.write;
  document.write = function () {
    logSink('document.write', arguments);
    return origWrite.apply(this, arguments);
  };

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) {
          const html = node.innerHTML || '';
          if (/<script|onerror|onload|javascript:/i.test(html)) {
            logSink('innerHTML(script-like)', [html.substring(0, 200)]);
          }
        }
      }
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  window.__r3dSinks = _r3dSinks;

  // ─── CSP-safe proxy relay ───────────────────────────────────────────
  // Test snippets call window.__r3d_proxy(endpoint, body) instead of
  // fetch(proxyUrl). The call dispatches a CustomEvent that the content
  // script (isolated world) picks up, forwards to the service worker
  // (which is NOT subject to page CSP), and returns the response.

  let _relaySeq = 0;
  window.__r3d_proxy = function(endpoint, body) {
    const id = '__r3d_relay_' + (++_relaySeq) + '_' + Date.now();
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

  // ─── Ad / tracking domain noise filter ─────────────────────────────

  const NOISE_DOMAINS = [
    'googleadservices.com',
    'doubleclick.net',
    'googlesyndication.com',
    'adservice.google.',
    'facebook.com/tr',
    'analytics.tiktok.com',
    'bat.bing.com',
  ];

  function isNoisyUrl(url) {
    return NOISE_DOMAINS.some(d => url.includes(d));
  }

  // ─── Fetch / XHR / WebSocket hooking ────────────────────────────────

  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = (typeof input === 'string') ? input : (input.url || '');
    if (isNoisyUrl(url)) return origFetch.apply(this, arguments);

    const method = (init && init.method) || 'GET';
    const startTs = Date.now();

    const promise = origFetch.apply(this, arguments);

    promise.then(response => {
      const cloned = response.clone();
      const contentType = cloned.headers.get('content-type') || '';

      if (contentType.includes('json') || contentType.includes('text')) {
        cloned.text().then(body => {
          window.dispatchEvent(new CustomEvent('__r3d_fetch', {
            detail: {
              url, method,
              status: cloned.status,
              contentType,
              bodyPreview: body.substring(0, 5000),
              bodySize: body.length,
              elapsed: Date.now() - startTs,
            }
          }));
        }).catch(() => {});
      }
    }).catch(() => {});

    return promise;
  };

  const origOpen = XMLHttpRequest.prototype.open;
  const origXhrSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this._r3d = { method, url, startTs: Date.now(), skip: isNoisyUrl(url) };
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function () {
    if (!this._r3d?.skip) {
      this.addEventListener('load', function () {
        const ct = this.getResponseHeader('content-type') || '';
        if (ct.includes('json') || ct.includes('text')) {
          let body = '';
          try {
            if (!this.responseType || this.responseType === 'text') {
              body = this.responseText;
            } else if (this.responseType === 'json') {
              body = JSON.stringify(this.response);
            } else {
              body = `[${this.responseType} data]`;
            }
          } catch (e) {
            body = '[Error reading response]';
          }

          window.dispatchEvent(new CustomEvent('__r3d_xhr', {
            detail: {
              url: this._r3d?.url || '',
              method: this._r3d?.method || '',
              status: this.status,
              contentType: ct,
              bodyPreview: (body || '').substring(0, 5000),
              bodySize: (body || '').length,
              elapsed: Date.now() - (this._r3d?.startTs || Date.now()),
            }
          }));
        }
      });
    }
    return origXhrSend.apply(this, arguments);
  };

  const OrigWebSocket = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = protocols ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    window.dispatchEvent(new CustomEvent('__r3d_ws', {
      detail: { event: 'connect', url: url, protocols: protocols || [], ts: Date.now() }
    }));
    ws.addEventListener('message', function (e) {
      const preview = typeof e.data === 'string' ? e.data.substring(0, 2000) : '[binary]';
      window.dispatchEvent(new CustomEvent('__r3d_ws', {
        detail: { event: 'message', url: url, direction: 'recv', preview: preview, size: (e.data && e.data.length) || 0, ts: Date.now() }
      }));
    });
    const origWsSend = ws.send.bind(ws);
    ws.send = function (data) {
      const preview = typeof data === 'string' ? data.substring(0, 2000) : '[binary]';
      window.dispatchEvent(new CustomEvent('__r3d_ws', {
        detail: { event: 'message', url: url, direction: 'send', preview: preview, size: (data && data.length) || 0, ts: Date.now() }
      }));
      return origWsSend(data);
    };
    ws.addEventListener('close', function (e) {
      window.dispatchEvent(new CustomEvent('__r3d_ws', {
        detail: { event: 'close', url: url, code: e.code, reason: e.reason, ts: Date.now() }
      }));
    });
    return ws;
  };
  window.WebSocket.prototype = OrigWebSocket.prototype;
  window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;
  window.WebSocket.OPEN = OrigWebSocket.OPEN;
  window.WebSocket.CLOSING = OrigWebSocket.CLOSING;
  window.WebSocket.CLOSED = OrigWebSocket.CLOSED;

  // ─── Prototype pollution runtime monitor ────────────────────────────

  try {
    let _flagged = false;
    const handler = {
      set(target, prop, value) {
        if (!_flagged && (prop === '__proto__' || prop === 'constructor')) {
          _flagged = true;
          window.dispatchEvent(new CustomEvent('__r3d_proto_pollution', {
            detail: { prop, value: String(value).substring(0, 100) }
          }));
        }
        target[prop] = value;
        return true;
      }
    };
  } catch (e) {}
})();
