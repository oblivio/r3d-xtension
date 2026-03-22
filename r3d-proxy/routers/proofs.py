"""One-click proof pages — server-side fetch + rendered HTML proof artifacts."""

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from core.auth import verify_api_key
from core.replay import get_http_client
from core.vault import CredentialVault

router = APIRouter(prefix="/r3d", tags=["proofs"])

# ─── Constants ───────────────────────────────────────────────────────

_PROOF_CSS = """
body{margin:0;background:#0a0a0f;color:#c8c8d0;font-family:-apple-system,sans-serif;padding:24px}
h1{font-family:'SF Mono',monospace;color:#ff1744;font-size:18px;margin:0 0 6px}
.subtitle{color:#666680;font-size:12px;margin-bottom:24px}
.card{background:#0f0f1a;border:1px solid #1e1e32;border-radius:6px;padding:16px;margin-bottom:16px}
.card h2{font-size:13px;color:#00e5ff;margin:0 0 10px;font-family:'SF Mono',monospace}
.row{display:flex;gap:8px;align-items:baseline;padding:4px 0;border-bottom:1px solid #1e1e32;font-size:12px}
.row .k{color:#666680;min-width:160px;font-family:'SF Mono',monospace;font-size:11px}
.row .v{color:#e8e8f0;word-break:break-all}
.pass{color:#69f0ae;font-weight:700}.fail{color:#ff1744;font-weight:700}.warn{color:#ff9100;font-weight:700}
pre{background:#08081a;border:1px solid #1e1e32;border-radius:4px;padding:12px;font-size:11px;color:#c8c8d0;overflow-x:auto;white-space:pre-wrap;max-height:300px;overflow-y:auto}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:800;font-family:'SF Mono',monospace}
.verdict-vuln{background:rgba(255,23,68,.15);color:#ff1744;border:1px solid #ff1744}
.verdict-safe{background:rgba(105,240,174,.15);color:#69f0ae;border:1px solid #69f0ae}
.verdict-info{background:rgba(0,229,255,.1);color:#00e5ff;border:1px solid #00e5ff}
"""

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "Prevents SSL stripping attacks"),
    ("Content-Security-Policy", "CSP", "Prevents XSS and data injection"),
    ("X-Content-Type-Options", "X-CTO", "Prevents MIME sniffing"),
    ("X-Frame-Options", "XFO", "Prevents clickjacking"),
    ("Referrer-Policy", "Referrer", "Controls referrer leakage"),
    ("Permissions-Policy", "Permissions", "Restricts browser features"),
    ("X-XSS-Protection", "XSS-Prot", "Legacy XSS filter"),
    ("Cross-Origin-Opener-Policy", "COOP", "Isolates browsing context"),
    ("Cross-Origin-Resource-Policy", "CORP", "Restricts cross-origin reads"),
]

# ─── Endpoints ───────────────────────────────────────────────────────


@router.get("/prove", dependencies=[Depends(verify_api_key)])
async def prove(url: str, test: str = "headers", origin: str = "", request: Request = None):
    """One-click proof page — fetches a target URL server-side and renders proof.

    Credentials are decrypted on-demand from QE-encrypted storage.
    """
    target = url
    vault: CredentialVault = request.app.state.credential_vault
    merged = await vault.get_replay_headers(origin or "", {})

    try:
        async with get_http_client(timeout=12, follow_redirects=False) as c:
            resp = await c.get(target, headers=merged)
            resp_headers = dict(resp.headers)
            body_preview = resp.text[:3000]
    except Exception as exc:
        return HTMLResponse(f"<html><body style='background:#0a0a0f;color:#ff1744;padding:40px;font-family:monospace'>"
                           f"<h1>Connection Failed</h1><p>{exc}</p></body></html>")

    if test == "headers":
        rows = ""
        missing = 0
        for hdr, short, desc in SECURITY_HEADERS:
            val = resp_headers.get(hdr.lower(), "")
            if val:
                rows += f'<div class="row"><span class="k">{hdr}</span><span class="v pass">{val[:200]}</span></div>'
            else:
                missing += 1
                rows += f'<div class="row"><span class="k">{hdr}</span><span class="v fail">MISSING — {desc}</span></div>'

        verdict_cls = "verdict-vuln" if missing >= 3 else "verdict-safe" if missing == 0 else "verdict-info"
        verdict_txt = f"{missing} MISSING HEADERS" if missing else "ALL HEADERS PRESENT"
        return HTMLResponse(f"""<html><head><style>{_PROOF_CSS}</style></head><body>
            <h1>R3D — Security Header Proof</h1>
            <div class="subtitle">{target}</div>
            <div style="margin-bottom:16px"><span class="badge {verdict_cls}">{verdict_txt}</span> <span style="color:#666680;font-size:11px">HTTP {resp.status_code}</span></div>
            <div class="card"><h2>Security Headers</h2>{rows}</div>
            <div class="card"><h2>All Response Headers</h2>{''.join(f'<div class="row"><span class="k">{k}</span><span class="v">{v[:200]}</span></div>' for k,v in resp_headers.items())}</div>
            </body></html>""")

    elif test == "cors":
        evil = origin or "https://evil.attacker.com"
        async with get_http_client(timeout=10) as c:
            cors_resp = await c.get(target, headers={**merged, "Origin": evil})
        acao = cors_resp.headers.get("access-control-allow-origin", "")
        acac = cors_resp.headers.get("access-control-allow-credentials", "")
        reflects = acao == evil or acao == "*"
        with_creds = acac.lower() == "true"
        vuln = reflects and with_creds

        verdict_cls = "verdict-vuln" if vuln else "verdict-safe" if not reflects else "verdict-info"
        verdict_txt = "CORS MISCONFIGURATION — ORIGIN REFLECTED WITH CREDENTIALS" if vuln else "CORS REFLECTS ORIGIN (no credentials)" if reflects else "CORS PROPERLY RESTRICTED"
        return HTMLResponse(f"""<html><head><style>{_PROOF_CSS}</style></head><body>
            <h1>R3D — CORS Proof</h1>
            <div class="subtitle">{target}</div>
            <div style="margin-bottom:16px"><span class="badge {verdict_cls}">{verdict_txt}</span></div>
            <div class="card"><h2>Test: Origin = {evil}</h2>
            <div class="row"><span class="k">Access-Control-Allow-Origin</span><span class="v {'fail' if reflects else 'pass'}">{acao or '(not set)'}</span></div>
            <div class="row"><span class="k">Access-Control-Allow-Credentials</span><span class="v {'fail' if with_creds else 'pass'}">{acac or '(not set)'}</span></div>
            </div></body></html>""")

    elif test == "redirect":
        hops = []
        async with get_http_client(timeout=12, follow_redirects=True, max_redirects=10) as c:
            rr = await c.get(target, headers=merged)
            for r in rr.history:
                hops.append({"url": str(r.url), "status": r.status_code, "location": r.headers.get("location", "")})
            hops.append({"url": str(rr.url), "status": rr.status_code, "location": "(final)"})
        final_external = False
        try:
            orig_host = urlparse(target).hostname
            final_host = urlparse(str(rr.url)).hostname
            final_external = orig_host != final_host
        except Exception:
            pass

        verdict_cls = "verdict-vuln" if final_external else "verdict-safe"
        verdict_txt = f"OPEN REDIRECT — redirects to external domain ({urlparse(str(rr.url)).hostname})" if final_external else "NO OPEN REDIRECT — stays on same domain"
        hop_html = "".join(f'<div class="row"><span class="k">Hop {i+1} (HTTP {h["status"]})</span><span class="v">{h["url"]}</span></div>' for i, h in enumerate(hops))
        return HTMLResponse(f"""<html><head><style>{_PROOF_CSS}</style></head><body>
            <h1>R3D — Redirect Chain Proof</h1>
            <div class="subtitle">{target}</div>
            <div style="margin-bottom:16px"><span class="badge {verdict_cls}">{verdict_txt}</span></div>
            <div class="card"><h2>Redirect Chain ({len(hops)} hops)</h2>{hop_html}</div>
            </body></html>""")

    elif test == "response":
        return HTMLResponse(f"""<html><head><style>{_PROOF_CSS}</style></head><body>
            <h1>R3D — Response Proof</h1>
            <div class="subtitle">{target}</div>
            <div style="margin-bottom:16px"><span class="badge verdict-info">HTTP {resp.status_code}</span> <span style="font-size:11px;color:#666680">{resp_headers.get('content-type','')}</span></div>
            <div class="card"><h2>Response Headers</h2>{''.join(f'<div class="row"><span class="k">{k}</span><span class="v">{v[:200]}</span></div>' for k,v in resp_headers.items())}</div>
            <div class="card"><h2>Response Body (preview)</h2><pre>{body_preview}</pre></div>
            </body></html>""")

    else:
        return HTMLResponse(f"""<html><head><style>{_PROOF_CSS}</style></head><body>
            <h1>R3D — Proof</h1>
            <div class="subtitle">{target}</div>
            <div class="card"><h2>Response (HTTP {resp.status_code})</h2>
            {''.join(f'<div class="row"><span class="k">{k}</span><span class="v">{v[:200]}</span></div>' for k,v in resp_headers.items())}
            </div><div class="card"><h2>Body</h2><pre>{body_preview}</pre></div>
            </body></html>""")
