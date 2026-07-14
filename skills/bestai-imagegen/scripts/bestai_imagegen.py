#!/usr/bin/env python3
"""
bestai_imagegen.py — Generate images through api.bestai.codes using the OpenAI
Responses built-in `image_generation` tool.

Why this exists
---------------
Codex (desktop/CLI), when pointed at a custom API-key provider, will NOT emit
the built-in `image_generation` tool in its /responses request (the
`AuthMode::ApiKey` gate in codex-rs). So its "Image Gen" skill can never reach
bestai. This script sends the tool directly, which is the path that has been
verified to work end-to-end (bestai -> OAuth Codex upstream -> gpt-image-2-codex
-> PNG).

Dependency-free: only the Python standard library. No `pip install` needed.

Credentials
-----------
By default the base_url and API key are read from cc-switch's currently-active
provider (no separate env var needed) — the same base_url/key your Codex uses:
  1) --base-url / --key flags (explicit override)
  2) cc-switch's current provider  (~/.cc-switch/, default app_type=codex)
  3) BESTAI_API_KEY / OPENAI_API_KEY env, BESTAI_BASE_URL env
  4) built-in default base_url

Usage
-----
  python bestai_imagegen.py --prompt "a quiet morning campus, two people walking"
  python bestai_imagegen.py -p "国风哪吒风火轮，金色描边" -o output/nezha.png -s 1536x1024 -q high
"""

import argparse
import base64
import json
import os
import re
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_BASE = os.environ.get("BESTAI_BASE_URL", "https://api.bestai.codes/v1")
DEFAULT_MODEL = "gpt-5.5"  # universally available; gpt-5.6-luna 404s on some accounts

# Hard allowlist: credentials are only ever sent to these domains and their
# subdomains (e.g. api.bestai.codes, relay01.favcodes.win). Guards against a
# mis-set / switched cc-switch base_url leaking the key to an untrusted host.
# Edit this tuple to change what is permitted.
ALLOWED_DOMAINS = ("cccode.ai", "favcodes.win", "bestai.codes", "unitoks.com")

MAX_IMAGE_BYTES = 20 * 1024 * 1024  # refuse larger --image inputs
MAX_BATCH = 16                      # --n upper bound (guards against runaway loops)

# Secrets registered here are scrubbed from every error/status line we print
# (defense-in-depth: a malicious upstream echoing request headers in an error
# body must not get the key persisted into terminal logs / agent transcripts).
_SECRETS = []


def _redact(text):
    for s in _SECRETS:
        if s:
            text = text.replace(s, "***")
    return text


def host_allowed(base_url):
    # https only: an http:// base would send the key in cleartext (and let any
    # on-path observer answer with a redirect). Checked before every request.
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    return bool(host) and any(
        host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS
    )

CCSWITCH_DIR = os.path.join(os.path.expanduser("~"), ".cc-switch")
CCSWITCH_CURRENT_KEY = {
    "codex": "currentProviderCodex",
    "claude": "currentProviderClaude",
    "claude-desktop": "currentProviderClaudeDesktop",
    "gemini": "currentProviderGemini",
}


def _ccswitch_rows(trace):
    """Load ALL cc-switch providers as rows: {app, id, name, sc, is_current}.

    Handles every storage generation cc-switch has shipped:
      * new:    ~/.cc-switch/cc-switch.db  (SQLite, providers table,
                PRIMARY KEY (id, app_type), is_current column)
      * older:  same db without the is_current column
      * legacy: ~/.cc-switch/config.json   (v2 per-app sections / v1 flat)
    Appends a human-readable reason to `trace` for every dead end, so the
    caller can tell the user WHY resolution failed instead of a silent miss.
    Never raises; returns [] when nothing is readable.
    """
    if not os.path.isdir(CCSWITCH_DIR):
        trace.append("~/.cc-switch 目录不存在(这台机器没装/没配 cc-switch?)")
        return []
    db_p = os.path.join(CCSWITCH_DIR, "cc-switch.db")
    if os.path.exists(db_p):
        try:
            con = sqlite3.connect(f"file:{db_p}?mode=ro", uri=True)
            try:
                try:
                    raw = con.execute(
                        "SELECT app_type, id, name, settings_config, is_current"
                        " FROM providers").fetchall()
                except sqlite3.OperationalError:  # old schema: no is_current
                    raw = [r + (0,) for r in con.execute(
                        "SELECT app_type, id, name, settings_config"
                        " FROM providers").fetchall()]
            finally:
                con.close()
            rows = []
            for app, pid, name, scj, cur in raw:
                try:
                    sc = json.loads(scj)
                except Exception:
                    continue
                if isinstance(sc, dict):
                    rows.append({"app": app, "id": pid, "name": name or pid,
                                 "sc": sc, "is_current": bool(cur)})
            if rows:
                return rows
            trace.append("cc-switch.db 里没有可读的 provider")
        except Exception as e:
            trace.append(f"cc-switch.db 读取失败({e.__class__.__name__})")
    else:
        trace.append("cc-switch.db 不存在")
    return _ccswitch_rows_legacy(trace)


def _ccswitch_rows_legacy(trace):
    """Legacy ~/.cc-switch/config.json (pre-SQLite cc-switch).
    v2: {"claude": {"providers": {id: {...,"settingsConfig": {...}}}, "current": id},
         "codex": {...}}   (possibly wrapped in an "apps" object)
    v1: {"providers": {...}, "current": id}   (claude only)"""
    cfg_p = os.path.join(CCSWITCH_DIR, "config.json")
    if not os.path.exists(cfg_p):
        trace.append("config.json(旧版布局)也不存在")
        return []
    try:
        with open(cfg_p, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        trace.append(f"config.json 解析失败({e.__class__.__name__})")
        return []
    if not isinstance(cfg, dict):
        trace.append("config.json 不是 JSON 对象")
        return []
    root = cfg.get("apps") if isinstance(cfg.get("apps"), dict) else cfg
    sections = {}
    for app in ("claude", "codex", "claude-desktop", "gemini"):
        sec = root.get(app)
        if isinstance(sec, dict) and isinstance(sec.get("providers"), dict):
            sections[app] = sec
    if not sections and isinstance(cfg.get("providers"), dict):
        sections["claude"] = cfg  # v1 flat layout predates multi-app
    rows = []
    for app, sec in sections.items():
        cur = sec.get("current")
        for pid, p in sec["providers"].items():
            if not isinstance(p, dict):
                continue
            sc = p.get("settingsConfig") or p.get("settings_config")
            if isinstance(sc, dict):
                rows.append({"app": app, "id": pid, "name": p.get("name") or pid,
                             "sc": sc, "is_current": pid == cur})
    if not rows:
        trace.append("config.json 里没有可读的 provider")
    return rows


def _ccswitch_current_of(rows, app):
    """The current provider row of one app: settings.json pointer first
    (matched WITH app_type — ids repeat across apps), then the row-level
    is_current flag (the DB-native marker; settings.json may lack the key)."""
    pid = None
    try:
        with open(os.path.join(CCSWITCH_DIR, "settings.json"), encoding="utf-8") as f:
            pid = json.load(f).get(CCSWITCH_CURRENT_KEY.get(app, ""))
    except Exception:
        pass
    if pid:
        for r in rows:
            if r["app"] == app and r["id"] == pid:
                return r
    for r in rows:
        if r["app"] == app and r["is_current"]:
            return r
    return None


def _openai_base_key_from_sc(sc):
    """(base, key, base_is_anthropic) for the /v1/responses path.
    base_is_anthropic marks a base taken from ANTHROPIC_BASE_URL — those are
    endpoint roots (https://api.bestai.codes) and need /v1 appended."""
    auth = sc.get("auth") or {}
    env = sc.get("env") or {}
    key = None
    for k in ("OPENAI_API_KEY", "API_KEY", "key", "ANTHROPIC_AUTH_TOKEN"):
        if auth.get(k):
            key = auth[k]
            break
    if not key:
        for k in ("OPENAI_API_KEY", "API_KEY", "ANTHROPIC_AUTH_TOKEN"):
            if env.get(k):
                key = env[k]
                break
    base = env.get("OPENAI_BASE_URL")
    base_is_anthropic = False
    if not base and env.get("ANTHROPIC_BASE_URL"):
        base = env["ANTHROPIC_BASE_URL"]
        base_is_anthropic = True
    cfg = sc.get("config")
    if not base and isinstance(cfg, str):
        m = re.search(r'base_url\s*=\s*"([^"]+)"', cfg)
        if m:
            base = m.group(1)
    return base, key, base_is_anthropic


def _ensure_v1_path(base):
    b = (base or "").rstrip("/")
    return b if (not b or b.endswith("/v1")) else b + "/v1"


def resolve_from_ccswitch(app_type="codex", trace=None):
    """Resolve (base_url, key, label) for the OpenAI path from cc-switch.

    1. Current provider of the requested app (lenient, original semantics:
       a key alone is fine — base falls back to the default later).
    2. Otherwise BORROW from other providers — current providers of the other
       apps first, then everything — but strictly: the candidate must have a
       key AND an https base on an allowlisted host (borrowed credentials
       never leave the allowlist), and antigravity bases are skipped (that is
       a different protocol path; use --provider gemini for it).

    Returns (None, None, None) when nothing usable; `trace` (optional list)
    collects the reasons so the final error can say why.
    """
    trace = trace if trace is not None else []
    rows = _ccswitch_rows(trace)
    if not rows:
        return None, None, None

    prim = _ccswitch_current_of(rows, app_type)
    if prim is not None:
        base, key, is_anth = _openai_base_key_from_sc(prim["sc"])
        if is_anth:
            base = _ensure_v1_path(base)
        if key or base:
            return base, key, f"cc-switch:{app_type}/{prim['name']}"
        trace.append(f"当前 {app_type} provider '{prim['name']}' 里没有 key/base_url")
    else:
        trace.append(f"没有当前 {app_type} provider(settings.json 指针和 is_current 都没有)")

    seen = {id(prim)} if prim is not None else set()
    ordered = []
    for app in ("codex", "claude", "claude-desktop"):
        r = _ccswitch_current_of(rows, app)
        if r is not None and id(r) not in seen:
            ordered.append(r)
            seen.add(id(r))
    ordered += [r for r in rows if id(r) not in seen]
    for r in ordered:
        base, key, is_anth = _openai_base_key_from_sc(r["sc"])
        if not (base and key):
            continue
        if "antigravity" in base.lower():
            continue  # anthropic-protocol path; wrong for /v1/responses
        if is_anth:
            base = _ensure_v1_path(base)
        if not host_allowed(base):
            continue  # never borrow creds bound for a non-allowlisted host
        return base, key, f"cc-switch:{r['app']}/{r['name']}"
    trace.append("没有任何 provider 同时有 key + 白名单内的 https base_url")
    return None, None, None


def _die(msg, code=1):
    print("error: " + _redact(msg), file=sys.stderr)
    sys.exit(code)


def _collect_b64(node, keys, out):
    """Recursively collect string values stored under any of `keys`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys and isinstance(v, str) and v:
                out.append(v)
            else:
                _collect_b64(v, keys, out)
    elif isinstance(node, list):
        for v in node:
            _collect_b64(v, keys, out)


def _sniff_image(raw):
    """Magic-byte detection — the content decides the MIME, never the extension."""
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return None


def _read_image_bytes(path):
    """Read + validate an --image input: must actually BE a png/jpeg/webp (by
    magic bytes) and under MAX_IMAGE_BYTES. Guards the agent-driven invocation
    path against being tricked into uploading a non-image (key file, config,
    database) as 'image' data. Returns (raw_bytes, mime)."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        _die(f"cannot read input image {path}: {e}")
    if size > MAX_IMAGE_BYTES:
        _die(f"input image too large: {path} ({size} bytes; limit {MAX_IMAGE_BYTES})")
    with open(path, "rb") as f:
        raw = f.read()
    mime = _sniff_image(raw)
    if not mime:
        _die(f"not a supported image (png/jpg/webp by content, not extension): {path}")
    return raw, mime


def _image_data_url(path):
    raw, mime = _read_image_bytes(path)
    return f"data:{mime};base64,{base64.b64encode(raw).decode()}"


def build_payload(prompt, model, size, quality, image_paths=None):
    tool = {"type": "image_generation"}
    if size:
        tool["size"] = size
    if quality:
        tool["quality"] = quality
    # content = the edit/generation instruction + any input images to edit from.
    # Passing input_image(s) turns this into an EDIT (classic /v1/images/edits is
    # down on bestai; the Responses tool edits via input_image on the same model).
    content = [{"type": "input_text", "text": prompt}]
    for p in image_paths or []:
        content.append({"type": "input_image", "image_url": _image_data_url(p)})
    return {
        "model": model,
        "stream": True,
        # NOTE: input MUST be a list — a bare string yields upstream 400
        # "Input must be a list" on the Codex backend.
        "input": [{"type": "message", "role": "user", "content": content}],
        "tools": [tool],
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse ALL redirects. urllib's default handler forwards Authorization /
    x-api-key headers to the Location target, so a single 302 from a
    compromised (or spoofed) allowlisted host would exfiltrate the key past
    the ALLOWED_DOMAINS check — which only ever sees the initial URL.
    Authenticated API POSTs never legitimately redirect (urllib would
    downgrade them to body-less GETs anyway), so hard-fail instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlparse(newurl).hostname or "?"
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"redirect to '{target}' blocked — refusing to forward credentials",
            headers, fp)


def make_opener(proxy):
    # Default: ignore ambient HTTP(S)_PROXY env (it may point at a dead proxy)
    # and connect directly. Pass --proxy to route through one explicitly.
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    else:
        handler = urllib.request.ProxyHandler({})
    return urllib.request.build_opener(handler, _NoRedirectHandler())


def stream_once(opener, base, key, payload, verbose):
    """One request. Returns (images:list[str b64], text:str, error:obj|None)."""
    url = base.rstrip("/") + "/responses"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            # Cloudflare in front of bestai 403s the default Python-urllib UA.
            "User-Agent": "curl/8.4.0",
        },
    )
    images, text_parts, err = [], [], None
    with opener.open(req, timeout=300) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("event:"):
                if verbose:
                    print("  " + line, file=sys.stderr)
                continue
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            try:
                evt = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(evt, dict):  # valid JSON but not an event object
                continue
            _collect_b64(evt, {"result", "partial_image_b64", "b64_json"}, images)
            etype = evt.get("type", "")
            if "output_text" in etype:
                d = evt.get("delta")
                if isinstance(d, str):
                    text_parts.append(d)
            if isinstance(evt.get("error"), dict):
                err = evt["error"]
    return images, "".join(text_parts), err


def _check_out(out_path, force):
    """Refuse to overwrite an existing file (or write through a symlink)
    unless --force. Called for every output path BEFORE any request is sent,
    so a refusal never wastes a paid generation."""
    if force:
        return
    if os.path.islink(out_path) or os.path.exists(out_path):
        _die(f"output already exists: {out_path} — pass --force to overwrite")


def save_png(b64, out_path):
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except ValueError:  # binascii.Error is a ValueError subclass
        _die("corrupt image data from upstream (invalid base64)")
    try:
        dirname = os.path.dirname(os.path.abspath(out_path))
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(raw)
    except OSError as e:
        _die(f"cannot write {out_path}: {e}")
    dims = ""
    if len(raw) >= 24 and raw[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", raw[16:24])
        dims = f" ({w}x{h})"
    return len(raw), dims


# ---------------------------------------------------------------------------
# Gemini via the Antigravity path. Credentials come from the cc-switch provider
# whose base_url contains "antigravity" (the `anti-bestai` provider:
# ANTHROPIC_BASE_URL=…/antigravity + ANTHROPIC_AUTH_TOKEN). Uses the Anthropic
# /v1/messages endpoint (x-api-key auth), NOT /v1beta generateContent — the
# Antigravity upstream account authenticates by api_key, and generateContent
# (ForwardGemini) requires OAuth and 401s. Verified end-to-end 2026-07-13.
# ---------------------------------------------------------------------------
GEMINI_DEFAULT_MODEL = "gemini-3-pro-image"  # alts: gemini-3.1-flash-image, gemini-2.5-flash-image


_ANTIGRAVITY_BASE_FIELDS = ("GOOGLE_GEMINI_BASE_URL", "ANTHROPIC_BASE_URL",
                            "OPENAI_BASE_URL", "GEMINI_BASE_URL")
_ANTIGRAVITY_KEY_FIELDS = ("GEMINI_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                           "OPENAI_API_KEY", "GOOGLE_API_KEY", "API_KEY")


def _extract_base_key(sc):
    merged = {**(sc.get("auth") or {}), **(sc.get("env") or {})}
    base = next((merged[f] for f in _ANTIGRAVITY_BASE_FIELDS if merged.get(f)), "")
    if not base and isinstance(sc.get("config"), str):
        m = re.search(r'base_url\s*=\s*"([^"]+)"', sc["config"])
        if m:
            base = m.group(1)
    key = next((merged[f] for f in _ANTIGRAVITY_KEY_FIELDS if merged.get(f)), None)
    return base, key


def resolve_antigravity_from_ccswitch(trace=None):
    """Return (base_url, key) from the cc-switch provider whose base_url contains
    'antigravity'. Prefers the current Gemini/Claude provider, then any matching
    provider. Same storage handling as resolve_from_ccswitch (new SQLite layout,
    old schema, legacy config.json). Never raises."""
    trace = trace if trace is not None else []
    rows = _ccswitch_rows(trace)
    if not rows:
        return None, None
    ordered, seen = [], set()
    for app in ("gemini", "claude"):
        r = _ccswitch_current_of(rows, app)
        if r is not None and id(r) not in seen:
            ordered.append(r)
            seen.add(id(r))
    ordered += [r for r in rows if id(r) not in seen]
    for r in ordered:
        base, key = _extract_base_key(r["sc"])
        if base and "antigravity" in base.lower() and key:
            return base, key
    trace.append("没有 base_url 含 'antigravity' 且带 key 的 provider")
    return None, None


def _collect_gemini_images(node, out):
    """Walk a Gemini response for inlineData/inline_data base64 image parts."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("inlineData", "inline_data") and isinstance(v, dict) and v.get("data"):
                out.append(v["data"])
            else:
                _collect_gemini_images(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_gemini_images(v, out)


def _collect_anthropic_images(node, out):
    """Walk an Anthropic Messages response for base64 image data (source.data),
    also handling Gemini inlineData passthrough."""
    if isinstance(node, dict):
        src = node.get("source")
        if isinstance(src, dict) and isinstance(src.get("data"), str) and len(src["data"]) > 100:
            out.append(src["data"])
        for k, v in node.items():
            if k in ("inlineData", "inline_data") and isinstance(v, dict) and v.get("data"):
                out.append(v["data"])
            elif k != "source":
                _collect_anthropic_images(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_anthropic_images(v, out)


def gemini_generate(opener, base, key, model, prompt, size, image_paths):
    """POST Antigravity /v1/messages (Anthropic format, upstream api_key auth).
    Returns (images:list[str b64], error:obj|None). Raises HTTPError/URLError.
    Uses the messages path — the Antigravity upstream account authenticates by
    api_key; the /v1beta generateContent path requires OAuth and 401s."""
    url = base.rstrip("/") + "/v1/messages"
    content = [{"type": "text", "text": prompt}]
    for p in image_paths or []:
        raw, mime = _read_image_bytes(p)
        content.append({"type": "image", "source": {
            "type": "base64", "media_type": mime,
            "data": base64.b64encode(raw).decode()}})
    body = {"model": model, "max_tokens": 8192,
            "messages": [{"role": "user", "content": content}]}
    sz = (size or "").upper()
    if sz in ("1K", "2K", "4K"):
        # best-effort: the messages upstream may ignore this and return model default
        body["generationConfig"] = {"imageConfig": {"imageSize": sz}}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json", "User-Agent": "curl/8.4.0"})
    with opener.open(req, timeout=300) as resp:
        body_bytes = resp.read()
    try:
        data = json.loads(body_bytes)
    except ValueError:
        # e.g. a Cloudflare challenge page served with HTTP 200 — surface as a
        # retryable upstream error instead of an uncaught JSONDecodeError.
        snippet = body_bytes.decode("utf-8", "replace")[:200]
        return [], {"message": "upstream returned non-JSON response: " + snippet}
    images = []
    _collect_anthropic_images(data, images)
    return images, data.get("error") if isinstance(data, dict) else None


def _indexed_out(out, i, n):
    """out.png -> out.png (n==1) or out_1.png, out_2.png, ... (n>1)."""
    if n <= 1:
        return out
    root, ext = os.path.splitext(out)
    return f"{root}_{i + 1}{ext or '.png'}"


def _retry_generate(gen_fn, retries, label):
    """gen_fn() -> (images:list[b64], err) or raises HTTPError/URLError.
    Returns the best b64 image, or _die on exhaustion."""
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            print(f"[{attempt}/{retries}] {label} ...", file=sys.stderr)
            images, err = gen_fn()
            if err:
                msg = str(err.get("message") or err.get("code") or err.get("status") or err)
                last_err = msg
                if _retryable(msg):
                    print(f"  retryable: {_redact(msg)}", file=sys.stderr)
                    time.sleep(1.5)
                    continue
                _die("upstream error: " + msg)
            if not images:
                last_err = "no image in response"
                print("  no image; retrying ...", file=sys.stderr)
                time.sleep(1.0)
                continue
            return max(images, key=len)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300] or str(e.reason)
            last_err = f"HTTP {e.code}: {detail}"
            if 300 <= e.code < 400:  # blocked redirect (see _NoRedirectHandler)
                _die(last_err)
            if _retryable(detail) or e.code >= 500 or e.code == 404:
                print(f"  {_redact(last_err)} — retrying ...", file=sys.stderr)
                time.sleep(1.5)
                continue
            _die(last_err)
        except urllib.error.URLError as e:
            last_err = "network error: " + str(e.reason)
            print(f"  {_redact(last_err)} — retrying ...", file=sys.stderr)
            time.sleep(2.0)
            continue
    _die("exhausted retries. last: " + str(last_err) +
         "\n(503 'No available accounts' => that provider's bestai account pool is down.)")


def run_gemini(args, opener):
    cc_base, cc_key = (None, None)
    cc_trace = []
    if not args.no_ccswitch:
        cc_base, cc_key = resolve_antigravity_from_ccswitch(cc_trace)
    key = args.key or cc_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("BESTAI_API_KEY")
    base = args.base_url or cc_base
    why = ("; ".join(cc_trace) if cc_trace
           else "cc-switch 已被 --no-ccswitch 关闭" if args.no_ccswitch
           else "cc-switch 没有 antigravity provider")
    if not base:
        _die("no antigravity base_url — " + why +
             " — pass --base-url (e.g. https://api.bestai.codes/antigravity)")
    if not key:
        _die("no API key for gemini/antigravity — " + why +
             " — pass --key or set GEMINI_API_KEY / BESTAI_API_KEY")
    _SECRETS.append(key)
    if not host_allowed(base):
        _die(f"base_url '{base}' is not allowed — must be https and the host "
             f"must be under: {', '.join(ALLOWED_DOMAINS)}. "
             "Refusing to send credentials to an untrusted destination.")
    model = args.model if args.model != DEFAULT_MODEL else GEMINI_DEFAULT_MODEL
    src = "flag" if args.base_url else ("cc-switch" if cc_base else "default")
    mode = "editing" if args.image else "generating"
    note = f" from {len(args.image)} image(s)" if args.image else ""
    n = args.n
    outs = [_indexed_out(args.out, i, n) for i in range(n)]
    for o in outs:  # fail before spending any generation on a refused path
        _check_out(o, args.force)
    for i, out_i in enumerate(outs):
        label = f"gemini/antigravity {mode}{note} #{i + 1}/{n}: {model} @ {base} (base:{src})"
        b64 = _retry_generate(
            lambda: gemini_generate(opener, base, key, model, args.prompt, args.size, args.image),
            args.retries, label)
        nb, dims = save_png(b64, out_i)
        print(f"OK  saved {out_i}{dims}  ({nb} bytes)")


def main():
    ap = argparse.ArgumentParser(description="Generate an image via api.bestai.codes")
    ap.add_argument("--prompt", "-p", required=True,
                    help="generation prompt, or edit instruction when --image is given")
    ap.add_argument("--image", "-i", action="append", default=None,
                    help="input image to EDIT/reference (png/jpg/webp); repeat for multiple")
    ap.add_argument("--provider", default="openai", choices=["openai", "gemini"],
                    help="openai = Responses image_generation (default); "
                         "gemini = Gemini image models via the Antigravity "
                         "/v1/messages path (or native via --base-url/--key)")
    ap.add_argument("--out", "-o", default="bestai_image.png", help="output PNG path")
    ap.add_argument("--model", "-m", default=DEFAULT_MODEL,
                    help=f"openai: text model driving the tool (default {DEFAULT_MODEL}); "
                         f"gemini: image model (default {GEMINI_DEFAULT_MODEL}; "
                         "alts gemini-3.1-flash-image, gemini-2.5-flash-image)")
    ap.add_argument("--size", "-s", default=None,
                    help="openai: pixel dims e.g. 1024x1024 / 1536x1024 / 2048x2048 / auto; "
                         "gemini: 1K / 2K / 4K (best-effort — upstream may return model default)")
    ap.add_argument("--n", "--count", type=int, default=1,
                    help=f"number of images to generate, 1-{MAX_BATCH} "
                         "(>1 saves out_1.png, out_2.png, ...)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite --out if it already exists (refused otherwise)")
    ap.add_argument("--quality", "-q", default=None, choices=[None, "low", "medium", "high", "auto"],
                    help="openai only: low|medium|high|auto")
    ap.add_argument("--base-url", default=None, help="override base_url (default: from cc-switch, else built-in)")
    ap.add_argument("--key", default=None, help="override API key (default: from cc-switch / env)")
    ap.add_argument("--ccswitch-app", default="codex", choices=["codex", "claude", "claude-desktop"],
                    help="which cc-switch current provider to borrow creds from (default codex)")
    ap.add_argument("--no-ccswitch", action="store_true", help="do not read creds from cc-switch")
    ap.add_argument("--retries", type=int, default=4, help="retries on 404/5xx (account lottery)")
    ap.add_argument("--proxy", default=None, help="route via proxy, e.g. http://127.0.0.1:7899 (default: direct)")
    ap.add_argument("--verbose", "-v", action="store_true", help="print SSE event types")
    args = ap.parse_args()

    # Validate bounds before touching credentials or the network.
    if not 1 <= args.n <= MAX_BATCH:
        _die(f"--n must be between 1 and {MAX_BATCH} (got {args.n})")
    if args.retries < 1:
        _die(f"--retries must be >= 1 (got {args.retries})")

    opener = make_opener(args.proxy)

    # Credential resolution: explicit flags > cc-switch (current provider of the
    # requested app, else borrowed from any provider with allowlisted creds)
    # > env > default
    cc_base, cc_key, cc_label = (None, None, None)
    cc_trace = []
    if not args.no_ccswitch:
        cc_base, cc_key, cc_label = resolve_from_ccswitch(args.ccswitch_app, cc_trace)

    key = (args.key or cc_key
           or os.environ.get("BESTAI_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    if not key:
        why = ("; ".join(cc_trace) if cc_trace
               else "cc-switch 已被 --no-ccswitch 关闭" if args.no_ccswitch
               else "cc-switch 里没找到可用的 key")
        _die("no API key — " + why +
             " — pass --key or set BESTAI_API_KEY / OPENAI_API_KEY")
    _SECRETS.append(key)

    base_url = args.base_url or cc_base or DEFAULT_BASE
    src = "flag" if args.base_url else (cc_label if cc_base else "default")
    key_src = "flag" if args.key else (cc_label if cc_key else "env")

    # Security guard: never send the key to a non-https or non-allowlisted URL.
    if not host_allowed(base_url):
        _die(f"base_url '{base_url}' is not allowed (source: {src}) — must be "
             f"https and the host must be under: {', '.join(ALLOWED_DOMAINS)}. "
             "Refusing to send credentials to an untrusted destination.")

    for p in args.image or []:
        if not os.path.isfile(p):
            _die(f"input image not found: {p}")

    if args.provider == "gemini":
        run_gemini(args, opener)
        return

    mode = "editing" if args.image else "generating"
    note = f" from {len(args.image)} image(s)" if args.image else ""
    payload = build_payload(args.prompt, args.model, args.size, args.quality, args.image)
    n = args.n
    outs = [_indexed_out(args.out, i, n) for i in range(n)]
    for o in outs:  # fail before spending any generation on a refused path
        _check_out(o, args.force)
    for i, out_i in enumerate(outs):
        label = f"{mode}{note} #{i + 1}/{n}: {args.model} @ {base_url} (base:{src}, key:{key_src})"
        # stream_once returns (images, text, err); [::2] -> (images, err)
        b64 = _retry_generate(
            lambda: stream_once(opener, base_url, key, payload, args.verbose)[::2],
            args.retries, label)
        nb, dims = save_png(b64, out_i)
        print(f"OK  saved {out_i}{dims}  ({nb} bytes)")


def _retryable(msg):
    m = (msg or "").lower()
    # Transient upstream conditions worth re-rolling the account / waiting on.
    # "concurrency limit"/"retry later"/"rate limit" are load-shedding signals
    # the gateway itself asks us to retry (observed live 2026-07-13).
    return any(s in m for s in ("model not found", "not found", "no available",
                                "upstream", "timeout", "temporarily",
                                "concurrency", "retry later", "rate limit",
                                "too many requests"))


if __name__ == "__main__":
    main()
