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
}


def resolve_from_ccswitch(app_type="codex"):
    """Read (base_url, key) from cc-switch's current provider. Returns (None, None)
    if cc-switch is not present or nothing usable is found. Never raises."""
    settings_p = os.path.join(CCSWITCH_DIR, "settings.json")
    db_p = os.path.join(CCSWITCH_DIR, "cc-switch.db")
    if not (os.path.exists(settings_p) and os.path.exists(db_p)):
        return None, None
    try:
        with open(settings_p, encoding="utf-8") as f:
            settings = json.load(f)
        pid = settings.get(CCSWITCH_CURRENT_KEY.get(app_type, "currentProviderCodex"))
        if not pid:
            return None, None
        con = sqlite3.connect(f"file:{db_p}?mode=ro", uri=True)
        try:
            row = con.execute(
                "SELECT settings_config FROM providers WHERE id=?", (pid,)
            ).fetchone()
        finally:
            con.close()
        if not row:
            return None, None
        sc = json.loads(row[0])
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
        base = env.get("OPENAI_BASE_URL") or env.get("ANTHROPIC_BASE_URL")
        cfg = sc.get("config")
        if not base and isinstance(cfg, str):
            m = re.search(r'base_url\s*=\s*"([^"]+)"', cfg)
            if m:
                base = m.group(1)
        return base, key
    except Exception:
        return None, None


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


def resolve_antigravity_from_ccswitch():
    """Return (base_url, key) from the cc-switch provider whose base_url contains
    'antigravity'. Prefers the current Gemini provider (e.g. `antigravity-gemini`),
    then falls back to any matching provider. Never raises."""
    settings_p = os.path.join(CCSWITCH_DIR, "settings.json")
    db_p = os.path.join(CCSWITCH_DIR, "cc-switch.db")
    if not os.path.exists(db_p):
        return None, None
    try:
        con = sqlite3.connect(f"file:{db_p}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT id, settings_config FROM providers").fetchall()
        finally:
            con.close()
        by_id = {}
        for pid, scj in rows:
            try:
                by_id[pid] = json.loads(scj)
            except Exception:
                continue
        order = []
        try:
            st = json.load(open(settings_p, encoding="utf-8"))
            for k in ("currentProviderGemini", "currentProviderClaude"):
                if st.get(k) in by_id:
                    order.append(st[k])
        except Exception:
            pass
        order += [p for p in by_id if p not in order]
        for pid in order:
            base, key = _extract_base_key(by_id[pid])
            if base and "antigravity" in base.lower() and key:
                return base, key
        return None, None
    except Exception:
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
    if not args.no_ccswitch:
        cc_base, cc_key = resolve_antigravity_from_ccswitch()
    key = args.key or cc_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("BESTAI_API_KEY")
    base = args.base_url or cc_base
    if not base:
        _die("no antigravity base_url — cc-switch has no provider whose base_url "
             "contains 'antigravity'; pass --base-url (e.g. https://api.bestai.codes/antigravity)")
    if not key:
        _die("no API key for gemini/antigravity — pass --key or set GEMINI_API_KEY / BESTAI_API_KEY")
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

    # Credential resolution: explicit flags > cc-switch current provider > env > default
    cc_base, cc_key = (None, None)
    if not args.no_ccswitch:
        cc_base, cc_key = resolve_from_ccswitch(args.ccswitch_app)

    key = (args.key or cc_key
           or os.environ.get("BESTAI_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    if not key:
        _die("no API key — cc-switch had none; pass --key or set BESTAI_API_KEY / OPENAI_API_KEY")
    _SECRETS.append(key)

    base_url = args.base_url or cc_base or DEFAULT_BASE
    src = "flag" if args.base_url else ("cc-switch" if cc_base else "default")
    key_src = "flag" if args.key else ("cc-switch" if cc_key else "env")

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
