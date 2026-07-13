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
# subdomains (e.g. api.bestai.codes). Guards against a mis-set / switched
# cc-switch base_url leaking the key to an untrusted host. Add your own hosts
# to this tuple if you route through a different gateway.
ALLOWED_DOMAINS = ("bestai.codes",)


def host_allowed(base_url):
    host = (urlparse(base_url).hostname or "").lower().rstrip(".")
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
    print("error: " + msg, file=sys.stderr)
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


def build_payload(prompt, model, size, quality):
    tool = {"type": "image_generation"}
    if size:
        tool["size"] = size
    if quality:
        tool["quality"] = quality
    return {
        "model": model,
        "stream": True,
        # NOTE: input MUST be a list — a bare string yields upstream 400
        # "Input must be a list" on the Codex backend.
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "tools": [tool],
    }


def make_opener(proxy):
    # Default: ignore ambient HTTP(S)_PROXY env (it may point at a dead proxy)
    # and connect directly. Pass --proxy to route through one explicitly.
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    else:
        handler = urllib.request.ProxyHandler({})
    return urllib.request.build_opener(handler)


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
            _collect_b64(evt, {"result", "partial_image_b64", "b64_json"}, images)
            etype = evt.get("type", "")
            if "output_text" in etype:
                d = evt.get("delta")
                if isinstance(d, str):
                    text_parts.append(d)
            if isinstance(evt.get("error"), dict):
                err = evt["error"]
    return images, "".join(text_parts), err


def save_png(b64, out_path):
    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    dirname = os.path.dirname(os.path.abspath(out_path))
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(raw)
    dims = ""
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", raw[16:24])
        dims = f" ({w}x{h})"
    return len(raw), dims


def main():
    ap = argparse.ArgumentParser(description="Generate an image via api.bestai.codes")
    ap.add_argument("--prompt", "-p", required=True, help="image prompt")
    ap.add_argument("--out", "-o", default="bestai_image.png", help="output PNG path")
    ap.add_argument("--model", "-m", default=DEFAULT_MODEL,
                    help=f"model (default {DEFAULT_MODEL}; gpt-5.6-luna may 404 on some accounts)")
    ap.add_argument("--size", "-s", default=None,
                    help="e.g. 1024x1024 / 1536x1024 / auto (default: auto)")
    ap.add_argument("--quality", "-q", default=None, choices=[None, "low", "medium", "high", "auto"])
    ap.add_argument("--base-url", default=None, help="override base_url (default: from cc-switch, else built-in)")
    ap.add_argument("--key", default=None, help="override API key (default: from cc-switch / env)")
    ap.add_argument("--ccswitch-app", default="codex", choices=["codex", "claude", "claude-desktop"],
                    help="which cc-switch current provider to borrow creds from (default codex)")
    ap.add_argument("--no-ccswitch", action="store_true", help="do not read creds from cc-switch")
    ap.add_argument("--retries", type=int, default=4, help="retries on 404/5xx (account lottery)")
    ap.add_argument("--proxy", default=None, help="route via proxy, e.g. http://127.0.0.1:7899 (default: direct)")
    ap.add_argument("--verbose", "-v", action="store_true", help="print SSE event types")
    args = ap.parse_args()

    opener = make_opener(args.proxy)

    # Credential resolution: explicit flags > cc-switch current provider > env > default
    cc_base, cc_key = (None, None)
    if not args.no_ccswitch:
        cc_base, cc_key = resolve_from_ccswitch(args.ccswitch_app)

    key = (args.key or cc_key
           or os.environ.get("BESTAI_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    if not key:
        _die("no API key — cc-switch had none; pass --key or set BESTAI_API_KEY / OPENAI_API_KEY")

    base_url = args.base_url or cc_base or DEFAULT_BASE
    src = "flag" if args.base_url else ("cc-switch" if cc_base else "default")
    key_src = "flag" if args.key else ("cc-switch" if cc_key else "env")

    # Security guard: never send the key to a host outside the allowlist.
    if not host_allowed(base_url):
        host = urlparse(base_url).hostname or "(none)"
        _die(f"base_url host '{host}' is not in the allowed domains "
             f"{', '.join(ALLOWED_DOMAINS)} (base source: {src}). "
             "Refusing to send credentials to an untrusted host.")

    payload = build_payload(args.prompt, args.model, args.size, args.quality)

    last_err = None
    for attempt in range(1, args.retries + 1):
        tag = f"[{attempt}/{args.retries}]"
        try:
            print(f"{tag} requesting {args.model} @ {base_url} "
                  f"(base:{src}, key:{key_src}) ...", file=sys.stderr)
            images, text, err = stream_once(opener, base_url, key, payload, args.verbose)
            if err:
                last_err = json.dumps(err, ensure_ascii=False)
                msg = str(err.get("message") or err.get("code") or err)
                if _retryable(msg):
                    print(f"{tag} retryable upstream error: {msg}", file=sys.stderr)
                    time.sleep(1.5)
                    continue
                _die("upstream error: " + msg)
            if not images:
                # Model returned text but never called the image tool.
                snippet = (text or "").strip()[:200]
                last_err = "no image returned; model text: " + snippet
                print(f"{tag} no image; retrying ...", file=sys.stderr)
                time.sleep(1.0)
                continue
            biggest = max(images, key=len)
            n, dims = save_png(biggest, args.out)
            print(f"OK  saved {args.out}{dims}  ({n} bytes)")
            return
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            last_err = f"HTTP {e.code}: {detail}"
            if _retryable(detail) or e.code >= 500 or e.code == 404:
                print(f"{tag} {last_err} — retrying ...", file=sys.stderr)
                time.sleep(1.5)
                continue
            _die(last_err)
        except urllib.error.URLError as e:
            last_err = "network error: " + str(e.reason)
            print(f"{tag} {last_err} — retrying ...", file=sys.stderr)
            time.sleep(2.0)
            continue

    _die("exhausted retries. last: " + str(last_err))


def _retryable(msg):
    m = (msg or "").lower()
    return any(s in m for s in ("model not found", "not found", "no available",
                                "upstream", "timeout", "temporarily"))


if __name__ == "__main__":
    main()
