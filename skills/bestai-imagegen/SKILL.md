---
name: bestai-imagegen
description: "Generate or edit raster images (photos, illustrations, concept art, product/UI mockups, logos, textures, hero images) through api.bestai.codes. Use whenever the user asks to create, generate, or edit an image and the built-in image tool is unavailable or not working (e.g. Codex under a custom API-key provider withholds its image_gen tool). Shells out to a bundled dependency-free Python script that calls bestai's Responses image_generation tool directly. Works in both Codex and Claude Code."
---

# bestai-imagegen

Generate images through **api.bestai.codes** by running the bundled Python script
(standard library only — no `pip install`), which POSTs to `/v1/responses` with
`tools:[{"type":"image_generation"}]`. Upstream generates and returns a PNG. This
bypasses clients (e.g. Codex on a custom apikey provider) that refuse to emit the
built-in image_gen tool.

## When to use
Any request to create or edit a bitmap image: photo, illustration, concept art,
product/UI mockup, logo exploration, texture, banner, hero image, etc.

## Credentials
Resolution order (first hit wins):
1. `--key` / `--base-url` flags.
2. **cc-switch current provider** (`~/.cc-switch/`, app_type `codex`) — if you use
   cc-switch with a bestai provider, this is automatic, no setup.
3. `BESTAI_API_KEY` / `OPENAI_API_KEY` environment variable.
4. Built-in default base_url.

If you do NOT use cc-switch, set your own bestai key once:
`export BESTAI_API_KEY=sk-...` (or `setx BESTAI_API_KEY "sk-..."` on Windows).
This skill bundles NO key — everyone uses their own. Never paste a key into chat.

## How to run
Run the bundled script with your shell/exec/Bash tool (path is relative to this
skill's own directory):

```bash
python "<this-skill-dir>/scripts/bestai_imagegen.py" \
  --prompt "<detailed prompt>" \
  --out "output/imagegen/<name>.png" \
  --size 1536x1024 --quality high
```

In Codex the skill dir is `%USERPROFILE%\.codex\skills\bestai-imagegen`; in Claude
Code it is `$HOME/.claude/skills/bestai-imagegen`. If `python` is missing, try
`py` or `python3`.

Options: `--prompt/-p` (required), `--out/-o`, `--model/-m` (default `gpt-5.5`),
`--size/-s`, `--quality/-q` (low|medium|high|auto), `--ccswitch-app`,
`--no-ccswitch`, `--proxy`, `--retries`, `-v`.

After it prints `OK  saved <path>`, display the PNG (view_image in Codex / Read in
Claude Code) and report the saved path. On failure it prints a clear error and
exits non-zero — relay it.

## Prompt guidance
Structure the prompt as: scene/backdrop → subject → details → constraints. Quote
exact in-image text verbatim. For edits, list invariants ("change only X; keep Y
unchanged"). Augment only when the user's prompt is generic.

## Notes
- Default model `gpt-5.5` (broadly available). `gpt-5.6-luna` is a beta model only
  some accounts are entitled to and can 404 "Model not found"; `--retries`
  (default 4) re-rolls the account.
- The script sends `User-Agent: curl/8.4.0` (Cloudflare 403s the default Python
  UA) and connects direct, ignoring stale `HTTP_PROXY` env. Use `--proxy` if you
  actually need one.
- `input` is sent as a message list (a bare string yields upstream 400).
- **Domain allowlist (safety)**: the script only sends credentials to `bestai.codes`
  and its subdomains; a base_url on any other host is rejected before the request.
  Add your own gateway host to `ALLOWED_DOMAINS` at the top of the script if needed.
