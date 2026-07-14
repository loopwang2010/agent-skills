# agent-skills

Portable skills for **Codex** and **Claude Code**, laid out one skill per
directory under `skills/`.

| Skill | What it does |
|-------|--------------|
| [`bestai-imagegen`](skills/bestai-imagegen/) | Generate/edit raster images through `api.bestai.codes`. Two providers: **OpenAI** via the Responses `image_generation` tool (the path that works even when a client like Codex on a custom API-key provider refuses to emit the built-in image tool), and **Gemini** via the Antigravity `/v1/messages` path. Supports batch count, size/quality, model selection, and image editing. Stdlib-only Python, no `pip install`. |

## Install into Codex

The skill layout matches Codex's GitHub skill-installer. From a Codex session,
just say:

```
install skill from https://github.com/loopwang2010/agent-skills/tree/main/skills/bestai-imagegen
```

Or run the installer script directly:

```bash
python "$CODEX_HOME/skills/.system/skill-installer/scripts/install-skill-from-github.py" \
  --url https://github.com/loopwang2010/agent-skills/tree/main/skills/bestai-imagegen
```

(`$CODEX_HOME` defaults to `~/.codex`. The installer downloads the repo, verifies
`SKILL.md` exists, and copies the folder to `~/.codex/skills/bestai-imagegen`.)

## Install into Claude Code

Copy the skill folder into your skills directory:

```bash
git clone https://github.com/loopwang2010/agent-skills.git
cp -r agent-skills/skills/bestai-imagegen ~/.claude/skills/
```

## Credentials — bring your own

**No API key is bundled in this repo.** Each user supplies their own bestai key,
resolved in this order: `--key`/`--base-url` flags → cc-switch's current provider
(`~/.cc-switch/`) → `BESTAI_API_KEY` / `OPENAI_API_KEY` env → built-in default
base_url. If you don't use cc-switch, set the key once:

```bash
export BESTAI_API_KEY=sk-...        # macOS/Linux
setx BESTAI_API_KEY "sk-..."        # Windows
```

Never paste an API key into a chat or commit one to a repo. As a safety net the
script only sends credentials over **https** to hosts in its `ALLOWED_DOMAINS`
allowlist, and **refuses all HTTP redirects** (so a 302 can't forward the key
elsewhere). Edit the tuple at the top of
`skills/bestai-imagegen/scripts/bestai_imagegen.py` to match your own gateway
host(s).

## Providers & options

```bash
# OpenAI (default provider) — text -> image
python skills/bestai-imagegen/scripts/bestai_imagegen.py \
  -p "a quiet morning campus, two students walking" \
  -o output/test.png -s 1536x1024 -q high

# batch: N>1 saves out_1.png, out_2.png, ...
python skills/bestai-imagegen/scripts/bestai_imagegen.py -p "..." --n 4 -o hero.png

# edit an existing image (prompt = edit instruction; --image repeatable)
python skills/bestai-imagegen/scripts/bestai_imagegen.py \
  -p "change only the sky to a dramatic sunset; keep everything else" \
  -i source.png -o edited.png

# Gemini via Antigravity
python skills/bestai-imagegen/scripts/bestai_imagegen.py \
  --provider gemini -p "..." -m gemini-3-pro-image --size 2K -o g.png
```

| Flag | Meaning |
|------|---------|
| `--provider` | `openai` (default) or `gemini` (Antigravity `/v1/messages`) |
| `--n / --count N` | number of images; `N>1` writes `out_1.png, out_2.png, …` |
| `--size / -s` | openai: pixel dims (`1024x1024` / `1536x1024` / `2048x2048` / `auto`); gemini: `1K` / `2K` / `4K` (best-effort) |
| `--model / -m` | openai text model (default `gpt-5.5`); gemini image model (default `gemini-3-pro-image`) |
| `--quality / -q` | openai only: `low` / `medium` / `high` / `auto` |
| `--image / -i` | source image to edit (real png/jpg/webp, ≤ 20 MB); repeat for compositing/references |
| `--force` | required to overwrite an existing `--out` file (refused otherwise) |

See the skill's own [`SKILL.md`](skills/bestai-imagegen/SKILL.md) for full usage
and notes, and [`SECURITY.md`](SECURITY.md) for the credential/file security
boundary (allowlist, redirect guard, `--image`/`--out` hardening). Licensed under
[MIT](LICENSE).
