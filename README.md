# agent-skills

Portable skills for **Codex** and **Claude Code**, laid out one skill per
directory under `skills/`.

| Skill | What it does |
|-------|--------------|
| [`bestai-imagegen`](skills/bestai-imagegen/) | Generate/edit raster images through `api.bestai.codes` by calling the OpenAI Responses `image_generation` tool directly — the path that works even when a client (e.g. Codex on a custom API-key provider) refuses to emit the built-in image tool. Stdlib-only Python, no `pip install`. |

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
script refuses to send credentials to any host outside its `ALLOWED_DOMAINS`
allowlist (`bestai.codes` by default — add your own gateway host if you route
through a different one).

## Quick check

```bash
python skills/bestai-imagegen/scripts/bestai_imagegen.py \
  -p "a quiet morning campus, two students walking" \
  -o output/test.png -s 1536x1024 -q high
```

See each skill's own `SKILL.md` for full usage and notes. Licensed under
[MIT](LICENSE).
