# Security

These skills run as agent-invoked CLI tools that handle **API credentials** and
**local files**, so their security boundary is worth stating explicitly. This
document covers `skills/bestai-imagegen`; other skills, when added, should append
their own section.

## Reporting

Found a vulnerability? Please **do not open a public issue**. Open a GitHub
[security advisory](https://github.com/loopwang2010/agent-skills/security/advisories/new)
on this repo, or contact the maintainer privately. Include a minimal
reproduction and the affected commit.

---

## bestai-imagegen

### Threat model

This tool is designed to be invoked **autonomously by an LLM agent** (Codex /
Claude Code), where the prompt, image paths, and output paths may be influenced
by content the agent is currently processing (a scraped page, a repo file, a
pasted message). It therefore defends against two distinct actors:

1. **A mis-set or switched credential source** — e.g. cc-switch's current
   provider points somewhere unexpected, so the key could be sent to the wrong
   host.
2. **A confused / prompt-injected agent** — induced to pass a sensitive file as
   `--image`, or an arbitrary path as `--out`.

It does **not** defend against a fully compromised local machine, a malicious
`--key` the user supplies deliberately, or a compromised *upstream account* on
the gateway itself (that is the gateway operator's responsibility).

### Credential handling

- The API key is resolved from (in order) `--key` → cc-switch's current provider
  (`~/.cc-switch/`) → `BESTAI_API_KEY` / `OPENAI_API_KEY` env → built-in default
  base_url. **No key is bundled in this repo** — every user brings their own.
- The key is **never** printed. Status lines show only its *source*
  (`key:cc-switch` / `key:env` / `key:flag`), never the value.
- Every emitted error/status string is passed through a redactor that scrubs the
  live key, so a malicious upstream that reflects request headers in an error
  body cannot get the key persisted into a terminal log or agent transcript.
- cc-switch's SQLite DB is opened **read-only** (`mode=ro`) and all queries are
  parameterized.

### Where credentials may be sent (allowlist + transport)

Credentials are only ever transmitted when **all** of these hold:

| Guard | Rule |
|-------|------|
| **Scheme** | `https://` only. An `http://` base_url is rejected before the request (no cleartext key on the wire). |
| **Host allowlist** | The host must equal, or be a subdomain of, one of `ALLOWED_DOMAINS` (`cccode.ai`, `favcodes.win`, `bestai.codes`, `unitoks.com`). Edit the tuple at the top of the script to change it. |
| **No redirects** | **All** HTTP 30x redirects are refused. urllib's default handler forwards the `Authorization` / `x-api-key` header to the `Location` target; a single 302 from a compromised or spoofed allowlisted host would otherwise exfiltrate the key past the allowlist (which only sees the initial URL). Authenticated API POSTs never legitimately redirect, so the tool hard-fails instead. |

The allowlist matcher is resistant to the usual bypass tricks — prefix
(`evilbestai.codes`), suffix (`bestai.codes.evil.com`), userinfo
(`bestai.codes@evil.com`), case, trailing dot, and port are all handled. This is
covered by the test suite's bypass matrix.

### Local-file safety

- **`--image` inputs are validated by content, not extension.** The file must
  actually begin with PNG / JPEG / WEBP magic bytes and be ≤ 20 MB; anything
  else is refused rather than uploaded. This blocks an agent from being tricked
  into base64-uploading a key file, `.env`, or the cc-switch DB relabeled as an
  "image".
- **`--out` will not overwrite an existing file** (or write through a symlink)
  unless `--force` is passed, and the check runs *before* any request — so a
  refusal never costs a paid generation. This limits an injected agent's ability
  to silently clobber a local file with image bytes.
- **`--n` (batch count) is capped at 16** and `--retries` must be ≥ 1, bounding
  runaway invocation.

### Residual risks / operator guidance

- **Prompt content is sent verbatim** to the upstream. Do not put secrets in
  prompts.
- **Pass `--out` paths inside the workspace** (e.g. `output/...`), never an
  absolute or `..`-containing path derived from untrusted content.
- **Do not let untrusted content dictate a `--image` path.** The magic-byte
  check stops *non-image* exfiltration, but a genuinely sensitive *image* (e.g.
  a screenshot containing secrets) would still be uploaded if its path is passed.
- The **allowlist assumes the listed hosts are trustworthy.** If you route
  through your own gateway, add only hosts you control.

### Verification

The behaviors above are enforced by a stdlib-only test suite
(`skills/bestai-imagegen/tests/`, `python -m unittest discover -s <dir>`),
including a **live redirect-guard test** that stands up a local attacker server
and asserts the `Authorization` header never reaches the redirect target.

### History

The current hardening (commit `c472d14`, refined in `1fb6fc1`) came out of an
adversarial two-reviewer pass. The redirect-based credential leak was
**empirically reproduced** against the exact urllib opener the script uses
before being fixed.
