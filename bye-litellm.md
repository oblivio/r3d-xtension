# bye-litellm

On **March 24 2026**, litellm versions **1.82.7 and 1.82.8** were published to
PyPI with a malicious `.pth` payload that executes on every Python process
startup.  The malware harvests SSH keys, cloud credentials, `.env` files, and
Kubernetes secrets, exfiltrates them to `models.litellm.cloud`, and attempts
lateral movement into Kubernetes clusters.

Full write-up: <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>

We removed litellm entirely rather than pinning to a safe version because:

1. **The maintainer account appears compromised** — the GitHub issue was closed
   as "not planned" and flooded with bot spam, suggesting the attacker still
   had (or has) control.
2. **Our usage was narrow** — we only called `litellm.acompletion()` to route
   chat completions to three providers (Azure OpenAI, OpenAI, Gemini).
3. **The `openai` SDK covers all three** — Azure OpenAI and OpenAI are
   natively supported, and Google Gemini exposes an
   [OpenAI-compatible endpoint](https://ai.google.dev/gemini-api/docs/openai).
   One dependency replaces a 500+ transitive-dependency tree.

## What changed

| Before | After |
|--------|-------|
| `litellm>=1.0.0` in requirements.txt | `openai>=1.60.0` |
| `import litellm; litellm.acompletion(…)` | `from core.llm import acompletion` |
| `LITELLM_MODEL` env var | `R3D_MODEL` (falls back to `LITELLM_MODEL`) |
| Provider routing via litellm internals | ~60-line wrapper in `core/llm.py` |

## Provider routing

The model-string prefix convention is unchanged:

| Prefix | Provider | SDK client |
|--------|----------|------------|
| `azure/…` | Azure OpenAI | `AsyncAzureOpenAI` |
| `gemini/…` | Google Gemini | `AsyncOpenAI` with Gemini base URL |
| *(anything else)* | OpenAI | `AsyncOpenAI` |

The prefix is stripped before the model name is sent to the API (e.g.
`gemini/gemini-2.5-pro` → `gemini-2.5-pro`).

## Environment variables

Provider credentials are read from the same env vars as before:

- `AZURE_API_KEY`, `AZURE_API_BASE`, `AZURE_API_VERSION`
- `GEMINI_API_KEY`
- `OPENAI_API_KEY`

The model env var was renamed from `LITELLM_MODEL` to `R3D_MODEL`.  The old
name still works as a fallback so existing `.env` files don't break.

## If you were affected

If you installed or upgraded litellm on or after March 24 2026:

1. Check for version 1.82.7/1.82.8: `pip show litellm`
2. Look for `litellm_init.pth` in site-packages and `~/.cache/uv`
3. Check for persistence: `~/.config/sysmon/sysmon.py`,
   `~/.config/systemd/user/sysmon.service`
4. In Kubernetes: audit `kube-system` for `node-setup-*` pods
5. **Rotate all credentials** on any affected machine
