---
name: deepseek-codex-adapter
description: Set up, debug, and validate a local OpenAI Responses-compatible proxy that lets Codex use DeepSeek Chat/Completions models as a model provider. Use when the user wants to configure DeepSeek for Codex, adapt DeepSeek to Codex's Responses API expectations, diagnose stream reconnects during tool calls, run smoke tests for Codex agent workflows, or package the setup as a reusable local skill.
---

# DeepSeek Codex Adapter

## Core Workflow

1. Confirm the goal: local Codex model backend, not MCP and not a sub-agent. MCP can expose DeepSeek as a tool, but it cannot replace the Codex sampling model.
2. Keep secrets out of logs and artifacts. Do not print `.env`, `.key`, tokens, private keys, or API key values.
3. Use `scripts/deepseek_responses_proxy.py` as the local bridge from Codex Responses API requests to DeepSeek Chat Completions.
4. Configure Codex with a custom provider using `wire_api = "responses"` and `base_url = "http://127.0.0.1:<port>/v1"`.
5. Run smoke tests before declaring the backend usable:
   - simple `/v1/responses` request
   - single shell tool call
   - multi-turn shell tool call
   - same-turn parallel tool calls
   - same-turn parallel tool calls with one expected failure and a recovery turn
   - bounded repository analysis that excludes secrets
6. Put a timeout around every Codex validation command. Use `timeout 60s ...` unless the user asks for a different limit.

## Setup Pattern

Create or reuse a local env file containing `DEEPSEEK_API_KEY`, then start the proxy. The key belongs in the local `.env` file or shell environment, not in Codex config, GitHub, wrapper scripts, or systemd unit files.

```bash
python3 scripts/deepseek_responses_proxy.py --host 127.0.0.1 --port 4000 --env-file .env
```

Codex config pattern:

```toml
[profiles.deepseek]
model = "deepseek-v4-pro"
model_provider = "deepseek-local"

[model_providers.deepseek-local]
name = "DeepSeek local Responses proxy"
base_url = "http://127.0.0.1:4000/v1"
wire_api = "responses"
env_key = "DEEPSEEK_API_KEY"
```

Use a wrapper when convenient:

```bash
codex --profile deepseek "$@"
```

## Validation Commands

Use temporary or read-only workdirs for the first tests:

```bash
timeout 60s codex --profile deepseek exec -C /tmp/deepseek-codex-test --skip-git-repo-check --sandbox read-only "Run pwd, then summarize."
```

For repository-level testing, explicitly exclude sensitive paths:

```bash
timeout 60s codex --profile deepseek exec -C "$PWD" --sandbox read-only \
  "List files with rg --files while excluding .env, .key, .git, node_modules, test-results, token, secret, credential files. Read only package manifests and safe entrypoint snippets. Do not modify files."
```

## Failure Triage

- `reasoning_content must be passed back`: ensure the proxy sends `thinking: {"type": "disabled"}` to DeepSeek, or implement full reasoning-content round-tripping.
- `stream disconnected` after tool calls: inspect proxy logs for DeepSeek HTTP 400. Common causes are invalid tool message ordering, unmerged parallel function calls, or unstable Responses event indexes.
- Parallel tool call failures: verify consecutive Responses `function_call` input items are merged into one Chat assistant message with multiple `tool_calls`, followed by matching tool messages.
- Codex model list does not show the model: prefer invoking a named profile/wrapper; `/v1/models` mainly reduces refresh friction.

## Reference

Read `references/protocol-notes.md` when diagnosing protocol-level failures or changing the proxy.
Read `references/mechanism-and-comparison.md` when explaining how the adapter works, what problems it solves, and how it differs from generic API relay services.
Read `references/github-publish-checklist.md` before preparing a GitHub release or repository.
