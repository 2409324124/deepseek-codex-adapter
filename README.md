# DeepSeek Codex Adapter

Experimental Codex skill and local Responses-compatible proxy for using DeepSeek Chat models as a Codex model provider. It also includes a Dockerized MCP driver for the complementary workflow where Codex stays in control and DeepSeek performs bounded scan/patch tasks as a tool backend.

## What It Solves

Codex custom providers can use OpenAI Responses-style requests, while DeepSeek currently exposes Chat Completions style endpoints. Pointing Codex directly at DeepSeek fails because Codex calls `/v1/responses`, expects Responses streaming events, and uses Responses function-call objects for tool workflows.

This project provides a local adapter that:

- exposes a localhost `/v1/responses` endpoint for Codex
- converts Responses requests into DeepSeek Chat Completions requests
- converts DeepSeek output back into Responses-compatible streaming events
- supports Codex shell/tool calls, multi-turn continuation, and same-turn parallel tool calls
- disables DeepSeek thinking mode to avoid unsupported `reasoning_content` round-trips during tool use
- includes bounded smoke tests for real Codex agent workflows
- packages a narrow MCP driver for Docker image probes, allow-listed DeepSeek scan/patch artifacts, dynamic experiment harnesses, and isolated patch/test loops
- separates MCP scan, plan, validate, and apply paths: `deepseek_plan` is plan-only and rejects diff-shaped output at the server layer; `deepseek_patch(mode="diff")` creates candidate patches; `validate_patch` converts a candidate into `validated_patch_id` after mechanical checks; `harness_apply_patch` prefers validated patch ids

中文摘要：MCP driver 现在区分 scan / plan / patch / validate / apply。`deepseek_plan` 是 plan-only，服务端拒绝 diff；`deepseek_patch` 只生成候选补丁；`validate_patch` 机械校验后生成 `validated_patch_id`；`harness_apply_patch` 优先使用 validated patch id。

## How It Works

The request path is:

```text
Codex
  -> local /v1/responses proxy
  -> DeepSeek /chat/completions
  -> local Responses-style SSE stream
  -> Codex
```

The proxy handles the parts that simple URL forwarding does not:

- `instructions` become Chat `system` messages
- Responses `input` becomes Chat `messages`
- Responses function tools become Chat `tools`
- tool outputs become Chat `tool` messages
- parallel Responses `function_call` items are merged into one Chat assistant message with multiple `tool_calls`
- streaming function-call deltas keep stable Responses `output_index` values

## Difference From Common Relay Solutions

Generic API relays usually normalize URL paths, model names, and chat message payloads. That is enough for simple chat apps, but not enough for Codex agent workflows.

This adapter is Codex-specific:

- It implements `/v1/responses`, not only `/chat/completions`.
- It emits Responses-style SSE events.
- It reconstructs Codex function-call and tool-result history.
- It preserves call ids across parallel tool calls.
- It supports continuation through both `previous_response_id` and flat Responses `input` history.
- It includes validation prompts for single tool calls, multi-turn calls, same-turn parallel calls, failure recovery, and bounded repository analysis.

MCP is a different solution category: MCP can expose DeepSeek as a tool, but it does not make DeepSeek the Codex sampling model. This adapter targets the model-provider layer.

This repository includes both layers:

- `deepseek_responses_proxy.py`: makes DeepSeek usable behind Codex's Responses-style provider path.
- `deepseek_driver_mcp.py`: lets an OpenAI/Codex driver call DeepSeek through whitelist tools and saved artifacts.

The MCP driver does not expose arbitrary shell access. Its DeepSeek tools read only allow-listed non-sensitive files and call the local Responses proxy directly. DeepSeek output is redacted before artifact persistence under `artifacts/deepseek/<run-id>/`.

Plan, patch, validation, and apply outputs are separated:

- plan-mode output that contains unified diff markers is rejected with `PLAN_CONTAINS_DIFF` and does not write `patch.diff`
- diff-mode output creates a candidate patch artifact and returns `candidate_patch_id`
- `validate_patch` runs `validate_patch_diff`, including secret-like text, forbidden-path, dangerous host-access, and `git apply --check` checks, before returning `validated_patch_id`
- invalid candidate patches are marked rejected or quarantine and are not passed to `harness_apply_patch`
- `harness_apply_patch` prefers `validated_patch_id`; deprecated raw `patch_path` input is mechanically validated before isolated worktree apply

### MCP Patch Pipeline

```text
deepseek_patch(mode="diff")
  -> candidate_patch_id
  -> validate_patch(candidate_patch_id)
  -> validated_patch_id
  -> Codex driver review
  -> harness_apply_patch(validated_patch_id)
```

`validated_patch_id` is not a semantic safety guarantee. It only means the patch passed mechanical checks. Codex driver or user review remains required before applying, publishing, or merging any change.

For the Codex-driver/DeepSeek-worker flow, the MCP server also supports:

- artifact workspaces under `artifacts/deepseek/harness/<run-id>/`
- DeepSeek file generation with fenced-code extraction and versioned attempt copies
- temporary script execution in Docker with the repo mounted read-only
- structured static assertions for stdout markers, return codes, code snippets, and task-specific forbidden strings
- isolated sanitized repository copies for patch checking
- allow-listed test templates such as `python -m pytest`
- bounded failure feedback to DeepSeek for revised patch drafts
- JSON and Markdown reports for Codex review

Hosted LiteLLM-style gateways can be useful, but they broaden the trust boundary. This project defaults to a local Python standard-library proxy bound to `127.0.0.1`, so the DeepSeek API key stays on the user's machine.

## Status

Experimental. DeepSeek does not natively implement OpenAI Responses API, so this adapter should be validated with bounded Codex tests before real repository work.

Validated locally against:

- direct non-stream and stream `/v1/responses`
- single shell tool call
- multi-turn shell tool call
- same-turn parallel shell tool calls
- parallel call with one expected failure and a recovery call
- bounded read-only repository analysis excluding `.env`, `.key`, `.git`, `node_modules`, and test output folders
- Dockerized MCP protocol self-test with `tools/list`, PyTorch image probe, sensitive path rejection, `deepseek_scan`, and `deepseek_patch`
- LV4 harness smoke test: write an artifact Python script, run it in `cat-psych:cpu`, and write output under `artifacts/`
- LV5 harness smoke test: create an isolated worktree, apply a patch there, run `python -m pytest`, collect a report, and feed a bounded failure summary back to DeepSeek
- policy split smoke test: `tokenizer.py` is allowed with a soft `token` warning, while `.env` and `.key` remain hard rejections
- generated artifact smoke test: `deepseek_generate_artifact_file` extracts one Python code block, writes `latest` plus an attempt copy, runs it in Docker, and validates it with `harness_static_assertions`
- MCP output validation tests: plan diff-marker rejection, secret-like redaction, corrupt patch rejection, forbidden-path rejection, and `needs_host_access` non-escalation
- Dockerized MCP `tools/list` validation showing `deepseek_scan`, `deepseek_plan`, `deepseek_patch`, `validate_patch`, and `harness_apply_patch`
- E2E DeepSeek MCP validation through the local Responses proxy: `deepseek_plan` accepted a normal plan and did not write `patch.diff`; `deepseek_patch` produced a corrupt patch and was rejected with `PATCH_APPLY_CHECK_FAILED`; no patch was applied automatically
- MCP patch pipeline tests: candidate patch artifact creation, `validate_patch` success/failure paths, forbidden-path rejection, secret-like rejection, dangerous host-access rejection, and `harness_apply_patch(validated_patch_id)` behavior

`PLAN_CONTAINS_DIFF` is covered by local tests. The E2E run covered the normal plan path and the patch-validation rejection path.

Known Codex CLI boundary:

- Direct MCP protocol calls to the Dockerized server work.
- Non-interactive Codex MCP tool calls may require the user's Codex CLI approval/trust mode. In local Codex CLI 0.125.0 testing, `--dangerously-bypass-approvals-and-sandbox` could call MCP tools, while default `codex exec --sandbox read-only` returned `user cancelled MCP tool call`.
- Use the normal Codex/OpenAI driver for MCP orchestration. Do not use the DeepSeek profile as the outer driver for MCP tool testing.

## API Key

Put the DeepSeek key in a local `.env` file next to where you start the proxy:

```env
DEEPSEEK_API_KEY=your_deepseek_key
```

Then run:

```bash
python3 deepseek-codex-adapter/scripts/deepseek_responses_proxy.py --env-file .env
```

Alternatively, export the key in the shell:

```bash
export DEEPSEEK_API_KEY=your_deepseek_key
python3 deepseek-codex-adapter/scripts/deepseek_responses_proxy.py
```

Do not put API keys in Codex config, `SKILL.md`, GitHub, wrapper scripts, or systemd unit files.

## Repository Layout

```text
deepseek-codex-adapter/
├── SKILL.md
├── agents/openai.yaml
├── docker/mcp-driver.Dockerfile
├── scripts/
│   ├── deepseek_driver_mcp.py
│   └── deepseek_responses_proxy.py
└── references/
    ├── mcp-driver-workflow.md
    ├── protocol-notes.md
    ├── mechanism-and-comparison.md
    └── github-publish-checklist.md
tests/
├── test_mcp_output_validation.py
└── test_mcp_patch_pipeline.py
```

## Safety

Do not commit `.env`, `.key`, API keys, private keys, local systemd unit files with private paths, or project-specific wrapper scripts.

MCP patch validation is a mechanical gate, not a semantic security review. It checks format, secret-like content, forbidden paths, dangerous host-access patterns, and `git apply --check`. Codex driver or the user must still review any patch before applying or publishing it.

Run the publish checklist in `deepseek-codex-adapter/references/github-publish-checklist.md` before pushing.
