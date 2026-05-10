# Mechanism and Comparison

## What This Adapter Does

This skill packages a local compatibility layer for using DeepSeek as a Codex model backend. Codex sends OpenAI Responses-style requests to a localhost `/v1/responses` endpoint. The local proxy translates those requests into DeepSeek Chat Completions calls, then translates DeepSeek responses back into the Responses event shape that Codex expects.

It is a protocol adapter, not a prompt wrapper. The hard part is preserving Codex agent semantics: streaming, function calls, tool-call results, parallel calls, and multi-turn continuation.

## Request Path

1. Codex is configured with a custom provider:
   - `wire_api = "responses"`
   - `base_url = "http://127.0.0.1:<port>/v1"`
2. Codex calls local `/v1/responses`.
3. The proxy converts:
   - Responses `instructions` into Chat `system` messages.
   - Responses `input` into Chat `messages`.
   - Responses function tools into Chat `tools`.
   - Responses `function_call_output` into Chat `tool` messages.
4. The proxy calls `https://api.deepseek.com/chat/completions`.
5. The proxy streams back Responses-compatible SSE events:
   - `response.created`
   - `response.output_item.added`
   - text or function-call deltas
   - `response.output_item.done`
   - `response.completed`

## Problems Solved

### 1. DeepSeek Has No Native Responses API

Codex custom model providers can request `/v1/responses`. DeepSeek exposes Chat Completions style endpoints. Directly pointing Codex at DeepSeek fails because the path and object model do not match.

The proxy supplies the missing Responses endpoint locally.

### 2. Thinking Mode Breaks Tool Turns

DeepSeek thinking mode can require `reasoning_content` to be passed back after tool calls. Codex does not provide a native DeepSeek-specific `reasoning_content` round-trip.

The proxy disables DeepSeek thinking mode with:

```json
{"thinking": {"type": "disabled"}}
```

This keeps Codex tool loops in normal Chat Completions mode.

### 3. Parallel Tool Calls Need Correct Message Reconstruction

Codex may send prior tool calls back as flat Responses `input` items:

```text
function_call
function_call
function_call
function_call_output
function_call_output
function_call_output
```

DeepSeek Chat requires these to become one assistant message with several `tool_calls`, followed by matching tool messages. If each `function_call` is turned into a separate assistant message, DeepSeek returns a 400 error because earlier assistant tool calls are not immediately followed by their tool result messages.

The proxy merges consecutive `function_call` items into one assistant `tool_calls` message.

### 4. Streaming Output Indexes Must Be Stable

Responses streaming events identify output items by `output_index`. For parallel function calls, each call needs a stable index across:

- `response.output_item.added`
- `response.function_call_arguments.delta`
- `response.function_call_arguments.done`
- `response.output_item.done`

The proxy allocates each output item an index when it first appears and reuses it for all related events.

### 5. Failures Need Minimal, Bounded Reproduction

Codex often reports protocol errors as `stream disconnected` reconnect loops. The proxy logs DeepSeek HTTP errors without printing secrets, and the skill recommends bounded tests to avoid long retry loops.

## Difference From Common Relay Solutions

### Generic API Relays

Typical relay projects forward an OpenAI-compatible request to another model provider. They are usually optimized for simple chat completion compatibility:

- normalize `model`
- rewrite URL/base path
- forward `messages`
- return a chat completion response

That is enough for many apps, but not enough for Codex agent workflows.

### This Adapter

This adapter targets Codex specifically:

- It exposes `/v1/responses`, not only `/chat/completions`.
- It emits Responses-style streaming SSE events.
- It handles Codex function-call output items.
- It preserves tool call ids.
- It supports same-turn parallel tool calls.
- It supports continuation both through `previous_response_id` and flat Responses `input` history.
- It intentionally disables DeepSeek thinking mode to avoid unsupported reasoning-content round-trips.
- It includes a validation matrix for real Codex agent behavior, not just a single chat prompt.

### MCP or Sub-Agent Setups

MCP can expose DeepSeek as a callable tool, but the active Codex model still does the planning and sampling. That is useful for consultation, not for replacing Codex's main model backend.

This adapter instead makes DeepSeek the model provider that Codex samples from.

### Hosted LiteLLM-Style Gateways

Hosted or containerized gateways can be useful, but they introduce a broader trust boundary: API keys enter another service, container image, or network path. This skill defaults to a local Python standard-library proxy bound to `127.0.0.1`, so the DeepSeek key stays on the user's machine.

## Current Boundaries

- Treat the skill as experimental because DeepSeek still does not natively implement Responses API.
- Keep thinking mode disabled unless full `reasoning_content` round-tripping is implemented and tested.
- Do not claim universal Codex compatibility until large-repository, long-horizon edit workflows are tested.
- Never publish local `.env`, `.key`, systemd unit paths, wrapper paths, or project-specific defaults.
