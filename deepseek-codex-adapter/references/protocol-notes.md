# Protocol Notes

## Why a Proxy Is Needed

Codex custom model providers can speak OpenAI Responses semantics. DeepSeek exposes Chat Completions style endpoints, so direct `base_url = "https://api.deepseek.com"` will fail when Codex calls `/v1/responses`.

## Required Behaviors

- Convert Responses `input` into Chat `messages`.
- Convert Responses function tools into Chat `tools`.
- Stream Responses-compatible SSE events back to Codex.
- Preserve assistant/tool-call history across continuation requests.
- Explicitly disable DeepSeek thinking mode unless full `reasoning_content` round-tripping is implemented.

## Tool Call Compatibility

Codex may continue a turn in two ways:

1. `previous_response_id` points to stored assistant history, and `input` contains new tool outputs.
2. `input` contains prior `function_call` items and `function_call_output` items directly.

For path 2, consecutive Responses `function_call` items must become one Chat assistant message:

```json
{
  "role": "assistant",
  "content": null,
  "tool_calls": [
    {"id": "call_1", "type": "function", "function": {"name": "shell", "arguments": "..."}},
    {"id": "call_2", "type": "function", "function": {"name": "shell", "arguments": "..."}}
  ]
}
```

Then each result must follow as a separate Chat tool message using the matching `tool_call_id`.

## Known Failure Modes

- DeepSeek 400: `reasoning_content` must be passed back
  - Cause: DeepSeek thinking mode was enabled during tool use.
  - Short-term fix: send `thinking: {"type": "disabled"}`.

- DeepSeek 400: assistant message with `tool_calls` must be followed by tool messages
  - Cause: parallel `function_call` items were expanded into multiple assistant messages or tool outputs did not match every call id.
  - Fix: merge consecutive function calls and preserve call ids.

- Codex `stream disconnected` retry loop
  - Cause: often a DeepSeek 400 wrapped inside a Responses stream, malformed SSE events, or invalid output indexes.
  - Fix: inspect proxy logs, then run a 60 second minimal reproduction before changing broader repo-analysis prompts.

## Minimum Validation Matrix

1. Direct non-stream `/v1/responses`: returns a short text.
2. Direct stream `/v1/responses`: emits `response.completed`.
3. Codex single tool call: one shell command then final text.
4. Codex multi-turn tool call: first shell result informs second shell call.
5. Codex same-turn parallel calls: three shell calls in one assistant turn.
6. Codex parallel failure recovery: one expected failed shell call, then a recovery shell call.
7. Bounded repository analysis: read only safe files and finish under the agreed timeout.
