#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import uuid
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

STORE = {}
STORE_LOCK = Lock()


def load_env_value(path, key):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == key:
                    v = v.strip()
                    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                        v = v[1:-1]
                    return v
    except FileNotFoundError:
        return None
    return None


def content_to_text(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text") or part.get("input_text") or part.get("output_text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


def normalize_input(input_value):
    if input_value is None:
        return []
    if isinstance(input_value, str):
        return [{"role": "user", "content": input_value}]
    if isinstance(input_value, dict):
        return [input_value]
    if isinstance(input_value, list):
        return input_value
    return [{"role": "user", "content": str(input_value)}]


def responses_input_to_messages(items):
    messages = []
    pending_tool_calls = []

    def flush_pending_tool_calls():
        nonlocal pending_tool_calls
        if not pending_tool_calls:
            return
        messages.append({"role": "assistant", "content": None, "tool_calls": pending_tool_calls})
        pending_tool_calls = []

    for item in normalize_input(items):
        if not isinstance(item, dict):
            flush_pending_tool_calls()
            messages.append({"role": "user", "content": str(item)})
            continue

        typ = item.get("type")
        if typ == "function_call_output":
            flush_pending_tool_calls()
            messages.append({
                "role": "tool",
                "tool_call_id": item.get("call_id") or item.get("id") or "call_unknown",
                "content": content_to_text(item.get("output")),
            })
            continue

        if typ == "function_call":
            name = item.get("name") or "tool"
            arguments = item.get("arguments") or "{}"
            call_id = item.get("call_id") or item.get("id") or "call_unknown"
            pending_tool_calls.append({
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            })
            continue

        flush_pending_tool_calls()
        role = item.get("role") or "user"
        if role == "developer":
            role = "system"
        messages.append({"role": role, "content": content_to_text(item.get("content"))})

    flush_pending_tool_calls()
    return messages


def responses_tools_to_chat_tools(tools):
    out = []
    for tool in tools or []:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            continue
        if "function" in tool:
            out.append(tool)
            continue
        name = tool.get("name")
        if not name:
            continue
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": tool.get("description", ""),
                "parameters": tool.get("parameters") or {"type": "object", "properties": {}},
            },
        })
    return out


def response_base(response_id, model, status="in_progress", output=None):
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": status,
        "model": model,
        "output": output or [],
        "parallel_tool_calls": True,
        "usage": None,
    }


def sse(handler, event, data):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    handler.wfile.write(f"event: {event}\n".encode("utf-8"))
    handler.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
    handler.wfile.flush()


class Handler(BaseHTTPRequestHandler):
    server_version = "DeepSeekResponsesProxy/0.2"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def deepseek_request(self, body, stream):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.server.deepseek_url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.server.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=300 if stream else 120)

    def do_GET(self):
        if self.path in ("/health", "/v1/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return
        if self.path.startswith("/v1/models") or self.path.startswith("/models"):
            body = {
                "models": [{
                    "slug": self.server.model_slug,
                    "display_name": self.server.model_slug,
                    "description": "DeepSeek through a local Responses API compatibility proxy.",
                    "default_reasoning_level": "high",
                    "supported_reasoning_levels": [
                        {"effort": "low", "description": "Faster responses"},
                        {"effort": "medium", "description": "Balanced responses"},
                        {"effort": "high", "description": "Deeper reasoning"},
                    ],
                    "shell_type": "shell_command",
                    "visibility": "list",
                    "supported_in_api": True,
                    "priority": 1000,
                    "model_messages": None,
                    "supports_reasoning_summaries": False,
                    "support_verbosity": False,
                    "apply_patch_tool_type": "freeform",
                    "supports_parallel_tool_calls": True,
                    "supports_search_tool": False,
                    "context_window": 1048576,
                    "max_context_window": 1048576,
                }],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body, ensure_ascii=False).encode("utf-8"))
            return
        self.send_error(404)

    def do_POST(self):
        if self.path not in ("/responses", "/v1/responses"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req_body = json.loads(self.rfile.read(length) or b"{}")
            self.handle_response(req_body)
        except Exception as exc:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8"))

    def handle_response(self, req_body):
        model = req_body.get("model") or self.server.model_slug
        response_id = "resp_" + uuid.uuid4().hex
        prev_id = req_body.get("previous_response_id")

        messages = []
        if req_body.get("instructions"):
            messages.append({"role": "system", "content": content_to_text(req_body.get("instructions"))})
        if prev_id:
            with STORE_LOCK:
                messages.extend(STORE.get(prev_id, []))
        messages.extend(responses_input_to_messages(req_body.get("input")))

        chat_body = {
            "model": model,
            "messages": messages,
            "stream": bool(req_body.get("stream", False)),
            "thinking": {"type": "disabled"},
        }
        tools = responses_tools_to_chat_tools(req_body.get("tools"))
        if tools:
            chat_body["tools"] = tools
            chat_body["tool_choice"] = "auto"
        if req_body.get("max_output_tokens"):
            chat_body["max_tokens"] = req_body.get("max_output_tokens")

        if chat_body["stream"]:
            self.stream_response(chat_body, response_id, model, messages)
        else:
            self.full_response(chat_body, response_id, model, messages)

    def full_response(self, chat_body, response_id, model, messages):
        chat_body["stream"] = False
        try:
            with self.deepseek_request(chat_body, False) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}") from exc

        msg = payload.get("choices", [{}])[0].get("message", {})
        output = []
        if msg.get("tool_calls"):
            assistant_msg = {"role": "assistant", "content": None, "tool_calls": msg.get("tool_calls")}
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function", {})
                output.append({
                    "id": "fc_" + uuid.uuid4().hex,
                    "type": "function_call",
                    "status": "completed",
                    "call_id": tc.get("id") or "call_" + uuid.uuid4().hex,
                    "name": fn.get("name") or "tool",
                    "arguments": fn.get("arguments") or "{}",
                })
        else:
            text = msg.get("content") or ""
            assistant_msg = {"role": "assistant", "content": text}
            output.append({
                "id": "msg_" + uuid.uuid4().hex,
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            })

        with STORE_LOCK:
            STORE[response_id] = messages + [assistant_msg]
        body = response_base(response_id, model, "completed", output)
        body["usage"] = payload.get("usage")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode("utf-8"))

    def stream_response(self, chat_body, response_id, model, messages):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        sse(self, "response.created", {"type": "response.created", "response": response_base(response_id, model)})
        msg_item_id = "msg_" + uuid.uuid4().hex
        text_started = False
        text_output_index = None
        text_buf = []
        tool_calls = {}
        output_items = []
        next_output_index = 0

        def allocate_output_index():
            nonlocal next_output_index
            output_index = next_output_index
            next_output_index += 1
            return output_index

        try:
            with self.deepseek_request(chat_body, True) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    if not data:
                        continue
                    chunk = json.loads(data)
                    choice = (chunk.get("choices") or [{}])[0]
                    delta = choice.get("delta") or {}

                    text_delta = delta.get("content")
                    if text_delta:
                        if not text_started:
                            text_started = True
                            text_output_index = allocate_output_index()
                            item = {"id": msg_item_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []}
                            sse(self, "response.output_item.added", {"type": "response.output_item.added", "output_index": text_output_index, "item": item})
                            sse(self, "response.content_part.added", {"type": "response.content_part.added", "item_id": msg_item_id, "output_index": text_output_index, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}})
                        text_buf.append(text_delta)
                        sse(self, "response.output_text.delta", {"type": "response.output_text.delta", "item_id": msg_item_id, "output_index": text_output_index, "content_index": 0, "delta": text_delta})

                    for tc in delta.get("tool_calls") or []:
                        idx = str(tc.get("index", 0))
                        if idx not in tool_calls:
                            tool_calls[idx] = {
                                "id": "fc_" + uuid.uuid4().hex,
                                "call_id": tc.get("id") or "call_" + uuid.uuid4().hex,
                                "name": "",
                                "arguments": [],
                                "output_index": allocate_output_index(),
                                "started": False,
                            }
                        rec = tool_calls[idx]
                        if tc.get("id"):
                            rec["call_id"] = tc.get("id")
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            rec["name"] = fn.get("name")
                        if not rec["started"] and rec["name"]:
                            rec["started"] = True
                            item = {"id": rec["id"], "type": "function_call", "status": "in_progress", "call_id": rec["call_id"], "name": rec["name"], "arguments": ""}
                            sse(self, "response.output_item.added", {"type": "response.output_item.added", "output_index": rec["output_index"], "item": item})
                        if fn.get("arguments"):
                            rec["arguments"].append(fn.get("arguments"))
                            sse(self, "response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "item_id": rec["id"], "output_index": rec["output_index"], "delta": fn.get("arguments")})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            print(f"DeepSeek HTTP {exc.code} during stream: {detail}", file=sys.stderr, flush=True)
            sse(self, "response.failed", {"type": "response.failed", "response": {**response_base(response_id, model, "failed"), "error": {"message": f"DeepSeek HTTP {exc.code}: {detail}"}}})
            return
        except Exception as exc:
            print(f"Proxy stream error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            try:
                sse(self, "response.failed", {"type": "response.failed", "response": {**response_base(response_id, model, "failed"), "error": {"message": f"Proxy stream error: {type(exc).__name__}"}}})
            except Exception:
                pass
            return

        if tool_calls:
            chat_tool_calls = []
            for rec in tool_calls.values():
                args = "".join(rec["arguments"]) or "{}"
                item = {"id": rec["id"], "type": "function_call", "status": "completed", "call_id": rec["call_id"], "name": rec["name"] or "tool", "arguments": args}
                sse(self, "response.function_call_arguments.done", {"type": "response.function_call_arguments.done", "item_id": rec["id"], "output_index": rec["output_index"], "arguments": args})
                sse(self, "response.output_item.done", {"type": "response.output_item.done", "output_index": rec["output_index"], "item": item})
                output_items.append(item)
                chat_tool_calls.append({"id": rec["call_id"], "type": "function", "function": {"name": item["name"], "arguments": args}})
            assistant_msg = {"role": "assistant", "content": None, "tool_calls": chat_tool_calls}
        else:
            text = "".join(text_buf)
            if not text_started:
                text_output_index = allocate_output_index()
                item = {"id": msg_item_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []}
                sse(self, "response.output_item.added", {"type": "response.output_item.added", "output_index": text_output_index, "item": item})
                sse(self, "response.content_part.added", {"type": "response.content_part.added", "item_id": msg_item_id, "output_index": text_output_index, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}})
            sse(self, "response.output_text.done", {"type": "response.output_text.done", "item_id": msg_item_id, "output_index": text_output_index, "content_index": 0, "text": text})
            part = {"type": "output_text", "text": text, "annotations": []}
            sse(self, "response.content_part.done", {"type": "response.content_part.done", "item_id": msg_item_id, "output_index": text_output_index, "content_index": 0, "part": part})
            item = {"id": msg_item_id, "type": "message", "status": "completed", "role": "assistant", "content": [part]}
            sse(self, "response.output_item.done", {"type": "response.output_item.done", "output_index": text_output_index, "item": item})
            output_items.append(item)
            assistant_msg = {"role": "assistant", "content": text}

        with STORE_LOCK:
            STORE[response_id] = messages + [assistant_msg]
        sse(self, "response.completed", {"type": "response.completed", "response": response_base(response_id, model, "completed", output_items)})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--env-key", default="DEEPSEEK_API_KEY")
    parser.add_argument("--model-slug", default="deepseek-v4-pro")
    parser.add_argument("--deepseek-url", default="https://api.deepseek.com/chat/completions")
    args = parser.parse_args()

    api_key = os.environ.get(args.env_key) or load_env_value(args.env_file, args.env_key)
    if not api_key:
        print(f"{args.env_key} is missing in environment and {args.env_file}", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.api_key = api_key
    server.model_slug = args.model_slug
    server.deepseek_url = args.deepseek_url
    print(f"DeepSeek Responses proxy listening on http://{args.host}:{args.port}/v1", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
