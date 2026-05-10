#!/usr/bin/env python3
"""Dockerized MCP driver for the DeepSeek-Codex workflow.

This server uses the official Python MCP SDK and exposes narrow tools instead
of arbitrary shell access. It is intended to run inside Docker with:
- /var/run/docker.sock mounted for Docker API access
- the repository mounted at /repo
- REPO_HOST_PATH set to the host path for bind mounts into sibling containers

DeepSeek scan/patch tools read only allow-listed repository files and call the
local Responses proxy directly. They do not start a nested Codex process.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
from typing import Any
import urllib.error
import urllib.request

import docker
from mcp.server.fastmcp import FastMCP


SENSITIVE_NAMES = {".env", ".key", ".git", "node_modules", "test-results", "__pycache__"}
SENSITIVE_WORDS = ("secret", "token", "credential", "private_key", "apikey", "api_key")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
DEFAULT_RESPONSES_BASE_URL = "http://127.0.0.1:4000/v1"
MAX_ALLOWED_FILES = 80
DEFAULT_MAX_FILE_BYTES = 120_000
DEFAULT_MAX_TOTAL_BYTES = 700_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("REPO_PATH", "/repo"))
    parser.add_argument("--repo-host-path", default=os.environ.get("REPO_HOST_PATH"))
    return parser.parse_args()


ARGS = parse_args()
REPO = Path(ARGS.repo).resolve()
REPO_HOST_PATH = Path(ARGS.repo_host_path).resolve() if ARGS.repo_host_path else REPO
mcp = FastMCP("deepseek-driver")


def validate_image(image: str) -> str:
    if not IMAGE_RE.fullmatch(image):
        raise ValueError(f"refusing invalid image name: {image}")
    return image


def validate_run_id(run_id: str | None, fallback: str) -> str:
    value = run_id or fallback
    if not RUN_ID_RE.fullmatch(value):
        raise ValueError("run_id may only contain letters, numbers, dot, underscore, and dash")
    return value


def validate_repo_path(raw_path: str, *, must_exist: bool = False) -> str:
    path = Path(raw_path)
    resolved = (REPO / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        rel = resolved.relative_to(REPO)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {raw_path}") from exc

    parts = set(rel.parts)
    lowered = str(rel).lower()
    if parts & SENSITIVE_NAMES or any(word in lowered for word in SENSITIVE_WORDS):
        raise ValueError(f"refusing sensitive path: {raw_path}")
    if must_exist and not resolved.exists():
        raise ValueError(f"path does not exist: {raw_path}")
    return str(rel)


def docker_client() -> docker.DockerClient:
    return docker.from_env()


def read_text_snippet(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def collect_allowed_context(
    allow_paths: list[str],
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> tuple[list[str], str]:
    validated = [validate_repo_path(path, must_exist=True) for path in allow_paths]
    chunks: list[str] = []
    included: list[str] = []
    total = 0

    candidates: list[Path] = []
    for rel in validated:
        root = REPO / rel
        if root.is_file():
            candidates.append(root)
        elif root.is_dir():
            for child in sorted(root.rglob("*")):
                if len(candidates) >= MAX_ALLOWED_FILES:
                    break
                if not child.is_file():
                    continue
                try:
                    validate_repo_path(str(child), must_exist=True)
                except ValueError:
                    continue
                candidates.append(child)
        else:
            raise ValueError(f"allowed path is neither file nor directory: {rel}")

    for path in candidates[:MAX_ALLOWED_FILES]:
        rel = str(path.relative_to(REPO))
        text = read_text_snippet(path, max_file_bytes)
        encoded_len = len(text.encode("utf-8", errors="replace"))
        if total + encoded_len > max_total_bytes:
            remaining = max_total_bytes - total
            if remaining <= 0:
                break
            text = text.encode("utf-8", errors="replace")[:remaining].decode("utf-8", errors="replace")
        total += len(text.encode("utf-8", errors="replace"))
        included.append(rel)
        chunks.append(f"\n\n--- FILE: {rel} ---\n{text}")
        if total >= max_total_bytes:
            break

    if not chunks:
        raise ValueError("no readable non-sensitive files found in allow_paths")
    return included, "".join(chunks)


def run_container(
    image: str,
    command: list[str],
    *,
    timeout: int,
    volumes: dict[str, dict[str, str]] | None = None,
    working_dir: str | None = None,
) -> dict[str, Any]:
    client = docker_client()
    container = client.containers.run(
        image,
        command,
        detach=True,
        stdout=True,
        stderr=True,
        remove=False,
        volumes=volumes,
        working_dir=working_dir,
    )
    try:
        result = container.wait(timeout=timeout)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        return {
            "returncode": int(result.get("StatusCode", -1)),
            "stdout": logs[-12000:],
            "stderr": "",
        }
    except Exception as exc:
        try:
            container.kill()
        except Exception:
            pass
        return {"returncode": 124, "stdout": "", "stderr": f"container timed out or failed: {exc}"}
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass


def deepseek_file_prompt(task: str, included_paths: list[str], file_context: str, *, patch: bool) -> str:
    allowed = "\n".join(f"- {path}" for path in included_paths)
    mode_rules = (
        "必须输出一个 unified diff 补丁草案，放在唯一一个 ```diff 代码块中。不要声称已经修改文件。"
        if patch
        else "用中文输出结构化扫描报告。"
    )
    return f"""你是 DeepSeek，正在 Codex MCP 驾驶工作流中执行受限文件分析。

允许使用的文件内容：
{allowed}

硬性规则：
- 只能基于下方提供的文件内容回答；不要假设你读取了仓库其他文件。
- 不要要求读取 .env、.key、.git、node_modules、test-results、token、secret、credential 或私钥相关文件。
- 不要输出 API key、token、私钥或凭据值。
- 不要声称你执行了命令、安装依赖、修改文件或提交代码。
- 如果信息不足，明确说明缺口，不要扩大范围。

任务：
{task}

输出要求：
- {mode_rules}
- 先给 5-8 条可直接放入 Codex 上下文的摘要。
- 再给必要细节、风险、建议测试或后续动作。

文件内容：
{file_context}
"""


def responses_proxy_url() -> str:
    base = os.environ.get("DEEPSEEK_RESPONSES_BASE_URL", DEFAULT_RESPONSES_BASE_URL).rstrip("/")
    return f"{base}/responses"


def extract_output_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in payload.get("output") or []:
        if item.get("type") == "message":
            for content in item.get("content") or []:
                text = content.get("text") or content.get("output_text")
                if isinstance(text, str):
                    parts.append(text)
        elif isinstance(item.get("content"), str):
            parts.append(item["content"])
    if parts:
        return "\n".join(parts)
    return json.dumps(payload, ensure_ascii=False, indent=2)


def call_responses_proxy(prompt: str, *, timeout: int, max_output_tokens: int = 8000) -> str:
    body = {
        "model": "deepseek-v4-pro",
        "input": prompt,
        "stream": False,
        "max_output_tokens": max_output_tokens,
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        responses_proxy_url(),
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Responses proxy HTTP {exc.code}: {detail}") from exc
    return extract_output_text(payload)


def extract_diff_block(text: str) -> str | None:
    match = re.search(r"```diff\s*(.*?)```", text, flags=re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    return None


def run_deepseek_file_workflow(
    *,
    task: str,
    allow_paths: list[str],
    run_id: str | None,
    timeout: int,
    patch: bool,
) -> dict[str, Any]:
    run_id = validate_run_id(run_id, "mcp-deepseek-patch" if patch else "mcp-deepseek-scan")
    timeout = max(1, min(int(timeout), 1200))
    included, file_context = collect_allowed_context(allow_paths)
    artifact_dir = REPO / "artifacts" / "deepseek" / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    prompt = deepseek_file_prompt(task, included, file_context, patch=patch)
    prompt_path = artifact_dir / "prompt.md"
    output_path = artifact_dir / "deepseek-output.md"
    prompt_path.write_text(prompt, encoding="utf-8")
    output = call_responses_proxy(prompt, timeout=timeout)
    output_path.write_text(output, encoding="utf-8")

    result: dict[str, Any] = {
        "returncode": 0,
        "stdout": output[-12000:],
        "stderr": "",
        "artifact_dir": str(artifact_dir),
        "prompt_path": str(prompt_path),
        "output_path": str(output_path),
        "included_paths": included,
    }
    if patch:
        diff = extract_diff_block(output)
        if diff:
            patch_path = artifact_dir / "patch.diff"
            patch_path.write_text(diff, encoding="utf-8")
            result["patch_path"] = str(patch_path)
        else:
            result["patch_path"] = None
            result["stderr"] = "no ```diff code block found in DeepSeek output"
    return result


@mcp.tool()
def docker_list_images(limit: int = 50) -> dict[str, Any]:
    """List local Docker images using the mounted host Docker socket."""
    limit = max(1, min(int(limit), 200))
    images = []
    for image in docker_client().images.list()[:limit]:
        tags = image.tags or ["<none>:<none>"]
        attrs = image.attrs or {}
        size = attrs.get("Size", 0)
        images.append({"tags": tags, "id": image.short_id, "size_bytes": size})
    return {"returncode": 0, "images": images}


@mcp.tool()
def docker_probe_torch(image: str, timeout: int = 120) -> dict[str, Any]:
    """Run a narrow PyTorch import/version probe in a Docker image."""
    image = validate_image(image)
    timeout = max(1, min(int(timeout), 600))
    return run_container(
        image,
        ["python", "-c", "import torch; print(torch.__version__)"],
        timeout=timeout,
    )


@mcp.tool()
def docker_run_python_script(image: str, script_path: str, timeout: int = 600) -> dict[str, Any]:
    """Run a repository Python script inside a Docker image.

    The script directory is mounted read-only into /work. This keeps the target
    container from writing into the repository or reading unrelated paths.
    """
    image = validate_image(image)
    script_rel = validate_repo_path(script_path, must_exist=True)
    timeout = max(1, min(int(timeout), 1200))
    script_abs = REPO / script_rel
    rel_dir = script_abs.parent.relative_to(REPO)
    host_mount_dir = REPO_HOST_PATH / rel_dir
    return run_container(
        image,
        ["python", script_abs.name],
        timeout=timeout,
        volumes={str(host_mount_dir): {"bind": "/work", "mode": "ro"}},
        working_dir="/work",
    )


@mcp.tool()
def deepseek_scan(
    task: str,
    allow_paths: list[str],
    run_id: str | None = None,
    timeout: int = 180,
    needs_host_access: bool = False,
) -> dict[str, Any]:
    """Read only allow-listed files, call the local Responses proxy, and save artifacts."""
    return run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=run_id,
        timeout=timeout,
        patch=False,
    )


@mcp.tool()
def deepseek_patch(
    task: str,
    allow_paths: list[str],
    run_id: str | None = None,
    timeout: int = 180,
    needs_host_access: bool = False,
) -> dict[str, Any]:
    """Read only allow-listed files, ask DeepSeek for a patch draft, and save artifacts."""
    return run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=run_id,
        timeout=timeout,
        patch=True,
    )


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
