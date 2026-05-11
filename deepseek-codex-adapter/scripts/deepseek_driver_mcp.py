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
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
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
MAX_HARNESS_FILE_BYTES = 1_000_000
LOG_TAIL_BYTES = 20_000
ALLOWED_TEST_TEMPLATES = {
    "pytest": ["pytest"],
    "python -m pytest": ["python", "-m", "pytest"],
    "npm test": ["npm", "test"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("REPO_PATH", "/repo"))
    parser.add_argument("--repo-host-path", default=os.environ.get("REPO_HOST_PATH"))
    return parser.parse_args()


ARGS = parse_args()
REPO = Path(ARGS.repo).resolve()
REPO_HOST_PATH = Path(ARGS.repo_host_path).resolve() if ARGS.repo_host_path else REPO
ARTIFACT_ROOT = REPO / "artifacts" / "deepseek"
HARNESS_ROOT = ARTIFACT_ROOT / "harness"
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


def is_sensitive_rel(path: Path | str) -> bool:
    rel = Path(path)
    parts = set(rel.parts)
    lowered = str(rel).lower()
    return bool(parts & SENSITIVE_NAMES or any(word in lowered for word in SENSITIVE_WORDS))


def repo_host_path_for(path: Path) -> Path:
    resolved = path.resolve()
    rel = resolved.relative_to(REPO)
    return REPO_HOST_PATH / rel


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


def harness_dir(run_id: str | None) -> Path:
    return HARNESS_ROOT / validate_run_id(run_id, "harness-run")


def ensure_harness_workspace(run_id: str | None) -> tuple[str, Path]:
    value = validate_run_id(run_id, "harness-run")
    root = HARNESS_ROOT / value
    for name in ("inputs", "scripts", "outputs", "logs", "reports", "patches", "worktrees"):
        (root / name).mkdir(parents=True, exist_ok=True)
    manifest = root / "manifest.json"
    if not manifest.exists():
        write_json(
            manifest,
            {
                "run_id": value,
                "created_at_ms": now_ms(),
                "repo": str(REPO),
                "policy": {
                    "repo_mount": "read-only by default",
                    "artifact_mount": "read-write",
                    "no_privileged": True,
                    "no_host_root_mount": True,
                    "no_arbitrary_shell": True,
                    "no_docker_socket_forwarding": True,
                },
                "events": [],
            },
        )
    return value, root


def validate_workspace_rel_path(raw_path: str, *, must_exist: bool = False) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        raise ValueError(f"harness path must be relative: {raw_path}")
    if ".." in path.parts:
        raise ValueError(f"harness path escapes workspace: {raw_path}")
    if not path.parts:
        raise ValueError("harness path is empty")
    if is_sensitive_rel(path):
        raise ValueError(f"refusing sensitive harness path: {raw_path}")
    if must_exist:
        # Existence is checked after joining to a concrete workspace.
        pass
    return path


def workspace_path(root: Path, raw_path: str, *, must_exist: bool = False) -> Path:
    rel = validate_workspace_rel_path(raw_path, must_exist=must_exist)
    resolved = (root / rel).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"harness path escapes workspace: {raw_path}") from exc
    if must_exist and not resolved.exists():
        raise ValueError(f"harness path does not exist: {raw_path}")
    return resolved


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_harness_event(root: Path, event: dict[str, Any]) -> None:
    manifest = root / "manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
    events = payload.setdefault("events", [])
    event.setdefault("timestamp_ms", now_ms())
    events.append(event)
    write_json(manifest, payload)


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
    network_disabled: bool = False,
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
        network_disabled=network_disabled,
    )
    try:
        result = container.wait(timeout=timeout)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        return {
            "returncode": int(result.get("StatusCode", -1)),
            "stdout": logs[-LOG_TAIL_BYTES:],
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


def copy_ignore(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lowered = name.lower()
        if name in SENSITIVE_NAMES or any(word in lowered for word in SENSITIVE_WORDS):
            ignored.add(name)
        elif name in {"artifacts", "node_modules", "test-results", "__pycache__"}:
            ignored.add(name)
    return ignored


def run_local_command(cmd: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout[-LOG_TAIL_BYTES:],
            "stderr": proc.stderr[-LOG_TAIL_BYTES:],
            "duration_ms": int((time.time() - started) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": (exc.stdout or "")[-LOG_TAIL_BYTES:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-LOG_TAIL_BYTES:] if isinstance(exc.stderr, str) else "command timed out",
            "duration_ms": int((time.time() - started) * 1000),
        }


def markdown_report(root: Path, manifest: dict[str, Any]) -> str:
    lines = [
        f"# Harness Report: {manifest.get('run_id', root.name)}",
        "",
        f"- Repository: `{manifest.get('repo', REPO)}`",
        f"- Created at ms: `{manifest.get('created_at_ms', 'unknown')}`",
        "",
        "## Policy",
        "",
    ]
    for key, value in (manifest.get("policy") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Events", ""])
    for event in manifest.get("events", []):
        event_type = event.get("type", "event")
        status = event.get("status", "")
        lines.append(f"- `{event_type}` `{status}` at `{event.get('timestamp_ms', '')}`")
        for key in ("path", "image", "template", "returncode", "duration_ms", "sha256"):
            if key in event:
                lines.append(f"  - `{key}`: `{event[key]}`")
    lines.append("")
    return "\n".join(lines)


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
def harness_create_workspace(run_id: str) -> dict[str, Any]:
    """Create an artifact-only harness workspace for temporary DeepSeek code."""
    run_id, root = ensure_harness_workspace(run_id)
    append_harness_event(root, {"type": "create_workspace", "status": "ok"})
    return {
        "returncode": 0,
        "run_id": run_id,
        "workspace": str(root),
        "directories": ["inputs", "scripts", "outputs", "logs", "reports", "patches", "worktrees"],
        "manifest_path": str(root / "manifest.json"),
    }


@mcp.tool()
def harness_policy_check(
    run_id: str | None = None,
    repo_paths: list[str] | None = None,
    artifact_paths: list[str] | None = None,
    image: str | None = None,
    test_template: str | None = None,
) -> dict[str, Any]:
    """Check harness inputs against path, image, and command-template policy."""
    checks: list[dict[str, Any]] = []
    allowed = True

    for raw_path in repo_paths or []:
        try:
            validate_repo_path(raw_path, must_exist=False)
            checks.append({"kind": "repo_path", "value": raw_path, "allowed": True})
        except Exception as exc:
            allowed = False
            checks.append({"kind": "repo_path", "value": raw_path, "allowed": False, "reason": str(exc)})

    for raw_path in artifact_paths or []:
        try:
            validate_workspace_rel_path(raw_path, must_exist=False)
            checks.append({"kind": "artifact_path", "value": raw_path, "allowed": True})
        except Exception as exc:
            allowed = False
            checks.append({"kind": "artifact_path", "value": raw_path, "allowed": False, "reason": str(exc)})

    if image is not None:
        try:
            validate_image(image)
            checks.append({"kind": "image", "value": image, "allowed": True})
        except Exception as exc:
            allowed = False
            checks.append({"kind": "image", "value": image, "allowed": False, "reason": str(exc)})

    if test_template is not None:
        if test_template in ALLOWED_TEST_TEMPLATES:
            checks.append({"kind": "test_template", "value": test_template, "allowed": True})
        else:
            allowed = False
            checks.append(
                {
                    "kind": "test_template",
                    "value": test_template,
                    "allowed": False,
                    "reason": "unsupported test template",
                }
            )

    if run_id is not None:
        run_id, root = ensure_harness_workspace(run_id)
        append_harness_event(
            root,
            {
                "type": "policy_check",
                "status": "ok" if allowed else "failed",
                "allowed": allowed,
                "checks": checks,
            },
        )

    return {
        "returncode": 0 if allowed else 2,
        "allowed": allowed,
        "checks": checks,
        "allowed_test_templates": sorted(ALLOWED_TEST_TEMPLATES),
    }


@mcp.tool()
def harness_write_file(run_id: str, relative_path: str, content: str) -> dict[str, Any]:
    """Write a temporary harness file inside artifacts/deepseek/harness/<run-id> only."""
    run_id, root = ensure_harness_workspace(run_id)
    if len(content.encode("utf-8")) > MAX_HARNESS_FILE_BYTES:
        raise ValueError(f"harness file is too large: max {MAX_HARNESS_FILE_BYTES} bytes")
    target = workspace_path(root, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    digest = sha256_text(content)
    append_harness_event(
        root,
        {
            "type": "write_file",
            "status": "ok",
            "path": str(target.relative_to(root)),
            "bytes": len(content.encode("utf-8")),
            "sha256": digest,
        },
    )
    return {
        "returncode": 0,
        "run_id": run_id,
        "path": str(target),
        "relative_path": str(target.relative_to(root)),
        "bytes": len(content.encode("utf-8")),
        "sha256": digest,
    }


@mcp.tool()
def harness_run_temp_script(
    run_id: str,
    image: str,
    script_path: str,
    timeout: int = 600,
    network_disabled: bool = True,
) -> dict[str, Any]:
    """Run an artifact workspace Python script with repo read-only and artifacts read-write."""
    image = validate_image(image)
    run_id, root = ensure_harness_workspace(run_id)
    script = workspace_path(root, script_path, must_exist=True)
    if script.suffix != ".py":
        raise ValueError("only Python harness scripts are supported")
    timeout = max(1, min(int(timeout), 1200))
    artifact_host = repo_host_path_for(root)
    repo_host = REPO_HOST_PATH
    artifact_rel = script.relative_to(root)
    result = run_container(
        image,
        ["python", f"/artifact/{artifact_rel.as_posix()}"],
        timeout=timeout,
        volumes={
            str(repo_host): {"bind": "/repo", "mode": "ro"},
            str(artifact_host): {"bind": "/artifact", "mode": "rw"},
        },
        working_dir="/artifact",
        network_disabled=bool(network_disabled),
    )
    event = {
        "type": "run_temp_script",
        "status": "ok" if result["returncode"] == 0 else "failed",
        "path": str(artifact_rel),
        "image": image,
        "returncode": result["returncode"],
        "network_disabled": bool(network_disabled),
    }
    append_harness_event(root, event)
    log_path = root / "logs" / f"{script.stem}.log"
    log_path.write_text(result.get("stdout", "") + result.get("stderr", ""), encoding="utf-8")
    result.update({"run_id": run_id, "log_path": str(log_path), "script_sha256": sha256_file(script)})
    return result


@mcp.tool()
def harness_create_worktree(run_id: str, base_ref: str = "working-copy") -> dict[str, Any]:
    """Create an isolated sanitized repository copy under the harness workspace."""
    run_id, root = ensure_harness_workspace(run_id)
    if base_ref != "working-copy":
        raise ValueError("only base_ref='working-copy' is supported in this safe harness")
    target = root / "worktrees" / "repo"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(REPO, target, ignore=copy_ignore)
    append_harness_event(
        root,
        {
            "type": "create_worktree",
            "status": "ok",
            "path": str(target.relative_to(root)),
            "base_ref": base_ref,
        },
    )
    return {"returncode": 0, "run_id": run_id, "worktree_path": str(target), "base_ref": base_ref}


@mcp.tool()
def harness_apply_patch(run_id: str, patch_path: str, timeout: int = 120) -> dict[str, Any]:
    """Apply an artifact patch to the isolated harness worktree, never to the real repo."""
    run_id, root = ensure_harness_workspace(run_id)
    worktree = root / "worktrees" / "repo"
    if not worktree.exists():
        raise ValueError("missing isolated worktree; call harness_create_worktree first")
    patch_rel = validate_repo_path(patch_path, must_exist=True)
    patch_abs = REPO / patch_rel
    if not patch_abs.name.endswith((".diff", ".patch")):
        raise ValueError("patch_path must end with .diff or .patch")
    stored_patch = root / "patches" / patch_abs.name
    if patch_abs.resolve() != stored_patch.resolve():
        shutil.copy2(patch_abs, stored_patch)
    timeout = max(1, min(int(timeout), 600))
    check = run_local_command(["git", "apply", "--check", str(stored_patch)], cwd=worktree, timeout=timeout)
    applied = None
    if check["returncode"] == 0:
        applied = run_local_command(["git", "apply", str(stored_patch)], cwd=worktree, timeout=timeout)
    event = {
        "type": "apply_patch",
        "status": "ok" if applied and applied["returncode"] == 0 else "failed",
        "path": str(stored_patch.relative_to(root)),
        "returncode": check["returncode"] if not applied else applied["returncode"],
    }
    append_harness_event(root, event)
    return {
        "returncode": event["returncode"],
        "run_id": run_id,
        "worktree_path": str(worktree),
        "stored_patch": str(stored_patch),
        "check": check,
        "apply": applied,
    }


@mcp.tool()
def harness_run_repo_tests(
    run_id: str,
    image: str,
    test_template: str,
    timeout: int = 600,
    network_disabled: bool = True,
) -> dict[str, Any]:
    """Run an allow-listed test command template inside the isolated worktree."""
    image = validate_image(image)
    run_id, root = ensure_harness_workspace(run_id)
    worktree = root / "worktrees" / "repo"
    if not worktree.exists():
        raise ValueError("missing isolated worktree; call harness_create_worktree first")
    if test_template not in ALLOWED_TEST_TEMPLATES:
        raise ValueError(f"unsupported test_template: {test_template}")
    timeout = max(1, min(int(timeout), 1200))
    result = run_container(
        image,
        ALLOWED_TEST_TEMPLATES[test_template],
        timeout=timeout,
        volumes={str(repo_host_path_for(worktree)): {"bind": "/work", "mode": "rw"}},
        working_dir="/work",
        network_disabled=bool(network_disabled),
    )
    append_harness_event(
        root,
        {
            "type": "run_repo_tests",
            "status": "ok" if result["returncode"] == 0 else "failed",
            "image": image,
            "template": test_template,
            "returncode": result["returncode"],
            "network_disabled": bool(network_disabled),
        },
    )
    log_path = root / "logs" / f"tests-{test_template.replace(' ', '-')}.log"
    log_path.write_text(result.get("stdout", "") + result.get("stderr", ""), encoding="utf-8")
    result.update({"run_id": run_id, "log_path": str(log_path), "test_template": test_template})
    return result


@mcp.tool()
def harness_feedback_to_deepseek(
    run_id: str,
    failure_log: str,
    allow_paths: list[str],
    timeout: int = 180,
) -> dict[str, Any]:
    """Ask DeepSeek for a revised patch draft using a bounded failure summary and allow-listed files."""
    run_id, root = ensure_harness_workspace(run_id)
    if len(failure_log.encode("utf-8")) > MAX_HARNESS_FILE_BYTES:
        raise ValueError("failure_log is too large")
    task = (
        "基于允许文件和以下测试失败摘要，重新生成一个 unified diff 补丁草案。"
        "不要声称已经修改文件，不要读取其他文件。\n\n"
        f"测试失败摘要：\n{failure_log}"
    )
    result = run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=f"{run_id}-feedback",
        timeout=timeout,
        patch=True,
    )
    append_harness_event(
        root,
        {
            "type": "feedback_to_deepseek",
            "status": "ok" if result["returncode"] == 0 else "failed",
            "path": result.get("patch_path") or result.get("output_path"),
            "returncode": result["returncode"],
        },
    )
    return result


@mcp.tool()
def harness_collect_report(run_id: str) -> dict[str, Any]:
    """Collect harness manifest and write report.json/report.md."""
    run_id, root = ensure_harness_workspace(run_id)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = {
        "returncode": 0,
        "run_id": run_id,
        "workspace": str(root),
        "manifest": manifest,
        "files": sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()),
    }
    report_json = root / "reports" / "report.json"
    report_md = root / "reports" / "report.md"
    write_json(report_json, report)
    report_md.write_text(markdown_report(root, manifest), encoding="utf-8")
    append_harness_event(root, {"type": "collect_report", "status": "ok", "path": "reports/report.md"})
    return {
        "returncode": 0,
        "run_id": run_id,
        "report_json": str(report_json),
        "report_md": str(report_md),
        "workspace": str(root),
    }


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
