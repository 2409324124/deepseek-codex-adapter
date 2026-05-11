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
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request

import docker
from mcp.server.fastmcp import FastMCP


SENSITIVE_NAMES = {".env", ".key", ".git", "node_modules", "test-results", "__pycache__"}
HARD_SENSITIVE_WORDS = ("secret", "credential", "private_key", "apikey", "api_key")
SOFT_SENSITIVE_WORDS = ("token", "auth", "password", "session")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
PATCH_ID_RE = re.compile(r"^(candidate|validated)_\d{16,20}_[a-f0-9]{12}$")
POLICY_PROFILES = ("strict-secrets", "ml-code", "web-app")
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
LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "markdown": ".md",
    "text": ".txt",
}
PLAN_DIFF_MARKERS = (
    re.compile(r"^diff --git\b"),
    re.compile(r"^Index:\s+"),
    re.compile(r"^new file mode\s+"),
    re.compile(r"^deleted file mode\s+"),
    re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@"),
    re.compile(r"^\+\+\+\s+"),
    re.compile(r"^---\s+"),
)
SECRET_REDACTIONS = (
    (re.compile(r"sk-[A-Za-z0-9_-]{12,}"), "sk-[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL), "-----BEGIN [REDACTED] PRIVATE KEY-----"),
    (re.compile(r"\b(DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)\s*=\s*[^\s`'\"<>]+"), r"\1=[REDACTED]"),
    (re.compile(r"\b(token|api_key)\s*=\s*[^\s`'\"<>]+", re.IGNORECASE), lambda match: f"{match.group(1)}=[REDACTED]"),
)
PATCH_FORBIDDEN_PATHS = (
    ".env",
    ".key",
    ".git",
    "__pycache__",
    "artifacts",
    "security_review.md",
)
PATCH_FORBIDDEN_WORDS = (
    "secret",
    "credential",
    "private_key",
    "api_key",
)
PATCH_DANGEROUS_PATTERNS = (
    re.compile(r"\bneeds_host_access\b.*\b(privileged|cap_add|network_mode|volumes|mounts)\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\b(privileged|cap_add|network_mode|volumes|mounts)\b.*\bneeds_host_access\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bprivileged\s*=\s*True\b"),
    re.compile(r"\bcap_add\b"),
    re.compile(r"\bnetwork_mode\s*=\s*['\"]host['\"]"),
    re.compile(r"['\"]/:/"),
    re.compile(r"/var/run/docker\.sock"),
)


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
PATCH_ROOT = ARTIFACT_ROOT / "patches"
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


def validate_policy_profile(policy_profile: str | None) -> str:
    profile = policy_profile or "strict-secrets"
    if profile not in POLICY_PROFILES:
        raise ValueError(f"unsupported policy_profile: {profile}")
    return profile


def path_policy_findings(rel: Path | str, *, policy_profile: str | None = None) -> dict[str, Any]:
    profile = validate_policy_profile(policy_profile)
    path = Path(rel)
    parts = set(path.parts)
    lowered = str(path).lower()
    hard_hits = sorted((parts & SENSITIVE_NAMES) | {word for word in HARD_SENSITIVE_WORDS if word in lowered})
    soft_hits = sorted(word for word in SOFT_SENSITIVE_WORDS if word in lowered)
    allowed = not hard_hits
    if profile == "web-app" and any(word in lowered for word in ("password", "session")):
        allowed = False
        hard_hits = sorted(set(hard_hits) | {word for word in ("password", "session") if word in lowered})
        soft_hits = [word for word in soft_hits if word not in hard_hits]
    return {
        "allowed": allowed,
        "policy_profile": profile,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
    }


def validate_repo_path(raw_path: str, *, must_exist: bool = False) -> str:
    path = Path(raw_path)
    resolved = (REPO / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        rel = resolved.relative_to(REPO)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {raw_path}") from exc

    findings = path_policy_findings(rel)
    if not findings["allowed"]:
        raise ValueError(f"refusing sensitive path: {raw_path}")
    if must_exist and not resolved.exists():
        raise ValueError(f"path does not exist: {raw_path}")
    return str(rel)


def is_sensitive_rel(path: Path | str) -> bool:
    return not path_policy_findings(Path(path))["allowed"]


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


def make_patch_id(prefix: str, patch_text: str) -> str:
    if prefix not in {"candidate", "validated"}:
        raise ValueError("patch id prefix must be candidate or validated")
    digest = sha256_text(patch_text)[:12]
    return f"{prefix}_{time.time_ns()}_{digest}"


def patch_artifact_dir(patch_id: str) -> Path:
    if not PATCH_ID_RE.fullmatch(patch_id):
        raise ValueError("invalid patch_id")
    root = PATCH_ROOT.resolve()
    target = (PATCH_ROOT / patch_id).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("patch_id escapes patch artifact root") from exc
    return target


def write_patch_artifact(
    *,
    patch_id: str,
    patch_text: str,
    patch_kind: str,
    artifact_status: str,
    source_tool: str,
    run_id: str | None,
    redacted: bool = False,
    error_code: str | None = None,
    validation: dict[str, Any] | None = None,
    paths: list[str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    if patch_kind not in {"candidate", "validated"}:
        raise ValueError("patch_kind must be candidate or validated")
    if artifact_status not in {"candidate", "validated", "rejected", "quarantine"}:
        raise ValueError("unsupported artifact_status")
    if patch_kind == "candidate" and not patch_id.startswith("candidate_"):
        raise ValueError("candidate artifacts require candidate_ patch ids")
    if patch_kind == "validated" and not patch_id.startswith("validated_"):
        raise ValueError("validated artifacts require validated_ patch ids")

    target = patch_artifact_dir(patch_id)
    target.mkdir(parents=True, exist_ok=True)
    patch_path = target / "patch.diff"
    patch_path.write_text(patch_text, encoding="utf-8")
    metadata = {
        "patch_id": patch_id,
        "patch_kind": patch_kind,
        "artifact_status": artifact_status,
        "source_tool": source_tool,
        "run_id": run_id,
        "redacted": bool(redacted),
        "error_code": error_code,
        "validation": validation,
        "created_at_ms": now_ms(),
        "patch_sha256": sha256_text(patch_text),
        "paths": paths if paths is not None else patch_paths(patch_text),
        "warnings": warnings or [],
    }
    write_json(target / "metadata.json", metadata)
    return {
        "patch_id": patch_id,
        "patch_dir": str(target),
        "patch_path": str(patch_path),
        "metadata_path": str(target / "metadata.json"),
        "metadata": metadata,
    }


def load_patch_artifact(patch_id: str) -> dict[str, Any]:
    try:
        target = patch_artifact_dir(patch_id)
    except ValueError as exc:
        return {
            "ok": False,
            "returncode": 2,
            "error_code": "PATCH_ID_INVALID",
            "message": str(exc),
        }
    metadata_path = target / "metadata.json"
    patch_path = target / "patch.diff"
    if not metadata_path.exists() or not patch_path.exists():
        return {
            "ok": False,
            "returncode": 2,
            "error_code": "PATCH_ARTIFACT_NOT_FOUND",
            "message": f"patch artifact not found: {patch_id}",
        }
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "returncode": 2,
            "error_code": "PATCH_METADATA_INVALID",
            "message": str(exc),
        }
    return {
        "ok": True,
        "returncode": 0,
        "patch_id": patch_id,
        "patch_dir": str(target),
        "patch_path": str(patch_path),
        "metadata_path": str(metadata_path),
        "metadata": metadata,
        "patch_text": patch_path.read_text(encoding="utf-8", errors="replace"),
    }


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


def reserve_attempt(root: Path, label: str | None = None) -> tuple[int, str]:
    manifest = root / "manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
    key = label or "attempt"
    counters = payload.setdefault("attempt_counters", {})
    number = int(counters.get(key, 0)) + 1
    counters[key] = number
    write_json(manifest, payload)
    return number, f"{key}-{number:03d}"


def attempt_path(root: Path, directory: str, source_rel: Path, attempt_id: str) -> Path:
    suffix = "".join(source_rel.suffixes)
    stem = source_rel.name[: -len(suffix)] if suffix else source_rel.name
    if not stem:
        stem = "artifact"
    target_name = f"{stem}.{attempt_id}{suffix}"
    return root / directory / target_name


def docker_client() -> docker.DockerClient:
    # HIGH TRUST: this uses the host Docker daemon exposed by the MCP launcher.
    # Keep all Docker access behind narrow, allow-listed tools.
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


def redact_secret_like_text(text: str) -> tuple[str, bool]:
    redacted = text
    changed = False
    for pattern, replacement in SECRET_REDACTIONS:
        redacted, count = pattern.subn(replacement, redacted)
        changed = changed or count > 0
    return redacted, changed


def plan_diff_markers(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        for pattern in PLAN_DIFF_MARKERS:
            if pattern.search(stripped):
                findings.append({"line": lineno, "marker": stripped[:160]})
                break
    return findings


def validate_plan_output(text: str) -> dict[str, Any]:
    markers = plan_diff_markers(text)
    if markers:
        return {
            "ok": False,
            "error_code": "PLAN_CONTAINS_DIFF",
            "message": "Model output included unified diff markers in plan-only mode.",
            "markers": markers,
        }
    return {"ok": True, "error_code": None, "message": "plan output passed validation", "markers": []}


def patch_paths(diff: str) -> list[str]:
    paths: list[str] = []
    patterns = (
        re.compile(r"^diff --git a/(.*?) b/(.*?)$"),
        re.compile(r"^(?:---|\+\+\+) (?:a|b)/(.*?)$"),
    )
    for line in diff.splitlines():
        for pattern in patterns:
            match = pattern.match(line)
            if not match:
                continue
            values = match.groups()
            for value in values:
                if value != "/dev/null":
                    paths.append(value)
            break
    return sorted(set(paths))


def patch_forbidden_path_hits(paths: list[str]) -> list[str]:
    hits: list[str] = []
    for raw_path in paths:
        lowered = raw_path.lower()
        path = Path(raw_path)
        parts = set(path.parts)
        if parts & set(PATCH_FORBIDDEN_PATHS):
            hits.append(raw_path)
            continue
        if any(lowered.endswith(suffix) for suffix in (".key", ".pem", ".p12", ".pfx", ".pyc")):
            hits.append(raw_path)
            continue
        if any(word in lowered for word in PATCH_FORBIDDEN_WORDS):
            hits.append(raw_path)
    return sorted(set(hits))


def patch_dangerous_hits(diff: str) -> list[str]:
    hits: list[str] = []
    for pattern in PATCH_DANGEROUS_PATTERNS:
        match = pattern.search(diff)
        if match:
            hits.append(match.group(0)[:160])
    return hits


def validate_patch_diff(diff: str, *, cwd: Path | None = None, timeout: int = 120) -> dict[str, Any]:
    if not diff.strip() or "diff --git " not in diff:
        return {
            "ok": False,
            "error_code": "PATCH_INVALID_FORMAT",
            "message": "Patch is not a unified git diff.",
            "validated_patch_id": None,
        }

    redacted_diff, redacted = redact_secret_like_text(diff)
    if redacted:
        return {
            "ok": False,
            "error_code": "PATCH_CONTAINS_SECRET_LIKE_TEXT",
            "message": "Patch contains secret-like text and was rejected.",
            "validated_patch_id": None,
            "redacted": True,
        }

    paths = patch_paths(redacted_diff)
    forbidden_paths = patch_forbidden_path_hits(paths)
    if forbidden_paths:
        return {
            "ok": False,
            "error_code": "PATCH_TOUCHES_FORBIDDEN_PATH",
            "message": "Patch touches forbidden paths.",
            "validated_patch_id": None,
            "paths": forbidden_paths,
        }

    dangerous = patch_dangerous_hits(redacted_diff)
    if dangerous:
        return {
            "ok": False,
            "error_code": "PATCH_CONTAINS_DANGEROUS_HOST_ACCESS",
            "message": "Patch appears to add dangerous host access or permission logic.",
            "validated_patch_id": None,
            "hits": dangerous,
        }

    check_cwd = cwd or REPO
    with tempfile.TemporaryDirectory(prefix="deepseek-patch-check-") as temp_dir:
        temp_patch = Path(temp_dir) / "candidate.diff"
        temp_patch.write_text(redacted_diff, encoding="utf-8")
        check = run_local_command(
            ["git", "apply", "--check", str(temp_patch)],
            cwd=check_cwd,
            timeout=max(1, min(int(timeout), 600)),
        )
    if check["returncode"] != 0:
        return {
            "ok": False,
            "error_code": "PATCH_APPLY_CHECK_FAILED",
            "message": f"git apply --check failed: {check.get('stderr') or check.get('stdout')}",
            "validated_patch_id": None,
            "check": check,
        }
    return {
        "ok": True,
        "error_code": None,
        "message": "patch passed validation",
        "validated_patch_id": None,
        "patch_sha256": sha256_text(redacted_diff),
        "paths": paths,
        "check": check,
    }


def write_workflow_metadata(artifact_dir: Path, payload: dict[str, Any]) -> Path:
    metadata_path = artifact_dir / "metadata.json"
    write_json(metadata_path, payload)
    return metadata_path


def deepseek_file_prompt(
    task: str,
    included_paths: list[str],
    file_context: str,
    *,
    mode: str,
) -> str:
    allowed = "\n".join(f"- {path}" for path in included_paths)
    if mode == "diff":
        mode_rules = "必须输出一个 unified diff 补丁草案，放在唯一一个 ```diff 代码块中。不要声称已经修改文件。"
    elif mode == "plan":
        mode_rules = "只输出补丁计划，不要输出 unified diff，不要输出 ```diff 代码块，不要包含 diff marker。"
    else:
        mode_rules = "用中文输出结构化扫描报告。"
    return f"""你是 DeepSeek，正在 Codex MCP 驾驶工作流中执行受限文件分析。

允许使用的文件内容：
{allowed}

硬性规则：
- 只能基于下方提供的文件内容回答；不要假设你读取了仓库其他文件。
- 不要要求读取 .env、.key、.git、node_modules、test-results、secret、credential 或私钥相关文件。
- 不要输出 API key、访问令牌、私钥或凭据值。
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


def extract_fenced_code(text: str, language: str) -> tuple[str | None, list[dict[str, Any]]]:
    blocks: list[dict[str, Any]] = []
    pattern = re.compile(r"```([A-Za-z0-9_+.-]*)\s*\n(.*?)```", flags=re.DOTALL)
    wanted = language.lower().strip()
    aliases = {wanted}
    if wanted == "python":
        aliases.add("py")
    for match in pattern.finditer(text):
        label = (match.group(1) or "").strip().lower()
        code = match.group(2).strip() + "\n"
        blocks.append({"language": label, "code": code, "bytes": len(code.encode("utf-8"))})
    matching = [block for block in blocks if block["language"] in aliases]
    if len(matching) == 1:
        return matching[0]["code"], blocks
    if not matching and len(blocks) == 1 and wanted in ("text", "markdown"):
        return blocks[0]["code"], blocks
    return None, blocks


def deepseek_generate_file_prompt(
    task: str,
    included_paths: list[str],
    file_context: str,
    *,
    language: str,
) -> str:
    allowed = "\n".join(f"- {path}" for path in included_paths)
    return f"""你是 DeepSeek，正在 Codex MCP 监督型 harness 中生成一个 artifact 文件。

允许使用的文件内容：
{allowed}

硬性规则：
- 只能基于下方提供的文件内容和任务要求生成文件；不要假设你读取了其他文件。
- 不要要求读取 .env、.key、.git、node_modules、test-results、secret、credential 或私钥相关文件。
- 不要输出真实 API key、凭据、私钥或 secret 值。
- 不要声称你已经修改了仓库文件；你只是在输出候选 artifact 内容。
- 输出必须且只能包含一个 ```{language} fenced code block。
- code block 外不要写解释、摘要、清单或后续建议。

任务：
{task}

文件内容：
{file_context}
"""


def run_deepseek_file_workflow(
    *,
    task: str,
    allow_paths: list[str],
    run_id: str | None,
    timeout: int,
    mode: str,
    auto_validate: bool = False,
) -> dict[str, Any]:
    if mode not in {"scan", "plan", "diff"}:
        raise ValueError("mode must be one of: scan, plan, diff")
    run_id = validate_run_id(run_id, f"mcp-deepseek-{mode}")
    timeout = max(1, min(int(timeout), 1200))
    included, file_context = collect_allowed_context(allow_paths)
    artifact_dir = REPO / "artifacts" / "deepseek" / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    prompt = deepseek_file_prompt(task, included, file_context, mode=mode)
    prompt_path = artifact_dir / "prompt.md"
    output_path = artifact_dir / "deepseek-output.md"
    prompt_path.write_text(prompt, encoding="utf-8")
    raw_output = call_responses_proxy(prompt, timeout=timeout)
    output, redacted = redact_secret_like_text(raw_output)
    output_path.write_text(output, encoding="utf-8")
    status = "quarantine" if redacted else "accepted"
    error_code = None
    validation: dict[str, Any] | None = None

    result: dict[str, Any] = {
        "returncode": 0,
        "stdout": output[-12000:],
        "stderr": "",
        "mode": mode,
        "artifact_status": status,
        "redacted": redacted,
        "error_code": error_code,
        "artifact_dir": str(artifact_dir),
        "prompt_path": str(prompt_path),
        "output_path": str(output_path),
        "included_paths": included,
        "candidate_patch_id": None,
        "validated_patch_id": None,
    }

    if mode == "plan":
        validation = validate_plan_output(output)
        if not validation["ok"]:
            status = "quarantine" if redacted else "rejected"
            error_code = validation["error_code"]
            result.update(
                {
                    "returncode": 2,
                    "stderr": validation["message"],
                    "artifact_status": status,
                    "error_code": error_code,
                    "validation": validation,
                    "patch_path": None,
                }
            )
        else:
            result["validation"] = validation
            result["patch_path"] = None
    elif mode == "diff":
        diff = extract_diff_block(output)
        if redacted:
            status = "quarantine"
            error_code = "PATCH_CONTAINS_SECRET_LIKE_TEXT"
            validation = {
                "ok": False,
                "error_code": error_code,
                "message": "DeepSeek patch output contained secret-like text and was quarantined.",
                "validated_patch_id": None,
            }
            result.update(
                {
                    "returncode": 2,
                    "stderr": validation["message"],
                    "artifact_status": status,
                    "error_code": error_code,
                    "validation": validation,
                    "patch_path": None,
                    "candidate_patch_path": None,
                }
            )
        elif not diff:
            status = "quarantine" if redacted else "rejected"
            error_code = "PATCH_MISSING_DIFF"
            validation = {
                "ok": False,
                "error_code": error_code,
                "message": "no ```diff code block found in DeepSeek output",
                "validated_patch_id": None,
            }
            result.update(
                {
                    "returncode": 2,
                    "stderr": validation["message"],
                    "artifact_status": status,
                    "error_code": error_code,
                    "validation": validation,
                    "patch_path": None,
                    "candidate_patch_path": None,
                }
            )
        else:
            candidate_patch_id = make_patch_id("candidate", diff)
            candidate = write_patch_artifact(
                patch_id=candidate_patch_id,
                patch_text=diff,
                patch_kind="candidate",
                artifact_status="candidate",
                source_tool="deepseek_patch",
                run_id=run_id,
                validation={
                    "ok": None,
                    "error_code": None,
                    "message": "candidate patch generated; call validate_patch before apply",
                },
            )
            validation = candidate["metadata"]["validation"]
            result.update(
                {
                    "artifact_status": "candidate",
                    "patch_path": None,
                    "candidate_patch_id": candidate_patch_id,
                    "candidate_patch_path": candidate["patch_path"],
                    "candidate_metadata_path": candidate["metadata_path"],
                    "validation": validation,
                }
            )
            if auto_validate:
                validation_result = validate_patch_candidate_artifact(
                    candidate_patch_id=candidate_patch_id,
                    run_id=run_id,
                    timeout=timeout,
                )
                result["auto_validate"] = validation_result
                result["validated_patch_id"] = validation_result.get("validated_patch_id")
                if not validation_result.get("ok"):
                    result.update(
                        {
                            "returncode": 2,
                            "stderr": validation_result.get("message", "patch validation failed"),
                            "artifact_status": validation_result.get("artifact_status", "rejected"),
                            "error_code": validation_result.get("error_code"),
                            "validation": validation_result.get("validation"),
                        }
                    )
    metadata = {
        "run_id": run_id,
        "mode": mode,
        "artifact_status": result["artifact_status"],
        "redacted": result["redacted"],
        "error_code": result.get("error_code"),
        "validation": result.get("validation"),
        "candidate_patch_id": result.get("candidate_patch_id"),
        "validated_patch_id": result.get("validated_patch_id"),
        "included_paths": included,
    }
    result["metadata_path"] = str(write_workflow_metadata(artifact_dir, metadata))
    return result


def validate_patch_candidate_artifact(
    *,
    candidate_patch_id: str | None = None,
    patch_path: str | None = None,
    run_id: str | None = None,
    timeout: int = 120,
    source_tool: str = "validate_patch",
) -> dict[str, Any]:
    warnings: list[str] = []
    loaded: dict[str, Any] | None = None
    patch_text: str
    candidate_id: str | None = None

    if candidate_patch_id:
        loaded = load_patch_artifact(candidate_patch_id)
        if not loaded["ok"]:
            return loaded
        metadata = loaded["metadata"]
        if metadata.get("patch_kind") != "candidate":
            return {
                "ok": False,
                "returncode": 2,
                "artifact_status": metadata.get("artifact_status"),
                "candidate_patch_id": candidate_patch_id,
                "validated_patch_id": None,
                "error_code": "PATCH_ID_NOT_CANDIDATE",
                "message": "validate_patch requires a candidate patch artifact.",
            }
        patch_text = loaded["patch_text"]
        candidate_id = candidate_patch_id
    elif patch_path:
        warnings.append("patch_path is deprecated; use candidate_patch_id.")
        patch_rel = validate_repo_path(patch_path, must_exist=True)
        patch_abs = REPO / patch_rel
        if not patch_abs.name.endswith((".diff", ".patch")):
            return {
                "ok": False,
                "returncode": 2,
                "artifact_status": "rejected",
                "candidate_patch_id": None,
                "validated_patch_id": None,
                "error_code": "PATCH_INVALID_PATH",
                "message": "patch_path must end with .diff or .patch",
                "warnings": warnings,
            }
        patch_text = patch_abs.read_text(encoding="utf-8", errors="replace")
    else:
        return {
            "ok": False,
            "returncode": 2,
            "artifact_status": "rejected",
            "candidate_patch_id": None,
            "validated_patch_id": None,
            "error_code": "PATCH_INPUT_REQUIRED",
            "message": "candidate_patch_id or deprecated patch_path is required",
        }

    validation = validate_patch_diff(patch_text, cwd=REPO, timeout=timeout)
    if not validation["ok"]:
        status = "quarantine" if validation.get("error_code") == "PATCH_CONTAINS_SECRET_LIKE_TEXT" else "rejected"
        if candidate_id:
            persisted_patch_text = patch_text
            redacted = False
            if status == "quarantine":
                persisted_patch_text, redacted = redact_secret_like_text(patch_text)
            write_patch_artifact(
                patch_id=candidate_id,
                patch_text=persisted_patch_text,
                patch_kind="candidate",
                artifact_status=status,
                source_tool=source_tool,
                run_id=run_id,
                redacted=bool(validation.get("redacted")) or redacted,
                error_code=validation.get("error_code"),
                validation=validation,
                warnings=warnings,
            )
        return {
            "ok": False,
            "returncode": 2,
            "artifact_status": status,
            "candidate_patch_id": candidate_id,
            "validated_patch_id": None,
            "error_code": validation.get("error_code"),
            "message": validation.get("message"),
            "validation": validation,
            "warnings": warnings,
        }

    validated_patch_id = make_patch_id("validated", patch_text)
    validated = write_patch_artifact(
        patch_id=validated_patch_id,
        patch_text=patch_text,
        patch_kind="validated",
        artifact_status="validated",
        source_tool=source_tool,
        run_id=run_id,
        validation=validation,
        paths=validation.get("paths"),
        warnings=warnings,
    )
    return {
        "ok": True,
        "returncode": 0,
        "artifact_status": "validated",
        "candidate_patch_id": candidate_id,
        "validated_patch_id": validated_patch_id,
        "validated_patch_path": validated["patch_path"],
        "validated_metadata_path": validated["metadata_path"],
        "error_code": None,
        "message": "patch passed mechanical validation; Codex driver review is still required",
        "validation": validation,
        "warnings": warnings,
    }


def copy_ignore(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        findings = path_policy_findings(Path(name))
        if not findings["allowed"]:
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
    policy_profile: str = "strict-secrets",
) -> dict[str, Any]:
    """Check harness inputs against path, image, and command-template policy."""
    policy_profile = validate_policy_profile(policy_profile)
    checks: list[dict[str, Any]] = []
    allowed = True

    for raw_path in repo_paths or []:
        try:
            validate_repo_path(raw_path, must_exist=False)
            rel = Path(validate_repo_path(raw_path, must_exist=False))
            findings = path_policy_findings(rel, policy_profile=policy_profile)
            if not findings["allowed"]:
                allowed = False
            checks.append({"kind": "repo_path", "value": raw_path, **findings})
        except Exception as exc:
            allowed = False
            checks.append(
                {
                    "kind": "repo_path",
                    "value": raw_path,
                    "allowed": False,
                    "policy_profile": policy_profile,
                    "reason": str(exc),
                }
            )

    for raw_path in artifact_paths or []:
        try:
            rel = validate_workspace_rel_path(raw_path, must_exist=False)
            findings = path_policy_findings(rel, policy_profile=policy_profile)
            if not findings["allowed"]:
                allowed = False
            checks.append({"kind": "artifact_path", "value": raw_path, **findings})
        except Exception as exc:
            allowed = False
            checks.append(
                {
                    "kind": "artifact_path",
                    "value": raw_path,
                    "allowed": False,
                    "policy_profile": policy_profile,
                    "reason": str(exc),
                }
            )

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
                "policy_profile": policy_profile,
                "allowed": allowed,
                "checks": checks,
            },
        )

    return {
        "returncode": 0 if allowed else 2,
        "allowed": allowed,
        "policy_profile": policy_profile,
        "checks": checks,
        "allowed_test_templates": sorted(ALLOWED_TEST_TEMPLATES),
        "policy_profiles": list(POLICY_PROFILES),
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
def deepseek_generate_artifact_file(
    run_id: str,
    task: str,
    allow_paths: list[str],
    output_path: str,
    language: str = "python",
    timeout: int = 600,
    attempt_label: str | None = None,
    max_output_tokens: int = 12000,
) -> dict[str, Any]:
    """Ask DeepSeek for one fenced code block and write it as a versioned harness artifact."""
    run_id, root = ensure_harness_workspace(run_id)
    language = language.lower().strip()
    if not re.fullmatch(r"[A-Za-z0-9_+.-]{1,40}", language):
        raise ValueError(f"invalid language label: {language}")
    output_rel = validate_workspace_rel_path(output_path)
    expected_suffix = LANGUAGE_EXTENSIONS.get(language)
    if expected_suffix and Path(output_rel).suffix and Path(output_rel).suffix != expected_suffix:
        raise ValueError(f"output_path for {language} should end with {expected_suffix}")
    timeout = max(1, min(int(timeout), 1200))
    max_output_tokens = max(1000, min(int(max_output_tokens), 30000))
    attempt_number, attempt_id = reserve_attempt(root, attempt_label or Path(output_rel).stem)

    included, file_context = collect_allowed_context(allow_paths)
    prompt = deepseek_generate_file_prompt(task, included, file_context, language=language)
    prompt_path = root / "inputs" / f"generate-{attempt_id}.prompt.md"
    raw_output_path = root / "outputs" / f"generate-{attempt_id}.deepseek-output.md"
    metadata_path = root / "reports" / f"generate-{attempt_id}.json"
    prompt_path.write_text(prompt, encoding="utf-8")

    output = call_responses_proxy(prompt, timeout=timeout, max_output_tokens=max_output_tokens)
    raw_output_path.write_text(output, encoding="utf-8")
    code, blocks = extract_fenced_code(output, language)
    metadata: dict[str, Any] = {
        "returncode": 0,
        "run_id": run_id,
        "attempt_number": attempt_number,
        "attempt_id": attempt_id,
        "language": language,
        "output_path": output_path,
        "included_paths": included,
        "prompt_path": str(prompt_path),
        "raw_output_path": str(raw_output_path),
        "code_blocks": [{"language": block["language"], "bytes": block["bytes"]} for block in blocks],
    }

    if code is None:
        metadata.update(
            {
                "returncode": 2,
                "stderr": f"expected exactly one ```{language} fenced code block",
                "extracted_path": None,
                "latest_path": None,
                "sha256": None,
            }
        )
        write_json(metadata_path, metadata)
        append_harness_event(
            root,
            {
                "type": "generate_artifact_file",
                "status": "failed",
                "attempt_id": attempt_id,
                "path": output_path,
                "returncode": 2,
            },
        )
        metadata["metadata_path"] = str(metadata_path)
        return metadata

    if len(code.encode("utf-8")) > MAX_HARNESS_FILE_BYTES:
        raise ValueError(f"generated artifact is too large: max {MAX_HARNESS_FILE_BYTES} bytes")
    latest_path = workspace_path(root, str(output_rel))
    latest_path.parent.mkdir(parents=True, exist_ok=True)
    latest_path.write_text(code, encoding="utf-8")
    versioned_path = attempt_path(root, latest_path.parent.relative_to(root).as_posix(), output_rel, attempt_id)
    versioned_path.parent.mkdir(parents=True, exist_ok=True)
    versioned_path.write_text(code, encoding="utf-8")
    digest = sha256_text(code)
    metadata.update(
        {
            "stderr": "",
            "latest_path": str(latest_path),
            "versioned_path": str(versioned_path),
            "latest_relative_path": str(latest_path.relative_to(root)),
            "versioned_relative_path": str(versioned_path.relative_to(root)),
            "bytes": len(code.encode("utf-8")),
            "sha256": digest,
        }
    )
    write_json(metadata_path, metadata)
    append_harness_event(
        root,
        {
            "type": "generate_artifact_file",
            "status": "ok",
            "attempt_id": attempt_id,
            "path": str(latest_path.relative_to(root)),
            "versioned_path": str(versioned_path.relative_to(root)),
            "sha256": digest,
        },
    )
    metadata["metadata_path"] = str(metadata_path)
    return metadata


@mcp.tool()
def harness_run_temp_script(
    run_id: str,
    image: str,
    script_path: str,
    timeout: int = 600,
    network_disabled: bool = True,
    attempt_label: str | None = None,
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
    if attempt_label:
        attempt_id = validate_run_id(attempt_label, "attempt")
        log_path = root / "logs" / f"{script.stem}.{attempt_id}.log"
    else:
        log_path = root / "logs" / f"{script.stem}.log"
    log_path.write_text(result.get("stdout", "") + result.get("stderr", ""), encoding="utf-8")
    result.update(
        {
            "run_id": run_id,
            "log_path": str(log_path),
            "log_relative_path": str(log_path.relative_to(root)),
            "script_sha256": sha256_file(script),
        }
    )
    return result


@mcp.tool()
def harness_static_assertions(
    run_id: str,
    code_path: str | None = None,
    log_path: str | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    required_stdout: list[str] | None = None,
    required_stderr: list[str] | None = None,
    required_code: list[str] | None = None,
    forbidden_code: list[str] | None = None,
    forbidden_stdout: list[str] | None = None,
    expected_returncode: int | None = None,
    actual_returncode: int | None = None,
    max_duration_ms: int | None = None,
    actual_duration_ms: int | None = None,
    policy_profile: str = "ml-code",
    attempt_label: str | None = None,
) -> dict[str, Any]:
    """Run structured assertions over generated code, logs, stdout, and return metadata."""
    run_id, root = ensure_harness_workspace(run_id)
    policy_profile = validate_policy_profile(policy_profile)
    checks: list[dict[str, Any]] = []

    code_text = ""
    log_text = ""
    if code_path:
        code_file = workspace_path(root, code_path, must_exist=True)
        code_text = read_text_snippet(code_file, MAX_HARNESS_FILE_BYTES)
    if log_path:
        log_file = workspace_path(root, log_path, must_exist=True)
        log_text = read_text_snippet(log_file, MAX_HARNESS_FILE_BYTES)
    combined_stdout = (stdout or "") + ("\n" + log_text if log_text else "")
    combined_stderr = stderr or ""

    def add_check(kind: str, value: Any, passed: bool, detail: str = "") -> None:
        checks.append({"kind": kind, "value": value, "passed": passed, "detail": detail})

    for marker in required_stdout or []:
        add_check("required_stdout", marker, marker in combined_stdout)
    for marker in required_stderr or []:
        add_check("required_stderr", marker, marker in combined_stderr)
    for marker in required_code or []:
        add_check("required_code", marker, marker in code_text)
    for marker in forbidden_code or []:
        add_check("forbidden_code", marker, marker not in code_text)
    for marker in forbidden_stdout or []:
        add_check("forbidden_stdout", marker, marker not in combined_stdout)
    if expected_returncode is not None:
        add_check("expected_returncode", expected_returncode, actual_returncode == expected_returncode, f"actual={actual_returncode}")
    if max_duration_ms is not None and actual_duration_ms is not None:
        add_check("max_duration_ms", max_duration_ms, actual_duration_ms <= max_duration_ms, f"actual={actual_duration_ms}")

    hard_secret_patterns = [
        r"sk-[A-Za-z0-9_-]{20,}",
        r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{12,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ]
    if policy_profile in {"strict-secrets", "web-app", "ml-code"}:
        for pattern in hard_secret_patterns:
            found = re.search(pattern, code_text) is not None
            add_check("hard_secret_pattern", pattern, not found)

    passed = all(check["passed"] for check in checks)
    attempt_id = validate_run_id(attempt_label, "assertions") if attempt_label else f"assertions-{now_ms()}"
    report = {
        "returncode": 0 if passed else 2,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "policy_profile": policy_profile,
        "passed": passed,
        "checks": checks,
        "code_path": code_path,
        "log_path": log_path,
    }
    report_path = root / "reports" / f"{attempt_id}.assertions.json"
    write_json(report_path, report)
    append_harness_event(
        root,
        {
            "type": "static_assertions",
            "status": "ok" if passed else "failed",
            "attempt_id": attempt_id,
            "returncode": report["returncode"],
            "path": str(report_path.relative_to(root)),
        },
    )
    report["report_path"] = str(report_path)
    return report


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
def validate_patch(
    candidate_patch_id: str | None = None,
    patch_path: str | None = None,
    run_id: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Validate a candidate patch and return validated_patch_id after mechanical checks.

    This is not semantic security review and does not replace Codex driver
    review. patch_path is a deprecated compatibility input; prefer
    candidate_patch_id.
    """
    return validate_patch_candidate_artifact(
        candidate_patch_id=candidate_patch_id,
        patch_path=patch_path,
        run_id=run_id,
        timeout=timeout,
        source_tool="validate_patch",
    )


@mcp.tool()
def harness_apply_patch(
    run_id: str,
    validated_patch_id: str | None = None,
    patch_path: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Apply a validated patch to the isolated harness worktree, never to the real repo.

    Prefer validated_patch_id. The deprecated patch_path compatibility input is
    mechanically validated before use. Patch content safety remains the
    Codex driver review responsibility; validated_patch_id only means format,
    sensitive-path, secret-like, dangerous host-access, and git apply checks
    passed. MCP only provides basic validation and isolated worktree
    application. Docker daemon access remains a HIGH TRUST boundary, and
    needs_host_access is not a permission switch.
    """
    run_id, root = ensure_harness_workspace(run_id)
    worktree = root / "worktrees" / "repo"
    if not worktree.exists():
        raise ValueError("missing isolated worktree; call harness_create_worktree first")
    warnings: list[str] = []
    patch_text: str
    stored_name: str
    validation: dict[str, Any]
    source_ref: str | None = None

    if validated_patch_id:
        loaded = load_patch_artifact(validated_patch_id)
        if not loaded["ok"]:
            event = {
                "type": "apply_patch",
                "status": "rejected",
                "patch_id": validated_patch_id,
                "returncode": 2,
                "validation": loaded,
            }
            append_harness_event(root, event)
            return {
                "returncode": 2,
                "run_id": run_id,
                "worktree_path": str(worktree),
                "stored_patch": None,
                "validated_patch_id": validated_patch_id,
                "validation": loaded,
                "check": None,
                "apply": None,
                "warnings": warnings,
            }
        metadata = loaded["metadata"]
        metadata_validation = metadata.get("validation") or {}
        if (
            metadata.get("patch_kind") != "validated"
            or metadata.get("artifact_status") != "validated"
            or metadata_validation.get("ok") is not True
        ):
            validation = {
                "ok": False,
                "error_code": "PATCH_NOT_VALIDATED",
                "message": "harness_apply_patch requires a validated patch artifact.",
                "validated_patch_id": None,
            }
            event = {
                "type": "apply_patch",
                "status": "rejected",
                "patch_id": validated_patch_id,
                "returncode": 2,
                "validation": validation,
            }
            append_harness_event(root, event)
            return {
                "returncode": 2,
                "run_id": run_id,
                "worktree_path": str(worktree),
                "stored_patch": None,
                "validated_patch_id": validated_patch_id,
                "validation": validation,
                "check": None,
                "apply": None,
                "warnings": warnings,
            }
        patch_text = loaded["patch_text"]
        stored_name = f"{validated_patch_id}.diff"
        source_ref = validated_patch_id
        validation = validate_patch_diff(patch_text, cwd=worktree, timeout=timeout)
    elif patch_path:
        warnings.append("patch_path is deprecated; use validated_patch_id.")
        patch_rel = validate_repo_path(patch_path, must_exist=True)
        patch_abs = REPO / patch_rel
        if not patch_abs.name.endswith((".diff", ".patch")):
            raise ValueError("patch_path must end with .diff or .patch")
        patch_text = patch_abs.read_text(encoding="utf-8", errors="replace")
        validation = validate_patch_diff(patch_text, cwd=worktree, timeout=timeout)
        stored_name = patch_abs.name
        source_ref = str(patch_rel)
    else:
        validation = {
            "ok": False,
            "error_code": "PATCH_INPUT_REQUIRED",
            "message": "validated_patch_id or deprecated patch_path is required",
            "validated_patch_id": None,
        }
        event = {
            "type": "apply_patch",
            "status": "rejected",
            "returncode": 2,
            "validation": validation,
        }
        append_harness_event(root, event)
        return {
            "returncode": 2,
            "run_id": run_id,
            "worktree_path": str(worktree),
            "stored_patch": None,
            "validated_patch_id": None,
            "validation": validation,
            "check": None,
            "apply": None,
            "warnings": warnings,
        }

    if not validation["ok"]:
        event = {
            "type": "apply_patch",
            "status": "rejected",
            "path": source_ref,
            "returncode": 2,
            "validation": validation,
            "warnings": warnings,
        }
        append_harness_event(root, event)
        return {
            "returncode": 2,
            "run_id": run_id,
            "worktree_path": str(worktree),
            "stored_patch": None,
            "validated_patch_id": validated_patch_id,
            "validation": validation,
            "check": None,
            "apply": None,
            "warnings": warnings,
        }
    if not validated_patch_id:
        validated_patch_id = make_patch_id("validated", patch_text)
        write_patch_artifact(
            patch_id=validated_patch_id,
            patch_text=patch_text,
            patch_kind="validated",
            artifact_status="validated",
            source_tool="harness_apply_patch",
            run_id=run_id,
            validation=validation,
            paths=validation.get("paths"),
            warnings=warnings,
        )
    stored_patch = root / "patches" / stored_name
    stored_patch.write_text(patch_text, encoding="utf-8")
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
        "validated_patch_id": validated_patch_id,
        "source": source_ref,
        "warnings": warnings,
    }
    append_harness_event(root, event)
    return {
        "returncode": event["returncode"],
        "run_id": run_id,
        "worktree_path": str(worktree),
        "stored_patch": str(stored_patch),
        "validated_patch_id": validated_patch_id,
        "validation": validation,
        "check": check,
        "apply": applied,
        "warnings": warnings,
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
    result.update(
        {
            "run_id": run_id,
            "log_path": str(log_path),
            "log_relative_path": str(log_path.relative_to(root)),
            "test_template": test_template,
        }
    )
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
        mode="diff",
    )
    append_harness_event(
        root,
        {
            "type": "feedback_to_deepseek",
            "status": "ok" if result["returncode"] == 0 else "failed",
            "path": result.get("candidate_patch_path") or result.get("patch_path") or result.get("output_path"),
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
    """Read only allow-listed files, call the local Responses proxy, and save artifacts.

    needs_host_access is reserved for future policy signaling and does not grant
    additional permissions.
    """
    return run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=run_id,
        timeout=timeout,
        mode="scan",
    )


@mcp.tool()
def deepseek_plan(
    task: str,
    allow_paths: list[str],
    run_id: str | None = None,
    timeout: int = 180,
    needs_host_access: bool = False,
) -> dict[str, Any]:
    """Read only allow-listed files and ask DeepSeek for a plan-only artifact.

    Plan output is rejected if it contains unified diff markers. needs_host_access
    is reserved for future policy signaling and does not grant permissions.
    """
    return run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=run_id,
        timeout=timeout,
        mode="plan",
    )


@mcp.tool()
def deepseek_patch(
    task: str,
    allow_paths: list[str],
    run_id: str | None = None,
    timeout: int = 180,
    needs_host_access: bool = False,
    mode: str = "diff",
    auto_validate: bool = False,
) -> dict[str, Any]:
    """Read only allow-listed files, ask DeepSeek for a candidate patch, and save artifacts.

    needs_host_access is reserved for future policy signaling and does not grant
    additional permissions. mode="plan" rejects diff markers and never writes
    patch.diff; mode="diff" creates a candidate_patch_id. Call validate_patch
    to turn a candidate into validated_patch_id before harness_apply_patch.
    auto_validate is kept for compatibility and should normally stay false.
    """
    selected_mode = mode.lower().strip()
    if selected_mode not in {"plan", "diff"}:
        raise ValueError("mode must be 'plan' or 'diff'")
    return run_deepseek_file_workflow(
        task=task,
        allow_paths=allow_paths,
        run_id=run_id,
        timeout=timeout,
        mode=selected_mode,
        auto_validate=bool(auto_validate),
    )


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
