from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = REPO_ROOT / "deepseek-codex-adapter" / "scripts" / "deepseek_driver_mcp.py"


def load_driver(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()

    fake_docker = types.ModuleType("docker")
    fake_docker.DockerClient = object
    fake_docker.from_env = lambda: object()

    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")

    class FakeFastMCP:
        def __init__(self, *args, **kwargs):
            pass

        def tool(self):
            return lambda fn: fn

        def run(self, *args, **kwargs):
            pass

    fake_fastmcp.FastMCP = FakeFastMCP

    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.server", fake_server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_fastmcp)
    monkeypatch.setattr(
        sys,
        "argv",
        ["deepseek_driver_mcp.py", "--repo", str(repo), "--repo-host-path", str(repo)],
    )

    module_name = f"deepseek_driver_mcp_test_{tmp_path.name}"
    spec = importlib.util.spec_from_file_location(module_name, DRIVER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, repo


def test_plan_mode_rejects_diff_markers(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    output = "Plan first\n\ndiff --git a/foo b/foo\n@@ -1,1 +1,1 @@\n"

    result = driver.validate_plan_output(output)

    assert result["ok"] is False
    assert result["error_code"] == "PLAN_CONTAINS_DIFF"


def test_plan_mode_accepts_plain_plan(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    output = '{"steps": ["add a static test", "run pytest"]}'

    result = driver.validate_plan_output(output)

    assert result["ok"] is True
    assert result["error_code"] is None


def test_secret_like_output_is_redacted(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    fake_key = "sk-" + ("A" * 20)
    fake_env = "DEEPSEEK_API_KEY=" + "fake-do-not-print"
    text = f"{fake_key}\n{fake_env}\n"

    redacted, changed = driver.redact_secret_like_text(text)

    assert changed is True
    assert fake_key not in redacted
    assert fake_env not in redacted
    assert "sk-[REDACTED]" in redacted
    assert "DEEPSEEK_API_KEY=[REDACTED]" in redacted


def test_deepseek_plan_rejects_diff_without_patch_file(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)

    monkeypatch.setattr(driver, "collect_allowed_context", lambda paths: (paths, "context"))
    monkeypatch.setattr(driver, "call_responses_proxy", lambda prompt, timeout, max_output_tokens=8000: "diff --git a/x b/x\n")

    result = driver.deepseek_plan(
        task="make a plan only",
        allow_paths=["README.md"],
        run_id="plan-rejects-diff",
        timeout=5,
    )

    assert result["returncode"] == 2
    assert result["error_code"] == "PLAN_CONTAINS_DIFF"
    assert result["patch_path"] is None
    assert not (repo / "artifacts" / "deepseek" / "plan-rejects-diff" / "patch.diff").exists()


def test_patch_validation_rejects_corrupt_patch(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)

    def fake_run(cmd, cwd, timeout):
        return {"returncode": 1, "stdout": "", "stderr": "corrupt patch at line 2"}

    monkeypatch.setattr(driver, "run_local_command", fake_run)
    corrupt = "diff --git a/foo.txt b/foo.txt\nthis is not a valid patch\n"

    result = driver.validate_patch_diff(corrupt, cwd=tmp_path, timeout=5)

    assert result["ok"] is False
    assert result["error_code"] == "PATCH_APPLY_CHECK_FAILED"
    assert result["validated_patch_id"] is None


def test_patch_validation_rejects_forbidden_paths(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    diff = """diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1 @@
+placeholder
diff --git a/security_review.md b/security_review.md
new file mode 100644
--- /dev/null
+++ b/security_review.md
@@ -0,0 +1 @@
+internal
diff --git a/secret.key b/secret.key
new file mode 100644
--- /dev/null
+++ b/secret.key
@@ -0,0 +1 @@
+placeholder
"""

    result = driver.validate_patch_diff(diff, cwd=tmp_path, timeout=5)

    assert result["ok"] is False
    assert result["error_code"] == "PATCH_TOUCHES_FORBIDDEN_PATH"
    assert result["validated_patch_id"] is None


def test_needs_host_access_is_not_permission_switch(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    source = DRIVER_PATH.read_text(encoding="utf-8")
    forbidden_branches = (
        "if needs_host_access",
        "needs_host_access and",
        "privileged=needs_host_access",
        "network_mode=needs_host_access",
    )

    assert all(fragment not in source for fragment in forbidden_branches)
    for name in ("deepseek_scan", "deepseek_plan", "deepseek_patch"):
        func = getattr(driver, name)
        assert func.__defaults__ is not None
        assert "needs_host_access" in func.__code__.co_varnames


def test_docker_client_high_trust_comment_remains(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    source = DRIVER_PATH.read_text(encoding="utf-8")
    start = source.index("def docker_client")
    snippet = source[start : start + 260]

    assert "HIGH TRUST" in snippet
    assert "host Docker daemon" in snippet
    assert "allow-listed tools" in snippet
    assert driver.docker_client is not None


def test_harness_apply_patch_docstring_keeps_review_boundary(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    doc = driver.harness_apply_patch.__doc__ or ""
    lower = doc.lower()

    assert "codex driver" in lower
    assert "review" in lower
    assert "isolated harness worktree" in lower or "isolated worktree" in lower
    assert "patch content" in lower


def test_harness_apply_patch_rejects_unvalidated_raw_patch(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)
    run_id, root = driver.ensure_harness_workspace("raw-rejected")
    worktree = root / "worktrees" / "repo"
    worktree.mkdir(parents=True)
    patch_file = repo / "bad.diff"
    patch_file.write_text("not a unified diff\n", encoding="utf-8")

    result = driver.harness_apply_patch(run_id=run_id, patch_path="bad.diff", timeout=5)

    assert result["returncode"] == 2
    assert result["validation"]["error_code"] == "PATCH_INVALID_FORMAT"
    assert result["apply"] is None
