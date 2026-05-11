from __future__ import annotations

import re
from pathlib import Path

from test_mcp_output_validation import DRIVER_PATH, load_driver


VALID_DIFF = """diff --git a/foo.txt b/foo.txt
--- a/foo.txt
+++ b/foo.txt
@@ -1 +1 @@
-old
+new
"""


def make_repo_with_file(repo: Path) -> None:
    (repo / "foo.txt").write_text("old\n", encoding="utf-8")


def test_make_patch_id_does_not_leak_paths_or_secrets(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    fake = "sk-" + ("A" * 20)
    patch_text = f"{VALID_DIFF}\n# /home/miku/projects/repo {fake}\n"

    patch_id = driver.make_patch_id("candidate", patch_text)

    assert patch_id.startswith("candidate_")
    assert "/" not in patch_id
    assert "home" not in patch_id
    assert fake not in patch_id
    assert patch_id.endswith(driver.sha256_text(patch_text)[:12])
    assert re.fullmatch(r"candidate_\d{16,20}_[a-f0-9]{12}", patch_id)


def test_make_patch_id_does_not_collide_for_same_patch_same_second(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)

    first = driver.make_patch_id("candidate", VALID_DIFF)
    second = driver.make_patch_id("candidate", VALID_DIFF)

    assert first != second
    assert first.rsplit("_", 1)[-1] == second.rsplit("_", 1)[-1]


def test_deepseek_patch_candidate_artifact_shape(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)
    make_repo_with_file(repo)
    output = f"summary\n\n```diff\n{VALID_DIFF}```\n"

    monkeypatch.setattr(driver, "collect_allowed_context", lambda paths: (paths, "context"))
    monkeypatch.setattr(driver, "call_responses_proxy", lambda prompt, timeout, max_output_tokens=8000: output)

    result = driver.deepseek_patch(
        task="make a tiny patch",
        allow_paths=["README.md"],
        run_id="candidate-shape",
        timeout=5,
    )

    assert result["returncode"] == 0
    assert result["artifact_status"] == "candidate"
    assert result["candidate_patch_id"].startswith("candidate_")
    assert result["validated_patch_id"] is None
    assert result["patch_path"] is None

    loaded = driver.load_patch_artifact(result["candidate_patch_id"])
    assert loaded["ok"] is True
    metadata = loaded["metadata"]
    assert metadata["artifact_status"] == "candidate"
    assert metadata["patch_kind"] == "candidate"
    assert metadata["validation"]["ok"] is None


def test_validate_patch_generates_validated_patch_id(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)
    make_repo_with_file(repo)
    candidate_id = driver.make_patch_id("candidate", VALID_DIFF)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=VALID_DIFF,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id="validate-ok",
    )

    result = driver.validate_patch(candidate_patch_id=candidate_id, run_id="validate-ok", timeout=5)

    assert result["ok"] is True
    assert result["validated_patch_id"].startswith("validated_")
    loaded = driver.load_patch_artifact(result["validated_patch_id"])
    assert loaded["ok"] is True
    assert loaded["metadata"]["artifact_status"] == "validated"
    assert loaded["metadata"]["patch_kind"] == "validated"
    assert loaded["metadata"]["validation"]["ok"] is True


def test_validate_patch_rejects_corrupt_patch(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    corrupt = "diff --git a/foo.txt b/foo.txt\nthis is not a valid patch\n"
    candidate_id = driver.make_patch_id("candidate", corrupt)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=corrupt,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id="validate-corrupt",
    )

    result = driver.validate_patch(candidate_patch_id=candidate_id, run_id="validate-corrupt", timeout=5)

    assert result["ok"] is False
    assert result["validated_patch_id"] is None
    assert result["error_code"] in {"PATCH_APPLY_CHECK_FAILED", "PATCH_INVALID_FORMAT"}


def test_validate_patch_rejects_forbidden_paths(tmp_path, monkeypatch):
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
diff --git a/artifacts/foo.txt b/artifacts/foo.txt
new file mode 100644
--- /dev/null
+++ b/artifacts/foo.txt
@@ -0,0 +1 @@
+placeholder
"""
    candidate_id = driver.make_patch_id("candidate", diff)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=diff,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id="validate-forbidden",
    )

    result = driver.validate_patch(candidate_patch_id=candidate_id, run_id="validate-forbidden", timeout=5)

    assert result["ok"] is False
    assert result["error_code"] == "PATCH_TOUCHES_FORBIDDEN_PATH"
    assert result["validated_patch_id"] is None


def test_validate_patch_rejects_secret_like_content(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    fake = "sk-" + ("A" * 20)
    diff = f"""diff --git a/foo.txt b/foo.txt
--- a/foo.txt
+++ b/foo.txt
@@ -0,0 +1 @@
+{fake}
"""
    candidate_id = driver.make_patch_id("candidate", diff)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=diff,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id="validate-secret",
    )

    result = driver.validate_patch(candidate_patch_id=candidate_id, run_id="validate-secret", timeout=5)

    assert result["ok"] is False
    assert result["error_code"] == "PATCH_CONTAINS_SECRET_LIKE_TEXT"
    assert result["validated_patch_id"] is None
    assert fake not in result["message"]
    loaded = driver.load_patch_artifact(candidate_id)
    assert fake not in loaded["patch_text"]
    assert "[REDACTED]" in loaded["patch_text"]
    assert loaded["metadata"]["artifact_status"] == "quarantine"


def test_validate_patch_rejects_dangerous_needs_host_access(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    diff = """diff --git a/tool.py b/tool.py
new file mode 100644
--- /dev/null
+++ b/tool.py
@@ -0,0 +1,4 @@
+def run(needs_host_access=False):
+    if needs_host_access:
+        privileged=True
+        network_mode="host"
"""
    candidate_id = driver.make_patch_id("candidate", diff)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=diff,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id="validate-danger",
    )

    result = driver.validate_patch(candidate_patch_id=candidate_id, run_id="validate-danger", timeout=5)

    assert result["ok"] is False
    assert result["error_code"] == "PATCH_CONTAINS_DANGEROUS_HOST_ACCESS"
    assert result["validated_patch_id"] is None


def test_harness_apply_patch_prefers_validated_patch_id(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)
    make_repo_with_file(repo)
    run_id, root = driver.ensure_harness_workspace("apply-validated")
    worktree = root / "worktrees" / "repo"
    worktree.mkdir(parents=True)
    make_repo_with_file(worktree)
    validation = driver.validate_patch_diff(VALID_DIFF, cwd=worktree, timeout=5)
    assert validation["ok"] is True
    validated_id = driver.make_patch_id("validated", VALID_DIFF)
    driver.write_patch_artifact(
        patch_id=validated_id,
        patch_text=VALID_DIFF,
        patch_kind="validated",
        artifact_status="validated",
        source_tool="test",
        run_id=run_id,
        validation=validation,
        paths=validation["paths"],
    )

    result = driver.harness_apply_patch(run_id=run_id, validated_patch_id=validated_id, timeout=5)

    assert result["returncode"] == 0
    assert result["validated_patch_id"] == validated_id
    assert result["warnings"] == []
    assert (worktree / "foo.txt").read_text(encoding="utf-8") == "new\n"


def test_harness_apply_patch_rejects_unvalidated_candidate_id(tmp_path, monkeypatch):
    driver, _repo = load_driver(tmp_path, monkeypatch)
    run_id, root = driver.ensure_harness_workspace("reject-candidate")
    (root / "worktrees" / "repo").mkdir(parents=True)
    candidate_id = driver.make_patch_id("candidate", VALID_DIFF)
    driver.write_patch_artifact(
        patch_id=candidate_id,
        patch_text=VALID_DIFF,
        patch_kind="candidate",
        artifact_status="candidate",
        source_tool="test",
        run_id=run_id,
    )

    result = driver.harness_apply_patch(run_id=run_id, validated_patch_id=candidate_id, timeout=5)

    assert result["returncode"] == 2
    assert result["validation"]["error_code"] in {"PATCH_NOT_VALIDATED", "PATCH_ID_NOT_VALIDATED"}
    assert result["apply"] is None


def test_harness_apply_patch_patch_path_deprecated_warning(tmp_path, monkeypatch):
    driver, repo = load_driver(tmp_path, monkeypatch)
    run_id, root = driver.ensure_harness_workspace("deprecated-path")
    (root / "worktrees" / "repo").mkdir(parents=True)
    patch_file = repo / "bad.diff"
    patch_file.write_text("not a unified diff\n", encoding="utf-8")

    result = driver.harness_apply_patch(run_id=run_id, patch_path="bad.diff", timeout=5)

    assert result["returncode"] == 2
    assert "deprecated" in " ".join(result["warnings"])
    assert result["validation"]["error_code"] == "PATCH_INVALID_FORMAT"
    assert result["apply"] is None


def test_tools_registry_contains_validate_patch():
    source = DRIVER_PATH.read_text(encoding="utf-8")
    marker = "@mcp.tool()\ndef validate_patch"

    assert marker in source
    assert "validated_patch_id" in source
    assert "does not replace Codex driver" in source
