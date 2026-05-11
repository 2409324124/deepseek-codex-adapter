# MCP Driver Workflow

## Purpose

The MCP driver is for the "Codex drives, DeepSeek assists" mode. Codex remains the active agent. DeepSeek is called by a narrow MCP tool to scan allow-listed files or draft a patch, and the full DeepSeek output is saved under `artifacts/deepseek/<run-id>/`.

This is different from using DeepSeek as the Codex model provider. It is also different from a generic MCP wrapper around arbitrary shell commands: the server exposes only a small whitelist of tools.

## Components

- `scripts/deepseek_responses_proxy.py`: local `/v1/responses` proxy to DeepSeek.
- `scripts/deepseek_driver_mcp.py`: official Python MCP SDK server.
- `docker/mcp-driver.Dockerfile`: builds a Docker image that includes the MCP server script.
- Target repository mounted at `/repo`.
- Host Docker socket mounted only so the MCP tools can run controlled Docker probes or scripts.

The MCP image contains the server code. The target repository does not need to contain `deepseek_driver_mcp.py`.

## Build And Register

From the skill directory:

```bash
docker build -t deepseek-driver-mcp:local -f docker/mcp-driver.Dockerfile .
```

Register against a target repository:

```bash
codex mcp add deepseek-driver -- \
  docker run --rm -i --network host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /path/to/repo:/repo \
    deepseek-driver-mcp:local \
    --repo-host-path /path/to/repo
```

Recommended config for the full Codex-driver/DeepSeek-worker harness:

```toml
[mcp_servers.deepseek-driver]
enabled_tools = ["docker_list_images", "docker_probe_torch", "docker_run_python_script", "harness_create_workspace", "harness_policy_check", "harness_write_file", "deepseek_generate_artifact_file", "harness_run_temp_script", "harness_static_assertions", "harness_create_worktree", "harness_apply_patch", "harness_run_repo_tests", "harness_feedback_to_deepseek", "harness_collect_report", "deepseek_scan", "deepseek_plan", "deepseek_patch"]
startup_timeout_sec = 60
tool_timeout_sec = 600
```

## Tools

- `docker_list_images(limit=50)`: lists local Docker images through the mounted Docker socket.
- `docker_probe_torch(image, timeout=120)`: runs `import torch; print(torch.__version__)` in a selected image.
- `docker_run_python_script(image, script_path, timeout=600)`: runs one repository Python script by mounting that script's directory read-only.
- `harness_create_workspace(run_id)`: creates `artifacts/deepseek/harness/<run-id>/` with `inputs/`, `scripts/`, `outputs/`, `logs/`, `reports/`, `patches/`, and `worktrees/`.
- `harness_policy_check(run_id, repo_paths, artifact_paths, image, test_template, policy_profile)`: checks paths, image names, and test templates against the harness policy.
- `harness_write_file(run_id, relative_path, content)`: writes only inside the harness artifact workspace and records bytes plus sha256.
- `deepseek_generate_artifact_file(run_id, task, allow_paths, output_path, language, timeout, attempt_label)`: calls DeepSeek, requires exactly one fenced code block, writes the latest artifact, and stores a versioned attempt copy plus extraction metadata.
- `harness_run_temp_script(run_id, image, script_path, timeout, network_disabled=True, attempt_label=None)`: runs an artifact Python script in Docker with `/repo` read-only and `/artifact` read-write. When `attempt_label` is set, the log path is versioned. Use returned `log_relative_path` when calling `harness_static_assertions(log_path=...)`.
- `harness_static_assertions(run_id, ...)`: checks generated code, stdout/stderr, return code, runtime, required markers, and task-specific forbidden strings. The default `ml-code` profile does not treat `token` as forbidden code.
- `harness_create_worktree(run_id, base_ref="working-copy")`: creates a sanitized isolated repository copy under the harness workspace.
- `harness_apply_patch(run_id, patch_path, timeout=120)`: validates raw patch input, runs `git apply --check`, and applies the patch only inside the isolated worktree.
- `harness_run_repo_tests(run_id, image, test_template, timeout=600, network_disabled=True)`: runs only an allow-listed template: `pytest`, `python -m pytest`, or `npm test`.
- `harness_feedback_to_deepseek(run_id, failure_log, allow_paths, timeout=180)`: sends a bounded failure summary plus allow-listed files to DeepSeek for a revised patch draft.
- `harness_collect_report(run_id)`: writes `reports/report.json` and `reports/report.md` for Codex review.
- `deepseek_scan(task, allow_paths, run_id, timeout=180)`: reads only allow-listed non-sensitive files, calls the local Responses proxy, and writes redacted `prompt.md` plus `deepseek-output.md`.
- `deepseek_plan(task, allow_paths, run_id, timeout=180)`: asks for plan-only output. Diff markers are rejected with `PLAN_CONTAINS_DIFF`, and `patch.diff` is never written.
- `deepseek_patch(task, allow_paths, run_id, timeout=180, mode="diff")`: same read boundary as scan. `mode="plan"` uses plan validation; `mode="diff"` validates a unified diff before saving accepted `patch.diff`.

## Scan / Plan / Patch Validation Flow

1. Codex driver calls `deepseek_scan` for bounded repository analysis.
2. Codex driver calls `deepseek_plan` for plan-only output.
3. `deepseek_plan` rejects diff markers with `PLAN_CONTAINS_DIFF`.
4. Codex driver reviews the plan.
5. Codex driver calls `deepseek_patch(mode="diff")` for a candidate patch.
6. MCP redacts secret-like content before persisting output.
7. MCP validates diff patches with `validate_patch_diff`.
8. Invalid patches are rejected and do not produce accepted `patch.diff` for apply.
9. `harness_apply_patch` validates raw patch input and applies only into an isolated worktree.
10. Codex driver review remains required.

`harness_apply_patch` applying a patch in an isolated worktree does not mean the patch is semantically safe. It only means the patch passed mechanical checks and was applied outside the real repository.

## Security Boundary

The server rejects paths outside `/repo` and rejects sensitive names or substrings:

- `.env`
- `.key`
- `.git`
- `node_modules`
- `test-results`
- `secret`
- `credential`
- `private_key`
- `api_key`

`token`, `auth`, `password`, and `session` are soft policy signals by default. They are reported by `harness_policy_check` but are not automatically rejected in generated code, because ML/NLP tasks commonly use words such as `token` and `tokenizer`.

DeepSeek scan/patch/generate does not receive a shell, does not scan the repository, and does not read files beyond `allow_paths`. It sees only the file contents that the MCP server embeds in the prompt.

Harness tools keep writes away from the real repository:

- Temporary DeepSeek code is written under `artifacts/deepseek/harness/<run-id>/`.
- Docker execution mounts the repository read-only and the artifact workspace read-write.
- Patch checking and test runs happen in an isolated sanitized copy under `worktrees/repo`.
- The MCP server does not expose arbitrary shell strings; repo tests must use predefined templates.

The Docker socket mount is still high trust. Treat `docker_*` tools as controlled host-capability tools and keep `enabled_tools` explicit.

## Validation Matrix

Run these before claiming the MCP driver is usable:

1. `codex mcp get deepseek-driver --json` shows the server enabled with the whitelist tools.
2. MCP `tools/list` returns exactly the expected tool names.
3. `docker_probe_torch` returns the PyTorch version for a known local image.
4. `deepseek_scan` succeeds on one safe allow-listed file and writes `artifacts/deepseek/<run-id>/deepseek-output.md`.
5. `deepseek_scan` with `.env` fails with a sensitive-path rejection.
6. `deepseek_plan` accepts plan-only output and rejects diff-shaped output with `PLAN_CONTAINS_DIFF`.
7. `deepseek_patch(mode="diff")` writes accepted `patch.diff` only after patch validation succeeds.
8. corrupt or forbidden-path patches are rejected and do not enter `harness_apply_patch`.
9. `harness_policy_check` rejects `.env`, `.key`, `.git`, and `../` paths.
10. `harness_policy_check(policy_profile="ml-code")` allows `scripts/tokenizer.py` while reporting a soft `token` hit.
11. `deepseek_generate_artifact_file` writes both a latest file and a versioned attempt copy.
12. `harness_run_temp_script(attempt_label=...)` writes a versioned log.
13. `harness_static_assertions` passes with default `ml-code` when generated code contains `token`, and fails when `forbidden_code=["token"]` is explicitly requested.
14. `harness_run_temp_script` can run a temporary artifact Python script and write to `outputs/`.
15. `harness_apply_patch` applies a validated patch to the isolated worktree and leaves the real repository untouched.
16. `harness_run_repo_tests` runs an allow-listed template in Docker and logs stdout/stderr.
17. `harness_feedback_to_deepseek` can turn a bounded failure log plus allow-listed files into a revised patch draft.

## Harness Levels

- Level 0, environment probes: `docker_list_images`, `docker_probe_torch`.
- Level 1, read-only DeepSeek analysis: `deepseek_scan`.
- Level 2, bounded script execution: `docker_run_python_script` for existing scripts, `harness_run_temp_script` for artifact scripts.
- Level 3, plan and patch draft: `deepseek_plan`, `deepseek_patch`.
- Level 4, dynamic experiment harness: `harness_create_workspace`, `deepseek_generate_artifact_file`, `harness_write_file`, `harness_run_temp_script`, `harness_static_assertions`, `harness_collect_report`.
- Level 5, reviewable repair loop: `harness_create_worktree`, `harness_apply_patch`, `harness_run_repo_tests`, `harness_feedback_to_deepseek`, final Codex review.

The intended operating model is:

```text
Codex/GPT driver
  -> deepseek-driver MCP
  -> DeepSeek scan/patch/feedback
  -> artifacts + isolated worktree + reports
  -> Codex review/apply/test/commit decision
```

## Known Codex CLI Boundary

In local validation with Codex CLI 0.125.0:

- Direct MCP protocol calls to the Dockerized server worked.
- `codex exec --dangerously-bypass-approvals-and-sandbox` could call `docker_list_images` and `docker_probe_torch`.
- `codex exec --sandbox read-only` and `codex exec --full-auto` could discover the MCP server but returned `user cancelled MCP tool call` for tool execution.
- A DeepSeek-profile outer `codex exec` session did not expose the expected MCP tool-call surface and should not be used as the MCP driver.

Practical rule: use the normal Codex/OpenAI driver for MCP orchestration, and call DeepSeek through the MCP tool backend. If non-interactive `codex exec` cancels MCP tools, document that as a Codex CLI approval boundary rather than falling back to arbitrary shell access.
