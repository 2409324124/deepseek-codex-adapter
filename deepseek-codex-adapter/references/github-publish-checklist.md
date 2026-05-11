# GitHub Publish Checklist

## Release Scope

Publish only the skill package, public docs, and tests:

```text
deepseek-codex-adapter/
├── SKILL.md
├── agents/openai.yaml
├── docker/mcp-driver.Dockerfile
├── scripts/deepseek_driver_mcp.py
├── scripts/deepseek_responses_proxy.py
└── references/
    ├── protocol-notes.md
    ├── mcp-driver-workflow.md
    ├── mechanism-and-comparison.md
    └── github-publish-checklist.md
tests/
├── test_mcp_output_validation.py
└── test_mcp_patch_pipeline.py
```

Do not publish:

- `.env`
- `.key`
- `*.key`
- `artifacts/`
- `security_review.md`
- tokens or private keys
- local systemd unit files with user-specific paths
- wrapper scripts containing private paths
- project planning files unless the user explicitly wants them
- `__pycache__` or other generated files

## Pre-Publish Checks

Run from the skill folder or parent workspace:

```bash
python3 -m py_compile scripts/deepseek_responses_proxy.py
python3 -m py_compile scripts/deepseek_driver_mcp.py
python3 -m pytest ../tests/test_mcp_output_validation.py -q
python3 -m pytest ../tests/test_mcp_patch_pipeline.py -q
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
docker build -t deepseek-driver-mcp:local -f docker/mcp-driver.Dockerfile .
git diff --check
find . -type f | sort
```

From the repository root, confirm no sensitive files are tracked:

```bash
git ls-files | grep -E '(^|/)(\.env|.*\.key|security_review\.md|artifacts/|.*private.*|.*secret.*|.*credential.*)' || true
```

The command should produce no output.

Inspect for private paths and secret-shaped text:

```bash
rg -n "[/]home[/]|[/]mnt[/]|DEE[P]SEEK_API_KEY=.*|gho[_]|sk[-]|BEGIN .*PRIV[A]TE|\\.env|\\.key" .
```

Expected matches may include `.env` as a documented filename, placeholder API-key examples, and redaction regexes, but must not include real secrets or local project-specific absolute paths.

Before pushing, also confirm:

- `artifacts/` is not tracked.
- `security_review.md` is not tracked.
- `.env` and `*.key` are not tracked.
- `__pycache__/` and `*.pyc` are absent.
- README does not claim Docker or MCP is absolutely safe.
- README does not claim DeepSeek patches can be automatically trusted.
- README does not claim `validated_patch_id` means a patch is semantically safe.
- README says Codex driver or user review is still required.
- `tools/list` includes `validate_patch`.
- `SKILL.md` enabled tools include `validate_patch`.
- `harness_apply_patch` docs prefer `validated_patch_id`; `patch_path` remains deprecated compatibility only.

## Suggested Repository Shape

Use a dedicated repository or a clean branch in a skills repository. Avoid publishing from an unrelated application repo with a dirty worktree.

Recommended repository names:

- `deepseek-codex-adapter`
- `codex-deepseek-responses-proxy`
- `codex-skill-deepseek-adapter`

## Suggested GitHub Description

Local Codex skill and Responses-compatible proxy for using DeepSeek Chat models as an experimental Codex model provider, with tool-call and parallel-call compatibility tests.

## Suggested Caveat

DeepSeek does not natively expose OpenAI Responses API. This project provides an experimental local compatibility proxy and should be validated with bounded Codex agent tests before real repository work.
