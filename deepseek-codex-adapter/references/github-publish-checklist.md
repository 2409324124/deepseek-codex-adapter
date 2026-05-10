# GitHub Publish Checklist

## Release Scope

Publish only the skill folder contents:

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
```

Do not publish:

- `.env`
- `.key`
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
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
docker build -t deepseek-driver-mcp:local -f docker/mcp-driver.Dockerfile .
find . -type f | sort
```

Inspect for private paths:

```bash
rg -n "[/]home[/]|[/]mnt[/]|DEE[P]SEEK_API_KEY=.*|gho[_]|sk[-]|BEGIN .*PRIV[A]TE|\\.env|\\.key" .
```

Expected matches may include `.env` as a documented filename, but must not include real secrets or local project-specific absolute paths.

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
