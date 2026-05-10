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

Recommended config:

```toml
[mcp_servers.deepseek-driver]
enabled_tools = ["docker_list_images", "docker_probe_torch", "docker_run_python_script", "deepseek_scan", "deepseek_patch"]
startup_timeout_sec = 60
tool_timeout_sec = 600
```

## Tools

- `docker_list_images(limit=50)`: lists local Docker images through the mounted Docker socket.
- `docker_probe_torch(image, timeout=120)`: runs `import torch; print(torch.__version__)` in a selected image.
- `docker_run_python_script(image, script_path, timeout=600)`: runs one repository Python script by mounting that script's directory read-only.
- `deepseek_scan(task, allow_paths, run_id, timeout=180)`: reads only allow-listed non-sensitive files, calls the local Responses proxy, and writes `prompt.md` plus `deepseek-output.md`.
- `deepseek_patch(task, allow_paths, run_id, timeout=180)`: same read boundary as scan, but asks for a unified diff draft and extracts `patch.diff` when a diff block exists.

## Security Boundary

The server rejects paths outside `/repo` and rejects sensitive names or substrings:

- `.env`
- `.key`
- `.git`
- `node_modules`
- `test-results`
- `secret`
- `token`
- `credential`
- `private_key`
- `api_key`

DeepSeek scan/patch does not receive a shell, does not scan the repository, and does not read files beyond `allow_paths`. It sees only the file contents that the MCP server embeds in the prompt.

The Docker socket mount is still high trust. Treat `docker_*` tools as controlled host-capability tools and keep `enabled_tools` explicit.

## Validation Matrix

Run these before claiming the MCP driver is usable:

1. `codex mcp get deepseek-driver --json` shows the server enabled with the whitelist tools.
2. MCP `tools/list` returns exactly the expected tool names.
3. `docker_probe_torch` returns the PyTorch version for a known local image.
4. `deepseek_scan` succeeds on one safe allow-listed file and writes `artifacts/deepseek/<run-id>/deepseek-output.md`.
5. `deepseek_scan` with `.env` fails with a sensitive-path rejection.
6. `deepseek_patch` writes `deepseek-output.md` and, when DeepSeek emits a diff block, `patch.diff`.

## Known Codex CLI Boundary

In local validation with Codex CLI 0.125.0:

- Direct MCP protocol calls to the Dockerized server worked.
- `codex exec --dangerously-bypass-approvals-and-sandbox` could call `docker_list_images` and `docker_probe_torch`.
- `codex exec --sandbox read-only` and `codex exec --full-auto` could discover the MCP server but returned `user cancelled MCP tool call` for tool execution.
- A DeepSeek-profile outer `codex exec` session did not expose the expected MCP tool-call surface and should not be used as the MCP driver.

Practical rule: use the normal Codex/OpenAI driver for MCP orchestration, and call DeepSeek through the MCP tool backend. If non-interactive `codex exec` cancels MCP tools, document that as a Codex CLI approval boundary rather than falling back to arbitrary shell access.
