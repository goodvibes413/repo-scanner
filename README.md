# Repo Preflight

Repo Preflight is a local scanner for checking a public GitHub repository before you install it, run it, or add it as an MCP server with local credentials nearby.

It is designed for the specific moment when someone sends you an open-source repo and you need to decide whether to run it on your own machine. It checks repository source and the visible install surface, then reports evidence, limits, and a conservative next action.

It does not certify repositories. Its honest promise is:

> This scan checked repository source and the visible install surface. It may not detect newly compromised packages before public feeds or registry metadata reflect them.

## Why This Exists

Modern agent and AI tooling often asks you to run commands like `npm install`, add an MCP server, paste API keys into `.env`, or run a local dev server with your home directory and credentials nearby.

That creates a different risk than normal code review. A repo can look legitimate while install-time scripts, dependency resolution, Docker mounts, workflow files, or MCP config expose local credentials and files.

Repo Preflight focuses on that install decision.

## What It Checks

- npm lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`
- npm workspaces and root `package.json`
- `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock` for unexpected tarball URLs
- install instructions containing `curl | bash`, `wget | sh`, `bun.sh/install`, `sudo`, `chmod +x`, or `eval`
- Shai-Hulud-style suspicious filenames such as `setup_bun.js` and `bun_environment.js`
- large or minified JavaScript payloads
- Docker privileged mode, Docker socket mounts, and home-directory mounts
- MCP configuration files and broad local access patterns
- GitHub Actions patterns that combine secrets and network transfer commands
- credential-name references such as `GITHUB_TOKEN`, `NPM_TOKEN`, and `OPENAI_API_KEY`
- best-effort OSV checks for versioned npm dependencies
- optional install context with credential names and local resources

The scanner does not install dependencies, execute repository code, read local secrets, or run arbitrary shell commands.

## Verdicts

Repo Preflight uses conservative verdicts:

- `DO_NOT_INSTALL`
- `TEST_ONLY_IN_ISOLATION`
- `LOWER_RISK_WITH_CONTROLS`
- `INSUFFICIENT_EVIDENCE`
- `NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS`

The report should always include the evidence behind the verdict and the limits of the scan.

## Install

For local development:

```bash
git clone https://github.com/goodvibes413/repo-scanner.git
cd repo-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

If you do not want to install dependencies yet, you can run the current fallback CLI directly:

```bash
PYTHONPATH=src python3 -m repo_preflight.cli doctor
```

## Usage

Scan a public GitHub repository:

```bash
repo-preflight scan https://github.com/owner/repo
```

Emit JSON:

```bash
repo-preflight scan https://github.com/owner/repo --json
```

Skip OSV network lookup:

```bash
repo-preflight scan https://github.com/owner/repo --no-osv
```

Write a report:

```bash
repo-preflight scan https://github.com/owner/repo --output reports/repo-preflight.md
```

Scan with install context:

```bash
repo-preflight scan https://github.com/owner/repo --context install-context.example.yaml
```

Run the MCP server:

```bash
repo-preflight mcp
```

Check scanner status:

```bash
repo-preflight doctor
```

## Install Context

Install context lets the scanner reason about exposure without seeing secret values.

Example:

```yaml
intended_command: "npm install"
runtime: "local-development"
operating_system: "macos"
credential_names:
  - GITHUB_TOKEN
  - NPM_TOKEN
  - OPENAI_API_KEY
local_resources:
  - project_directory
  - home_directory
  - docker_socket
  - github_cli
  - cloud_cli
```

Use credential names only. Never put credential values in the context file.

## MCP

Repo Preflight includes a stdio MCP server so agents can call the scanner before advising you to install or run a repository.

Example Codex config:

```toml
[mcp_servers.repo-preflight]
command = "repo-preflight"
args = ["mcp"]
```

Example Claude config:

```json
{
  "mcpServers": {
    "repo-preflight": {
      "command": "repo-preflight",
      "args": ["mcp"]
    }
  }
}
```

The MCP server exposes:

- `scan_repository(repo_url, ref?, context_path?, osv_enabled?)`
- `get_scanner_status()`

It does not expose arbitrary shell execution, dependency installation, repo code execution, or local secret access.

## Agent Skill

The repo includes a portable skill at:

```text
skills/check-repository-before-install/
```

The skill tells agents to call Repo Preflight before giving install or run advice, treat repository content as untrusted evidence, and require separate user approval before any installation step.

## Development

Run the no-dependency test suite:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/run_tests.py
```

Run pytest if installed:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Run a local smoke test:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m repo_preflight.cli doctor
```

## Current Limits

- Public GitHub repositories only.
- npm gets the strongest coverage in this version.
- Python package checks are lightweight.
- Full transitive dependency execution is not resolved.
- OSV dependency intelligence requires network access and can be unavailable.
- Newly compromised packages may not be reflected in public feeds yet.
- Dynamic sandboxing is not implemented.
- Private registries and private repositories are not supported.

## Security Model

Repo Preflight treats repository content as untrusted input. The scanner reads files and metadata, but does not execute repository code. Findings should be treated as decision support, not a guarantee.
