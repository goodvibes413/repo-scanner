# Repo Preflight

Repo Preflight helps you ask:

> "Can I install or run this GitHub repo on my computer without exposing my credentials, files, or agent setup?"

It is built for the common situation where someone shares an open-source AI or agent repo and the setup instructions ask you to run commands like `npm install`, add an MCP server, paste API keys into `.env`, or run a local dev server.

Repo Preflight does **not** say a repo is safe. It checks the repository source and visible install surface, then gives a conservative recommendation with evidence and limits.

## The Easiest Way To Use It

The best workflow is:

1. Set up Repo Preflight once in Codex or Claude.
2. Paste a GitHub repo link into Codex or Claude.
3. Ask: "Use Repo Preflight to check this before I install it."
4. Read the recommendation before running any install commands.

Example prompt:

```text
Use Repo Preflight to check this repo before I install it:
https://github.com/owner/repo

I would run npm install locally. I may have GITHUB_TOKEN, NPM_TOKEN, and OPENAI_API_KEY on this machine.
```

## Skill vs MCP

Repo Preflight has two parts:

- **Skill:** tells Codex or Claude when to use the scanner and how to explain the result.
- **MCP server:** gives Codex or Claude an actual tool that runs the scanner.

Use both.

The skill alone is not enough because it is only instructions. The MCP server is what actually inspects the repo and returns evidence.

## Set Up In Codex

Codex can discover the repo-local skill here:

```text
.agents/skills/check-repository-before-install/
```

To let Codex run the scanner as a tool, add this MCP server to your Codex config.

Open:

```text
~/.codex/config.toml
```

Add this, replacing `/absolute/path/to/repo-scanner` with the folder where this repo lives on your computer:

```toml
[mcp_servers.repo-preflight]
command = "python3"
args = ["-m", "repo_preflight.cli", "mcp"]
cwd = "/absolute/path/to/repo-scanner"

[mcp_servers.repo-preflight.env]
PYTHONPATH = "/absolute/path/to/repo-scanner/src"
```

Restart Codex. Then ask:

```text
Use Repo Preflight to check https://github.com/owner/repo before I install it.
```

If Codex says the tool is unavailable, restart Codex and check that the path in `cwd` and `PYTHONPATH` is the full path to this repo.

If Codex cannot find `python3`, replace `command = "python3"` with the full path to your Python 3 command.

## Set Up In Claude Desktop

Claude Desktop can use Repo Preflight through MCP.

1. Open Claude Desktop.
2. Open **Claude** > **Settings** from the macOS menu bar.
3. Go to **Developer**.
4. Click **Edit Config**.
5. Add this server config, replacing `/absolute/path/to/repo-scanner` with the folder where this repo lives on your computer:

```json
{
  "mcpServers": {
    "repo-preflight": {
      "command": "python3",
      "args": ["-m", "repo_preflight.cli", "mcp"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/repo-scanner/src"
      }
    }
  }
}
```

Save the file, fully quit Claude Desktop, and reopen it.

Then ask:

```text
Use Repo Preflight to check https://github.com/owner/repo before I install it.
```

Claude Desktop may show a connector/tool indicator in the chat box after restart. If it does not, check the config path and restart Claude Desktop again.

If Claude Desktop cannot start the server, it may not know where `python3` is. Replace `"command": "python3"` with the full path to your Python 3 command.

## Set Up In Claude Code

Claude Code can discover the repo-local skill here:

```text
.claude/skills/check-repository-before-install/
```

For MCP, run this once from the repo folder:

```bash
claude mcp add --transport stdio repo-preflight -- python3 -m repo_preflight.cli mcp
```

If Claude Code cannot find `repo_preflight`, use the Claude Desktop JSON approach above or install the project locally with the developer setup below.

## Optional: Install As A Local Command

You can install the `repo-preflight` command locally. This is useful if you are comfortable with Terminal, but it is not required for the Codex or Claude MCP setup above.

```bash
git clone https://github.com/goodvibes413/repo-scanner.git
cd repo-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Then run:

```bash
repo-preflight doctor
repo-preflight scan https://github.com/owner/repo
```

## What The Scanner Checks

Repo Preflight looks for high-signal install risks:

- npm install scripts like `preinstall`, `install`, `postinstall`, and `prepare`
- workspace package scripts
- suspicious install commands like `curl | bash`, `wget | sh`, `bun.sh/install`, `sudo`, `chmod +x`, or `eval`
- Shai-Hulud-style filenames like `setup_bun.js` and `bun_environment.js`
- lockfile packages that resolve from unexpected tarball URLs
- Docker privileged mode, Docker socket mounts, and home-directory mounts
- MCP configs that may give broad local access
- GitHub Actions workflows that combine secrets and network transfer commands
- credential-name references like `GITHUB_TOKEN`, `NPM_TOKEN`, and `OPENAI_API_KEY`
- best-effort OSV checks for versioned npm dependencies

The scanner does not install dependencies, run repo code, read your secrets, or run arbitrary shell commands.

## What The Verdicts Mean

Repo Preflight uses conservative verdicts:

- `DO_NOT_INSTALL`: strong evidence of known malicious code, credential theft, exfiltration, or destructive behavior.
- `TEST_ONLY_IN_ISOLATION`: install scripts, remote shell commands, suspicious dependency resolution, broad MCP access, or other risky install behavior.
- `LOWER_RISK_WITH_CONTROLS`: no known malicious indicators from supported checks, but your local credentials or files could still be exposed.
- `INSUFFICIENT_EVIDENCE`: the scan could not check enough to give useful guidance.
- `NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS`: no findings from supported checks, but this is not a guarantee.

## Install Context

Install context helps the scanner reason about what would be exposed if you ran the repo locally.

Only provide credential names, never secret values.

Good:

```text
I may have GITHUB_TOKEN, NPM_TOKEN, and OPENAI_API_KEY on this machine.
```

Bad:

```text
OPENAI_API_KEY=sk-...
```

You can also describe local resources:

```text
This machine has my home folder, GitHub CLI, Docker, and cloud CLI logged in.
```

## Current Limits

- Public GitHub repositories only.
- npm has the strongest coverage in this version.
- Python package checks are lightweight.
- Full transitive dependency execution is not resolved.
- OSV dependency intelligence requires network access and can be unavailable.
- Newly compromised packages may not be reflected in public feeds yet.
- Dynamic sandboxing is not implemented.
- Private registries and private repositories are not supported.

## Developer Commands

Run the no-dependency test suite:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/run_tests.py
```

Run a local smoke test:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m repo_preflight.cli doctor
```

## Security Model

Repo Preflight treats repository content as untrusted input. It reads files and metadata, but does not execute repository code. Findings are decision support, not a guarantee.
