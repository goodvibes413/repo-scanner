from __future__ import annotations

import json
from pathlib import Path

from repo_preflight.context import load_install_context
from repo_preflight.mcp_server import handle_request
from repo_preflight.models import Verdict, render_markdown
from repo_preflight.scanner import scan_repository


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_flags_root_postinstall(tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({"scripts": {"postinstall": "node setup_bun.js"}}))

    report = scan_repository(str(tmp_path), osv_enabled=False)

    assert report.verdict == Verdict.TEST_ONLY_IN_ISOLATION
    assert any(finding.id == "npm-lifecycle-postinstall" for finding in report.findings)


def test_flags_workspace_postinstall(tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({"workspaces": ["packages/*"]}))
    write(tmp_path / "packages" / "tool" / "package.json", json.dumps({"scripts": {"postinstall": "node index.js"}}))

    report = scan_repository(str(tmp_path), osv_enabled=False)

    assert report.verdict == Verdict.TEST_ONLY_IN_ISOLATION
    assert any(finding.location and finding.location.path == "packages/tool/package.json" for finding in report.findings)


def test_flags_curl_bash_and_bun_install(tmp_path: Path) -> None:
    write(tmp_path / "README.md", "Install with: curl -fsSL https://bun.sh/install | bash\n")

    report = scan_repository(str(tmp_path), osv_enabled=False)

    ids = {finding.id for finding in report.findings}
    assert "doc-command-remote-shell-curl" in ids
    assert "doc-command-bun-install" in ids


def test_flags_suspicious_shai_hulud_filenames(tmp_path: Path) -> None:
    write(tmp_path / "setup_bun.js", "console.log('install')\n")
    write(tmp_path / "bun_environment.js", "console.log('env')\n")

    report = scan_repository(str(tmp_path), osv_enabled=False)

    titles = {finding.title for finding in report.findings}
    assert "Suspicious package file `setup_bun.js` found" in titles
    assert "Suspicious package file `bun_environment.js` found" in titles


def test_flags_unexpected_lockfile_tarball_url(tmp_path: Path) -> None:
    write(
        tmp_path / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "node_modules/example": {
                        "version": "1.2.3",
                        "resolved": "https://evil.example/example-1.2.3.tgz",
                    }
                }
            }
        ),
    )

    report = scan_repository(str(tmp_path), osv_enabled=False)

    assert report.verdict == Verdict.TEST_ONLY_IN_ISOLATION
    assert any(finding.id == "npm-lockfile-unexpected-tarball-url" for finding in report.findings)


def test_osv_unavailable_degrades_dependency_claim(monkeypatch, tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
    write(
        tmp_path / "package-lock.json",
        json.dumps({"packages": {"node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}),
    )

    def fake_query_osv(dependencies, enabled=True):
        from repo_preflight.models import SourceStatus

        return [], SourceStatus("osv", "unavailable", "test outage")

    monkeypatch.setattr("repo_preflight.scanner.query_osv", fake_query_osv)

    report = scan_repository(str(tmp_path), osv_enabled=True)

    assert report.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert any(status.name == "osv" and status.status == "unavailable" for status in report.source_statuses)


def test_report_distinguishes_boundaries_and_avoids_forbidden_words(tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({}))

    report = scan_repository(str(tmp_path), osv_enabled=False)
    markdown = render_markdown(report)

    assert "Repository source checked" in markdown
    assert "No dependency code was executed" in markdown
    for forbidden in ("safe", "clean", "trusted"):
        assert forbidden not in markdown.lower()


def test_install_context_uses_names_only(tmp_path: Path) -> None:
    context_path = tmp_path / "install-context.yaml"
    write(
        context_path,
        """
intended_command: "npm install"
credential_names:
  - GITHUB_TOKEN
  - OPENAI_API_KEY
local_resources:
  - home_directory
  - docker_socket
""",
    )
    write(tmp_path / "package.json", json.dumps({}))

    context = load_install_context(context_path)
    report = scan_repository(str(tmp_path), context=context, osv_enabled=False)

    assert report.verdict == Verdict.LOWER_RISK_WITH_CONTROLS
    assert any("GITHUB_TOKEN" in finding.evidence for finding in report.findings)


def test_mcp_scan_matches_cli_function(tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({"scripts": {"postinstall": "node setup_bun.js"}}))

    direct = scan_repository(str(tmp_path), osv_enabled=False)
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scan_repository",
                "arguments": {"repo_url": str(tmp_path), "osv_enabled": False},
            },
        }
    )

    assert response is not None
    structured = response["result"]["structuredContent"]
    assert structured["verdict"] == direct.verdict.value
