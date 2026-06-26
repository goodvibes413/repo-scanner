from __future__ import annotations

import fnmatch
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repo_preflight import __version__
from repo_preflight.github import materialize_repository
from repo_preflight.models import Finding, InstallContext, Location, RepoMetadata, ScanReport, Severity, SourceStatus, Verdict
from repo_preflight.osv import Dependency, query_osv


INSTALL_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
SUSPICIOUS_FILENAMES = {"setup_bun.js", "bun_environment.js", "bundle.js"}
EXPECTED_NPM_REGISTRY_PREFIXES = (
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com/",
)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}


COMMAND_PATTERNS: list[tuple[str, re.Pattern[str], str, Severity]] = [
    ("remote-shell-curl", re.compile(r"curl\b[^\n|]*(?:\|\s*(?:bash|sh|zsh)|\|\s*sudo\s+(?:bash|sh))", re.I), "Remote shell execution via curl", Severity.HIGH),
    ("remote-shell-wget", re.compile(r"wget\b[^\n|]*(?:\|\s*(?:bash|sh|zsh)|\|\s*sudo\s+(?:bash|sh))", re.I), "Remote shell execution via wget", Severity.HIGH),
    ("bun-install", re.compile(r"bun\.sh/install|curl\b[^\n]*bun\.sh", re.I), "Bun installer fetched during setup", Severity.HIGH),
    ("sudo-command", re.compile(r"\bsudo\s+", re.I), "Install instructions request sudo", Severity.MEDIUM),
    ("chmod-execute", re.compile(r"\bchmod\s+\+x\b", re.I), "Install instructions make downloaded code executable", Severity.MEDIUM),
    ("eval-command", re.compile(r"\beval\s+[`$(]", re.I), "Install instructions evaluate generated shell text", Severity.HIGH),
]

SECRET_NAME_PATTERN = re.compile(
    r"\b("
    r"API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|SECRET|PRIVATE[_-]?KEY|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_APPLICATION_CREDENTIALS"
    r")\b",
    re.I,
)


def scan_repository(repo_url: str, ref: str | None = None, context: InstallContext | None = None, osv_enabled: bool = True) -> ScanReport:
    findings: list[Finding] = []
    source_statuses: list[SourceStatus] = []
    repo_metadata = RepoMetadata(url=repo_url)
    dependencies: list[Dependency] = []
    package_dependency_seen = False
    lockfile_seen = False

    with materialize_repository(repo_url, ref=ref) as (repo_path, metadata, materialize_statuses):
        repo_metadata = metadata
        source_statuses.extend(materialize_statuses)
        if not repo_path.exists():
            return build_report(
                repo_metadata,
                findings,
                source_statuses,
                context,
                force_verdict=Verdict.INSUFFICIENT_EVIDENCE,
            )

        npm_result = scan_npm_surface(repo_path)
        findings.extend(npm_result.findings)
        dependencies.extend(npm_result.dependencies)
        package_dependency_seen = npm_result.package_dependency_seen
        lockfile_seen = npm_result.lockfile_seen

        findings.extend(scan_docs_for_install_commands(repo_path))
        findings.extend(scan_suspicious_files(repo_path))
        findings.extend(scan_credential_references(repo_path))
        findings.extend(scan_docker_risks(repo_path))
        findings.extend(scan_mcp_configs(repo_path))
        findings.extend(scan_github_actions(repo_path))
        findings.extend(scan_python_surface(repo_path))
        findings.extend(scan_install_context(context))

        osv_findings, osv_status = query_osv(dependencies, enabled=osv_enabled)
        findings.extend(osv_findings)
        source_statuses.append(osv_status)

        if package_dependency_seen and not lockfile_seen:
            source_statuses.append(SourceStatus("npm_lockfile", "missing", "package.json dependencies were found, but no npm lockfile was found. Full install resolution was not checked."))

    report = build_report(repo_metadata, findings, source_statuses, context)
    return report


class NpmScanResult:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.dependencies: list[Dependency] = []
        self.package_dependency_seen = False
        self.lockfile_seen = False


def scan_npm_surface(repo_path: Path) -> NpmScanResult:
    result = NpmScanResult()
    package_json_paths = sorted(find_files(repo_path, "package.json"))
    workspace_paths: set[Path] = set()
    for package_path in package_json_paths:
        data = read_json(package_path)
        if not isinstance(data, dict):
            result.findings.append(
                Finding(
                    id="npm-invalid-package-json",
                    title="package.json could not be parsed",
                    severity=Severity.MEDIUM,
                    category="Repository source risk",
                    description="A package manifest exists but could not be parsed as JSON.",
                    evidence=relative(repo_path, package_path),
                    location=Location(relative(repo_path, package_path)),
                    recommendation="Review the manifest manually before running package-manager commands.",
                )
            )
            continue
        result.findings.extend(scan_package_scripts(repo_path, package_path, data))
        deps = collect_declared_dependencies(data)
        if deps:
            result.package_dependency_seen = True
        for name, version in deps.items():
            result.dependencies.append(Dependency(name=name, version=clean_semver(version), ecosystem="npm", source=relative(repo_path, package_path)))
        workspace_paths.update(resolve_workspace_packages(repo_path, package_path, data))

    for workspace_path in sorted(workspace_paths):
        if workspace_path not in package_json_paths and workspace_path.exists():
            data = read_json(workspace_path)
            if isinstance(data, dict):
                result.findings.extend(scan_package_scripts(repo_path, workspace_path, data))

    lock_paths = [
        *find_files(repo_path, "package-lock.json"),
        *find_files(repo_path, "npm-shrinkwrap.json"),
        *find_files(repo_path, "pnpm-lock.yaml"),
        *find_files(repo_path, "yarn.lock"),
    ]
    if lock_paths:
        result.lockfile_seen = True
    for lock_path in sorted(lock_paths):
        result.findings.extend(scan_lockfile_urls(repo_path, lock_path))
        result.dependencies.extend(collect_lockfile_dependencies(repo_path, lock_path))
    return result


def scan_package_scripts(repo_path: Path, package_path: Path, data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings
    for script_name in sorted(INSTALL_LIFECYCLE_SCRIPTS):
        value = scripts.get(script_name)
        if not isinstance(value, str):
            continue
        findings.append(
            Finding(
                id=f"npm-lifecycle-{script_name}",
                title=f"npm lifecycle script `{script_name}` runs during install",
                severity=Severity.HIGH,
                category="Install-time execution risk",
                description="npm lifecycle scripts can execute automatically during package installation.",
                evidence=value[:300],
                location=Location(relative(repo_path, package_path), find_line(package_path, f'"{script_name}"')),
                recommendation="Do not run package installation on a machine with valuable credentials or broad filesystem access until this script is reviewed.",
            )
        )
        findings.extend(scan_text_patterns(repo_path, package_path, value, category="Install-time execution risk", base_id=f"npm-script-{script_name}"))
    return findings


def collect_declared_dependencies(data: dict[str, Any]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            for name, version in value.items():
                if isinstance(name, str) and isinstance(version, str):
                    deps[name] = version
    return deps


def resolve_workspace_packages(repo_path: Path, package_path: Path, data: dict[str, Any]) -> set[Path]:
    workspaces = data.get("workspaces")
    patterns: list[str] = []
    if isinstance(workspaces, list):
        patterns = [item for item in workspaces if isinstance(item, str)]
    elif isinstance(workspaces, dict) and isinstance(workspaces.get("packages"), list):
        patterns = [item for item in workspaces["packages"] if isinstance(item, str)]
    base = package_path.parent
    paths: set[Path] = set()
    for pattern in patterns:
        for candidate in base.glob(pattern):
            pkg = candidate / "package.json"
            try:
                pkg.resolve().relative_to(repo_path.resolve())
            except ValueError:
                continue
            if pkg.exists():
                paths.add(pkg)
    return paths


def scan_docs_for_install_commands(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    patterns = ("README*", "docs/**/*.md", "*.md", "*.rst", "*.txt")
    seen: set[Path] = set()
    for pattern in patterns:
        for path in repo_path.glob(pattern):
            if path in seen or not path.is_file() or should_skip(path):
                continue
            seen.add(path)
            text = read_text(path)
            findings.extend(scan_text_patterns(repo_path, path, text, category="Install-time execution risk", base_id="doc-command"))
    return findings


def scan_text_patterns(repo_path: Path, path: Path, text: str, category: str, base_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern_id, pattern, title, severity in COMMAND_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        findings.append(
            Finding(
                id=f"{base_id}-{pattern_id}",
                title=title,
                severity=severity,
                category=category,
                description="Installation or setup text contains a command pattern that can execute remote or elevated code.",
                evidence=match.group(0)[:300],
                location=Location(relative(repo_path, path), line_for_offset(text, match.start())),
                recommendation="Review the command manually and run only in an isolated environment with temporary credentials.",
            )
        )
    return findings


def scan_suspicious_files(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_repo_files(repo_path):
        name = path.name
        rel = relative(repo_path, path)
        if name in SUSPICIOUS_FILENAMES:
            findings.append(
                Finding(
                    id=f"suspicious-file-{name}",
                    title=f"Suspicious package file `{name}` found",
                    severity=Severity.HIGH if name != "bundle.js" else Severity.MEDIUM,
                    category="Install-time execution risk",
                    description="This filename has appeared in install-time malware patterns or opaque package payloads.",
                    evidence=rel,
                    location=Location(rel),
                    recommendation="Inspect this file before installing dependencies or running package scripts.",
                )
            )
        if path.suffix == ".js" and is_probably_minified_or_obfuscated(path):
            findings.append(
                Finding(
                    id="suspicious-js-obfuscation",
                    title="Large or minified JavaScript payload",
                    severity=Severity.MEDIUM,
                    category="Repository source risk",
                    description="Large single-line or heavily minified JavaScript can hide install-time behavior.",
                    evidence=rel,
                    location=Location(rel),
                    recommendation="Review why this generated payload is committed and whether it runs during install or startup.",
                )
            )
    return findings


def scan_credential_references(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_repo_files(repo_path):
        if path.stat().st_size > 512_000 or path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}:
            continue
        text = read_text(path)
        match = SECRET_NAME_PATTERN.search(text)
        if not match:
            continue
        severity = Severity.MEDIUM if path.name in {".env", ".env.local"} else Severity.LOW
        findings.append(
            Finding(
                id="credential-name-reference",
                title="Credential name referenced in repository",
                severity=severity,
                category="Credential exposure",
                description="The repository references credential names. This does not prove a secret value is present.",
                evidence=match.group(0),
                location=Location(relative(repo_path, path), line_for_offset(text, match.start())),
                recommendation="Use temporary scoped credentials if this project needs environment variables.",
            )
        )
    return findings


def scan_docker_risks(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    docker_candidates = [path for path in iter_repo_files(repo_path) if path.name == "Dockerfile" or fnmatch.fnmatch(path.name, "docker-compose*.yml") or fnmatch.fnmatch(path.name, "docker-compose*.yaml")]
    patterns = [
        ("docker-privileged", re.compile(r"privileged:\s*true|--privileged", re.I), "Docker privileged mode requested", Severity.HIGH),
        ("docker-socket", re.compile(r"/var/run/docker\.sock", re.I), "Docker socket mounted", Severity.HIGH),
        ("docker-home-mount", re.compile(r"(?:(?:~|\$HOME|/Users/[^:\s]+|/home/[^:\s]+):/|source:\s*(?:~|\$HOME|/Users/|/home/))", re.I), "Home directory mount detected", Severity.MEDIUM),
    ]
    for path in docker_candidates:
        text = read_text(path)
        for finding_id, pattern, title, severity in patterns:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        id=finding_id,
                        title=title,
                        severity=severity,
                        category="Install-time execution risk",
                        description="Docker configuration may grant repository code broad local access.",
                        evidence=match.group(0)[:300],
                        location=Location(relative(repo_path, path), line_for_offset(text, match.start())),
                        recommendation="Do not run this Docker setup with host credentials or the Docker socket mounted unless you understand the access granted.",
                    )
                )
    return findings


def scan_mcp_configs(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_repo_files(repo_path):
        if not (path.name in {"mcp.json", "claude_desktop_config.json"} or ".mcp" in path.parts or path.match("**/.cursor/mcp.json")):
            continue
        text = read_text(path)
        broad_access = re.search(r"(/Users/|/home/|~|\$HOME|--allow|--filesystem|--dangerously|--yes|npx\s+-y)", text, re.I)
        severity = Severity.HIGH if broad_access else Severity.MEDIUM
        findings.append(
            Finding(
                id="mcp-config-present",
                title="MCP configuration found",
                severity=severity,
                category="Install-time execution risk",
                description="MCP servers can expose local tools, files, network calls, or credentials to an agent workflow.",
                evidence=(broad_access.group(0) if broad_access else relative(repo_path, path))[:300],
                location=Location(relative(repo_path, path), line_for_offset(text, broad_access.start()) if broad_access else None),
                recommendation="Review the MCP command and permissions before adding it to an agent client.",
            )
        )
    return findings


def scan_github_actions(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = repo_path / ".github" / "workflows"
    if not workflows.exists():
        return findings
    for path in workflows.glob("*.y*ml"):
        text = read_text(path)
        if re.search(r"secrets\.[A-Z0-9_]+", text) and re.search(r"\b(curl|wget|Invoke-WebRequest|nc|netcat)\b", text, re.I):
            findings.append(
                Finding(
                    id="github-actions-secret-network",
                    title="GitHub Actions workflow combines secrets and network commands",
                    severity=Severity.HIGH,
                    category="Repository source risk",
                    description="A workflow references GitHub secrets and network transfer commands, which can be legitimate or exfiltration-prone.",
                    evidence=relative(repo_path, path),
                    location=Location(relative(repo_path, path)),
                    recommendation="Review the workflow before granting repository secrets or running it in a fork.",
                )
            )
        if re.search(r"base64\s+-d\s*\|\s*(bash|sh)|bash\s+-i|/dev/tcp/", text, re.I):
            findings.append(
                Finding(
                    id="github-actions-obfuscated-shell",
                    title="GitHub Actions workflow contains suspicious shell execution",
                    severity=Severity.CRITICAL,
                    category="Repository source risk",
                    description="The workflow contains shell patterns often used for hidden execution or reverse shells.",
                    evidence=relative(repo_path, path),
                    location=Location(relative(repo_path, path)),
                    recommendation="Do not run this workflow until reviewed.",
                )
            )
    return findings


def scan_python_surface(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for filename in ("setup.py", "pyproject.toml", "requirements.txt"):
        for path in find_files(repo_path, filename):
            text = read_text(path)
            findings.extend(scan_text_patterns(repo_path, path, text, category="Install-time execution risk", base_id="python-install"))
            if path.name == "setup.py" and re.search(r"\b(os\.system|subprocess\.|requests\.get|urllib\.request)", text):
                findings.append(
                    Finding(
                        id="python-setup-exec-risk",
                        title="setup.py contains execution or network primitives",
                        severity=Severity.MEDIUM,
                        category="Install-time execution risk",
                        description="Python setup files can run during installation and this one references execution or network APIs.",
                        evidence=relative(repo_path, path),
                        location=Location(relative(repo_path, path)),
                        recommendation="Review setup.py before installing this package.",
                    )
                )
    return findings


def scan_install_context(context: InstallContext | None) -> list[Finding]:
    if not context:
        return []
    findings: list[Finding] = []
    if context.credential_names:
        findings.append(
            Finding(
                id="install-context-credentials",
                title="Credentials may be reachable during local install",
                severity=Severity.MEDIUM,
                category="Install context",
                description="The provided install context says credential names may be present in the local environment.",
                evidence=", ".join(context.credential_names),
                recommendation="Use temporary scoped credentials and unset unrelated environment variables before installation.",
            )
        )
    risky_resources = {"home_directory", "docker_socket", "cloud_cli", "github_cli", "ssh_keys", "npm_token"}
    exposed = [resource for resource in context.local_resources if resource in risky_resources]
    if exposed:
        findings.append(
            Finding(
                id="install-context-local-resources",
                title="Sensitive local resources may be reachable",
                severity=Severity.MEDIUM,
                category="Install context",
                description="The provided install context includes local resources that can increase install impact.",
                evidence=", ".join(exposed),
                recommendation="Use an isolated environment without host mounts, Docker socket, cloud CLI sessions, or long-lived tokens.",
            )
        )
    return findings


def scan_lockfile_urls(repo_path: Path, lock_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if lock_path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = read_json(lock_path)
        if isinstance(data, dict):
            for package_name, package_data in iter_package_lock_packages(data):
                resolved = package_data.get("resolved") if isinstance(package_data, dict) else None
                if isinstance(resolved, str) and suspicious_tarball_url(resolved):
                    findings.append(lockfile_url_finding(repo_path, lock_path, resolved, package_name))
    else:
        text = read_text(lock_path)
        for match in re.finditer(r"https?://[^\s\"']+", text):
            url = match.group(0).rstrip(",")
            if suspicious_tarball_url(url):
                findings.append(lockfile_url_finding(repo_path, lock_path, url, "lockfile entry", line_for_offset(text, match.start())))
    return findings


def lockfile_url_finding(repo_path: Path, lock_path: Path, url: str, package_name: str, line: int | None = None) -> Finding:
    return Finding(
        id="npm-lockfile-unexpected-tarball-url",
        title="Lockfile resolves package from unexpected URL",
        severity=Severity.HIGH,
        category="Install-time execution risk",
        description="A lockfile package resolves outside the expected npm registry URLs.",
        evidence=f"{package_name}: {url[:300]}",
        location=Location(relative(repo_path, lock_path), line),
        recommendation="Review why dependency code is fetched from this URL before installing.",
    )


def suspicious_tarball_url(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        return False
    return not url.startswith(EXPECTED_NPM_REGISTRY_PREFIXES)


def collect_lockfile_dependencies(repo_path: Path, lock_path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    if lock_path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = read_json(lock_path)
        if isinstance(data, dict):
            for package_name, package_data in iter_package_lock_packages(data):
                version = package_data.get("version") if isinstance(package_data, dict) else None
                name = package_name.split("node_modules/")[-1] if "node_modules/" in package_name else package_name
                if isinstance(name, str) and name and isinstance(version, str):
                    deps.append(Dependency(name=name, version=version, ecosystem="npm", source=relative(repo_path, lock_path)))
    return deps


def iter_package_lock_packages(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    packages = data.get("packages")
    if isinstance(packages, dict):
        return [(name, value) for name, value in packages.items() if name and isinstance(value, dict)]
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        return [(name, value) for name, value in dependencies.items() if isinstance(value, dict)]
    return []


def build_report(
    repo: RepoMetadata,
    findings: list[Finding],
    source_statuses: list[SourceStatus],
    context: InstallContext | None,
    force_verdict: Verdict | None = None,
) -> ScanReport:
    verdict = force_verdict or choose_verdict(findings, source_statuses)
    return ScanReport(
        verdict=verdict,
        repo=repo,
        scan_timestamp=datetime.now(UTC).isoformat(),
        scanner_version=__version__,
        boundaries=[
            "Repository source checked",
            "Declared direct dependencies checked when package manifests were present",
            "Lockfile checked if present",
            "Transitive dependency execution not fully resolved",
            "No dependency code was executed",
        ],
        findings=sorted(findings, key=finding_sort_key),
        source_statuses=source_statuses,
        limitations=[
            "This scanner uses static inspection and does not execute repository code.",
            "Newly compromised packages may not be detected before public feeds or registry metadata reflect them.",
            "Dependency intelligence is best effort and currently focused on npm.",
            "Private repositories and authenticated package registries are not supported in this version.",
        ],
        recommended_controls=recommended_controls(verdict, findings, context),
        install_context=context,
    )


def choose_verdict(findings: list[Finding], source_statuses: list[SourceStatus]) -> Verdict:
    if any(finding.severity == Severity.CRITICAL for finding in findings):
        return Verdict.DO_NOT_INSTALL
    if any(status.name == "repository" and status.status == "failed" for status in source_statuses):
        return Verdict.INSUFFICIENT_EVIDENCE
    if any(finding.category == "Dependency advisory" for finding in findings):
        return Verdict.DO_NOT_INSTALL
    if any(finding.severity == Severity.HIGH or finding.category == "Install-time execution risk" for finding in findings):
        return Verdict.TEST_ONLY_IN_ISOLATION
    if any(status.status == "unavailable" and status.name == "osv" for status in source_statuses):
        return Verdict.INSUFFICIENT_EVIDENCE
    if any(status.status == "missing" and status.name == "npm_lockfile" for status in source_statuses):
        return Verdict.INSUFFICIENT_EVIDENCE
    if any(finding.category == "Install context" or finding.category == "Credential exposure" for finding in findings):
        return Verdict.LOWER_RISK_WITH_CONTROLS
    return Verdict.NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS


def recommended_controls(verdict: Verdict, findings: list[Finding], context: InstallContext | None) -> list[str]:
    controls = [
        "Use temporary scoped credentials for first run.",
        "Run first install in a disposable project directory or isolated VM/container.",
        "Avoid mounting the home directory or Docker socket into unreviewed code.",
    ]
    if verdict in {Verdict.DO_NOT_INSTALL, Verdict.TEST_ONLY_IN_ISOLATION}:
        controls.insert(0, "Do not install on your normal workstation with long-lived credentials available.")
    if context and context.credential_names:
        controls.append("Unset unrelated environment variables before install.")
    if any(finding.id.startswith("npm-lifecycle") for finding in findings):
        controls.append("Review npm lifecycle scripts before running package-manager install commands.")
    return controls


def finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return order[finding.severity], finding.category, finding.title


def find_files(root: Path, filename: str) -> list[Path]:
    return [path for path in iter_repo_files(root) if path.name == filename]


def iter_repo_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if should_skip(path):
            continue
        if path.is_file():
            files.append(path)
    return files


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def find_line(path: Path, needle: str) -> int | None:
    text = read_text(path)
    index = text.find(needle)
    if index == -1:
        return None
    return line_for_offset(text, index)


def line_for_offset(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def clean_semver(version: str) -> str | None:
    stripped = version.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", stripped):
        return stripped
    return None


def is_probably_minified_or_obfuscated(path: Path) -> bool:
    try:
        size = path.stat().st_size
        if size < 50_000:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    longest_line = max((len(line) for line in text.splitlines()), default=0)
    newline_count = text.count("\n")
    return longest_line > 8_000 or (size > 100_000 and newline_count < 20)
