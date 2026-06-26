from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    DO_NOT_INSTALL = "DO_NOT_INSTALL"
    TEST_ONLY_IN_ISOLATION = "TEST_ONLY_IN_ISOLATION"
    LOWER_RISK_WITH_CONTROLS = "LOWER_RISK_WITH_CONTROLS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS = "NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    location: Location | None = None
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location.to_dict() if self.location else None,
            "recommendation": self.recommendation,
        }


@dataclass
class SourceStatus:
    name: str
    status: str
    detail: str
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "checked_at": self.checked_at,
        }


@dataclass
class RepoMetadata:
    url: str
    default_branch: str | None = None
    latest_commit_sha: str | None = None
    latest_commit_date: str | None = None
    created_at: str | None = None
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    contributor_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "default_branch": self.default_branch,
            "latest_commit_sha": self.latest_commit_sha,
            "latest_commit_date": self.latest_commit_date,
            "created_at": self.created_at,
            "stars": self.stars,
            "forks": self.forks,
            "open_issues": self.open_issues,
            "contributor_count": self.contributor_count,
        }


@dataclass
class InstallContext:
    intended_command: str | None = None
    runtime: str | None = None
    operating_system: str | None = None
    credential_names: list[str] = field(default_factory=list)
    local_resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intended_command": self.intended_command,
            "runtime": self.runtime,
            "operating_system": self.operating_system,
            "credential_names": self.credential_names,
            "local_resources": self.local_resources,
        }


@dataclass
class ScanReport:
    verdict: Verdict
    repo: RepoMetadata
    scan_timestamp: str
    scanner_version: str
    boundaries: list[str]
    findings: list[Finding]
    source_statuses: list[SourceStatus]
    limitations: list[str]
    recommended_controls: list[str]
    install_context: InstallContext | None = None
    report_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "repo": self.repo.to_dict(),
            "scan_timestamp": self.scan_timestamp,
            "scanner_version": self.scanner_version,
            "boundaries": self.boundaries,
            "findings": [finding.to_dict() for finding in self.findings],
            "source_statuses": [status.to_dict() for status in self.source_statuses],
            "limitations": self.limitations,
            "recommended_controls": self.recommended_controls,
            "install_context": self.install_context.to_dict() if self.install_context else None,
            "report_path": self.report_path,
        }

    def write_markdown(self, path: Path) -> None:
        path.write_text(render_markdown(self), encoding="utf-8")
        self.report_path = str(path)


def render_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("# Repo Preflight Report")
    lines.append("")
    lines.append(f"**Verdict:** `{report.verdict.value}`")
    lines.append(f"**Repository:** {report.repo.url}")
    lines.append(f"**Commit:** `{report.repo.latest_commit_sha or 'unknown'}`")
    lines.append(f"**Default branch:** `{report.repo.default_branch or 'unknown'}`")
    lines.append(f"**Scanned at:** {report.scan_timestamp}")
    lines.append(f"**Scanner version:** {report.scanner_version}")
    lines.append("")
    lines.append("This scan checked repository source and the visible install surface. It may not detect newly compromised packages before public feeds or registry metadata reflect them.")
    lines.append("")
    lines.append("## Boundary")
    for boundary in report.boundaries:
        lines.append(f"- {boundary}")
    lines.append("")
    if report.install_context:
        lines.append("## Install Context")
        ctx = report.install_context
        lines.append(f"- Intended command: `{ctx.intended_command or 'not provided'}`")
        lines.append(f"- Runtime: `{ctx.runtime or 'not provided'}`")
        lines.append(f"- Operating system: `{ctx.operating_system or 'not provided'}`")
        if ctx.credential_names:
            lines.append(f"- Credential names: {', '.join(f'`{name}`' for name in ctx.credential_names)}")
        if ctx.local_resources:
            lines.append(f"- Local resources: {', '.join(f'`{name}`' for name in ctx.local_resources)}")
        lines.append("")
    lines.append("## Findings")
    if not report.findings:
        lines.append("- No findings were produced by the supported checks.")
    else:
        for finding in report.findings:
            location = ""
            if finding.location:
                location = f" ({finding.location.path}"
                if finding.location.line:
                    location += f":{finding.location.line}"
                location += ")"
            lines.append(f"- **{finding.severity.value.upper()}** `{finding.category}`: {finding.title}{location}")
            lines.append(f"  - Evidence: `{finding.evidence}`")
            lines.append(f"  - Recommendation: {finding.recommendation or 'Review before installing or running.'}")
    lines.append("")
    lines.append("## Source Status")
    for status in report.source_statuses:
        lines.append(f"- `{status.name}`: {status.status} - {status.detail}")
    lines.append("")
    lines.append("## Recommended Controls")
    for control in report.recommended_controls:
        lines.append(f"- {control}")
    lines.append("")
    lines.append("## Limitations")
    for limitation in report.limitations:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)
