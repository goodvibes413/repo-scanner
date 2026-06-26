from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from repo_preflight.models import Finding, Location, Severity, SourceStatus


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    source: str


def query_osv(dependencies: list[Dependency], enabled: bool = True) -> tuple[list[Finding], SourceStatus]:
    versioned = [dep for dep in dependencies if dep.version and dep.ecosystem == "npm"]
    if not versioned:
        return [], SourceStatus("osv", "not_applicable", "No versioned npm dependencies found for OSV query.")
    if not enabled:
        return [], SourceStatus("osv", "skipped", "OSV query disabled by caller.")
    queries = [
        {"package": {"name": dep.name, "ecosystem": "npm"}, "version": dep.version}
        for dep in versioned[:500]
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "repo-preflight"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return [], SourceStatus("osv", "unavailable", f"OSV query failed: {exc}")

    findings: list[Finding] = []
    results = payload.get("results", [])
    dep_by_index = versioned[:500]
    for index, result in enumerate(results):
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if not vulns:
            continue
        dep = dep_by_index[index]
        for vuln in vulns:
            vuln_id = vuln.get("id", "unknown")
            summary = vuln.get("summary") or vuln.get("details") or "Known advisory matched this package version."
            findings.append(
                Finding(
                    id=f"osv-{vuln_id}",
                    title=f"Known advisory for {dep.name}@{dep.version}",
                    severity=Severity.CRITICAL,
                    category="Dependency advisory",
                    description=summary[:500],
                    evidence=f"{dep.name}@{dep.version} matched {vuln_id}",
                    location=Location(dep.source),
                    recommendation="Do not install this dependency version until the advisory is reviewed and remediated.",
                )
            )
    return findings, SourceStatus("osv", "available", f"Queried OSV for {len(versioned[:500])} npm dependencies.")
