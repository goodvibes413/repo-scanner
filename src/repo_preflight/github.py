from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from repo_preflight.models import RepoMetadata, SourceStatus


GITHUB_RE = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?(?:[?#].*)?$")


def parse_github_url(url: str) -> tuple[str, str] | None:
    match = GITHUB_RE.match(url)
    if not match:
        return None
    return match.group(1), match.group(2)


@contextmanager
def materialize_repository(repo_url: str, ref: str | None = None) -> Iterator[tuple[Path, RepoMetadata, list[SourceStatus]]]:
    statuses: list[SourceStatus] = []
    metadata = RepoMetadata(url=repo_url)
    local_path = local_repo_path(repo_url)
    if local_path:
        metadata.url = str(local_path)
        metadata.default_branch = git_output(local_path, ["rev-parse", "--abbrev-ref", "HEAD"])
        metadata.latest_commit_sha = git_output(local_path, ["rev-parse", "HEAD"])
        metadata.latest_commit_date = git_output(local_path, ["log", "-1", "--format=%cI"])
        statuses.append(SourceStatus("repository", "available", "Scanned local repository path."))
        yield local_path, metadata, statuses
        return

    parsed = parse_github_url(repo_url)
    if not parsed:
        statuses.append(SourceStatus("repository", "failed", "Input is not a supported public GitHub URL or local path."))
        yield Path(), metadata, statuses
        return

    owner, repo = parsed
    metadata = fetch_github_metadata(owner, repo, repo_url, statuses)
    with tempfile.TemporaryDirectory(prefix="repo-preflight-") as tmp:
        target = Path(tmp) / "repo"
        clone_cmd = ["git", "clone", "--depth", "1"]
        if ref:
            clone_cmd.extend(["--branch", ref])
        clone_cmd.extend([repo_url, str(target)])
        try:
            subprocess.run(clone_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            statuses.append(SourceStatus("repository", "available", "Repository cloned without executing repository code."))
            metadata.latest_commit_sha = git_output(target, ["rev-parse", "HEAD"]) or metadata.latest_commit_sha
            metadata.latest_commit_date = git_output(target, ["log", "-1", "--format=%cI"]) or metadata.latest_commit_date
            metadata.default_branch = metadata.default_branch or git_output(target, ["rev-parse", "--abbrev-ref", "HEAD"])
            yield target, metadata, statuses
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            statuses.append(SourceStatus("repository", "failed", f"Clone failed: {detail.strip()[:240]}"))
            yield Path(), metadata, statuses


def local_repo_path(value: str) -> Path | None:
    if value.startswith("file://"):
        path = Path(value[7:]).expanduser()
    else:
        path = Path(value).expanduser()
    if path.exists() and path.is_dir():
        return path.resolve()
    return None


def fetch_github_metadata(owner: str, repo: str, repo_url: str, statuses: list[SourceStatus]) -> RepoMetadata:
    metadata = RepoMetadata(url=repo_url)
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "repo-preflight"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
        metadata.default_branch = payload.get("default_branch")
        metadata.created_at = payload.get("created_at")
        metadata.stars = payload.get("stargazers_count")
        metadata.forks = payload.get("forks_count")
        metadata.open_issues = payload.get("open_issues_count")
        statuses.append(SourceStatus("github_metadata", "available", "GitHub repository metadata fetched."))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        statuses.append(SourceStatus("github_metadata", "unavailable", f"GitHub metadata unavailable: {exc}"))
    metadata.contributor_count = fetch_contributor_count(owner, repo, statuses)
    return metadata


def fetch_contributor_count(owner: str, repo: str, statuses: list[SourceStatus]) -> int | None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=1&anon=true",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "repo-preflight"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            link = response.headers.get("Link", "")
            if 'rel="last"' in link:
                match = re.search(r"[?&]page=(\d+)>; rel=\"last\"", link)
                if match:
                    return int(match.group(1))
            payload = json.loads(response.read().decode("utf-8"))
            return len(payload) if isinstance(payload, list) else None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        statuses.append(SourceStatus("github_contributors", "unavailable", "Contributor count unavailable."))
        return None


def git_output(path: Path, args: list[str]) -> str | None:
    if not shutil.which("git"):
        return None
    try:
        result = subprocess.run(["git", *args], cwd=path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        return result.stdout.strip() or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
