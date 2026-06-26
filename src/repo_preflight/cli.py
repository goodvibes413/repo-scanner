from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from repo_preflight import __version__
from repo_preflight.context import load_install_context
from repo_preflight.mcp_server import run_mcp_server
from repo_preflight.models import render_markdown
from repo_preflight.scanner import scan_repository

try:
    import typer
except ModuleNotFoundError:  # pragma: no cover - exercised in this local environment.
    typer = None  # type: ignore[assignment]


def main() -> None:
    if typer is not None:
        build_typer_app()()
        return
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        run_scan(args)
    elif args.command == "mcp":
        run_mcp_server()
    elif args.command == "doctor":
        run_doctor()
    else:
        parser.print_help()
        raise SystemExit(1)


def build_typer_app():
    app = typer.Typer(help="Static repository install-surface preflight scanner.")

    @app.command()
    def scan(
        repo_url: str,
        ref: str | None = typer.Option(None, "--ref", help="Optional branch, tag, or commit-ish for git clone."),
        context: Path | None = typer.Option(None, "--context", help="Optional install-context YAML file."),
        json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of Markdown."),
        output: Path | None = typer.Option(None, "--output", help="Write report to this path instead of stdout."),
        no_osv: bool = typer.Option(False, "--no-osv", help="Skip best-effort OSV dependency lookup."),
    ) -> None:
        context_data = load_install_context(context)
        report = scan_repository(repo_url, ref=ref, context=context_data, osv_enabled=not no_osv)
        rendered = json.dumps(report.to_dict(), indent=2, sort_keys=True) if json_output else render_markdown(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered + "\n", encoding="utf-8")
        else:
            typer.echo(rendered)

    @app.command()
    def mcp() -> None:
        run_mcp_server()

    @app.command()
    def doctor() -> None:
        run_doctor()

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-preflight", description="Static repository install-surface preflight scanner.")
    parser.add_argument("--version", action="version", version=f"repo-preflight {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a public GitHub repository or local path.")
    scan_parser.add_argument("repo_url", help="Public GitHub URL or local path for fixture testing.")
    scan_parser.add_argument("--ref", help="Optional branch, tag, or commit-ish for git clone.")
    scan_parser.add_argument("--context", type=Path, help="Optional install-context YAML file.")
    scan_parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    scan_parser.add_argument("--output", type=Path, help="Write report to this path instead of stdout.")
    scan_parser.add_argument("--no-osv", action="store_true", help="Skip best-effort OSV dependency lookup.")

    subparsers.add_parser("mcp", help="Run stdio MCP server.")
    subparsers.add_parser("doctor", help="Print scanner status.")
    return parser


def run_scan(args: argparse.Namespace) -> None:
    context = load_install_context(args.context)
    report = scan_repository(args.repo_url, ref=args.ref, context=context, osv_enabled=not args.no_osv)
    if args.json:
        output = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    else:
        output = render_markdown(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
        report.report_path = str(args.output)
    else:
        print(output)


def run_doctor() -> None:
    payload = {
        "scanner": "repo-preflight",
        "version": __version__,
        "checks": {
            "static_repository_scan": "available",
            "npm_install_surface": "available",
            "osv_dependency_lookup": "best_effort_network_required",
            "mcp_stdio": "available",
            "code_execution": "disabled",
        },
        "promise": "Checks repository source and the visible install surface without executing repository code.",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
