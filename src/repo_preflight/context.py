from __future__ import annotations

from pathlib import Path

from repo_preflight.models import InstallContext


def load_install_context(path: Path | None) -> InstallContext | None:
    if path is None:
        return None
    data = parse_simple_yaml(path.read_text(encoding="utf-8"))
    return InstallContext(
        intended_command=as_optional_str(data.get("intended_command")),
        runtime=as_optional_str(data.get("runtime")),
        operating_system=as_optional_str(data.get("operating_system")),
        credential_names=as_str_list(data.get("credential_names")),
        local_resources=as_str_list(data.get("local_resources")),
    )


def parse_simple_yaml(text: str) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    current_list_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_list_key:
            result.setdefault(current_list_key, [])
            value = strip_quotes(stripped[2:].strip())
            if isinstance(result[current_list_key], list):
                result[current_list_key].append(value)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            result[key] = []
            current_list_key = key
            continue
        current_list_key = None
        if value.startswith("[") and value.endswith("]"):
            result[key] = [strip_quotes(item.strip()) for item in value[1:-1].split(",") if item.strip()]
        else:
            result[key] = strip_quotes(value)
    return result


def strip_quotes(value: str) -> str:
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def as_optional_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
