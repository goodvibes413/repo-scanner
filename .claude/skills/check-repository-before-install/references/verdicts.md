# Verdicts

Use these exact verdict labels.

- `DO_NOT_INSTALL`: Known malicious package or version, clear credential theft, exfiltration, destructive commands, or malicious workflow evidence.
- `TEST_ONLY_IN_ISOLATION`: Install hooks, remote shell execution, obfuscated install payloads, suspicious dependency resolution, broad MCP access, or broad local access.
- `LOWER_RISK_WITH_CONTROLS`: No known malicious indicators from supported checks, but the install context exposes credentials or sensitive local resources.
- `INSUFFICIENT_EVIDENCE`: Inaccessible repository, failed clone, unavailable feeds, unsupported package manager, missing lockfile where dependency risk matters, or incomplete scan.
- `NO_KNOWN_THREATS_FOUND_WITH_LIMITATIONS`: No findings across supported checks, with explicit dependency, feed freshness, and zero-day limitations.

Do not collapse verdicts into a numeric score. Do not upgrade a result to stronger reassurance because a repository is popular, old, or has many stars.
