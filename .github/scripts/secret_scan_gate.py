#!/usr/bin/env python3
"""Non-printing detect-secrets gate for committed files.

The gate intentionally reports only file path, line number, and detector type.
It never prints candidate secret values, environment variables, or scanner JSON.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ALLOWLIST: list[tuple[re.Pattern[str], re.Pattern[str], str]] = [
    (
        re.compile(r"^README\.md$"),
        re.compile(r"Administrator|password", re.IGNORECASE),
        "documented local/demo administrator placeholder",
    ),
    (
        re.compile(r"^docs/development\.md$"),
        re.compile(r"admin password", re.IGNORECASE),
        "documented local development placeholder",
    ),
    (
        re.compile(r"^pwd\.yml$"),
        re.compile(r"MYSQL_ROOT_PASSWORD"),
        "local development compose placeholder",
    ),
    (
        re.compile(r"^tests/conftest\.py$"),
        re.compile(r"access_key|secret_key"),
        "test fixture value",
    ),
    (
        re.compile(r"^tests/test_frappe_docker\.py$"),
        re.compile(r"restic_password"),
        "test fixture value",
    ),
]


def _line_text(path: str, line_number: int) -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _is_allowlisted(path: str, line_number: int) -> bool:
    line = _line_text(path, line_number)
    return any(
        path_re.search(path) and line_re.search(line)
        for path_re, line_re, _ in ALLOWLIST
    )


def _tracked_file_count() -> int:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return sum(1 for item in proc.stdout.split(b"\0") if item)


def main() -> int:
    cmd = [sys.executable, "-m", "detect_secrets", "scan", "--no-verify"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(
            "detect-secrets scan failed; scanner stderr suppressed to avoid accidental disclosure.",
            file=sys.stderr,
        )
        return proc.returncode

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(
            "detect-secrets produced invalid JSON; raw output suppressed.",
            file=sys.stderr,
        )
        return 2

    findings: list[tuple[str, int, str]] = []
    allowlisted = 0
    for path, items in sorted(payload.get("results", {}).items()):
        for item in items:
            line_number = int(item.get("line_number") or 0)
            detector = str(item.get("type") or "unknown detector")
            if _is_allowlisted(path, line_number):
                allowlisted += 1
                continue
            findings.append((path, line_number, detector))

    if findings:
        print(
            "Potential committed secrets detected; candidate values redacted:",
            file=sys.stderr,
        )
        for path, line_number, detector in findings:
            print(f"- {path}:{line_number}: {detector} ([REDACTED])", file=sys.stderr)
        return 1

    print(
        "Secret scan passed: detect-secrets scanned "
        f"{_tracked_file_count()} tracked files; "
        f"{allowlisted} known fixture/hash candidates allowlisted; "
        "0 non-allowlisted candidates."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
