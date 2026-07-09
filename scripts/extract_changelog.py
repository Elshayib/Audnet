#!/usr/bin/env python3
"""Extract a version section from CHANGELOG.md for GitHub Releases.

Usage:
  python scripts/extract_changelog.py 0.3.0
  python scripts/extract_changelog.py v0.3.0

Prints the section body (without the ## heading) to stdout.
Exits 1 if the section is missing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def normalize_version(raw: str) -> str:
    return raw[1:] if raw.startswith("v") else raw


def extract_section(changelog: str, version: str) -> str | None:
    # Match ## [0.3.0] - date  OR  ## [0.3.0]
    heading = re.compile(
        rf"^## \[{re.escape(version)}\](?:\s*-\s*.*)?\s*$",
        re.MULTILINE,
    )
    match = heading.search(changelog)
    if not match:
        return None
    start = match.end()
    next_heading = re.search(r"^## ", changelog[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(changelog)
    body = changelog[start:end].strip()
    return body if body else None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: extract_changelog.py <version>", file=sys.stderr)
        return 2
    version = normalize_version(argv[1])
    path = Path("CHANGELOG.md")
    if not path.is_file():
        print("CHANGELOG.md not found", file=sys.stderr)
        return 1
    body = extract_section(path.read_text(encoding="utf-8"), version)
    if body is None:
        print(f"No CHANGELOG section for [{version}]", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
