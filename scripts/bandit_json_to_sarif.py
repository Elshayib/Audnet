#!/usr/bin/env python3
"""Convert Bandit JSON report to SARIF 2.1.0 for GitHub Code Scanning.

Usage:
  python scripts/bandit_json_to_sarif.py bandit.json bandit.sarif
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _level(severity: str) -> str:
    mapping = {
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "UNDEFINED": "note",
    }
    return mapping.get(severity.upper(), "warning")


def convert(bandit_report: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for issue in bandit_report.get("results", []):
        test_id = str(issue.get("test_id", "B000"))
        test_name = str(issue.get("test_name", test_id))
        if test_id not in rules:
            rules[test_id] = {
                "id": test_id,
                "name": test_name,
                "shortDescription": {"text": test_name},
                "fullDescription": {
                    "text": str(issue.get("issue_text", test_name)),
                },
                "defaultConfiguration": {
                    "level": _level(str(issue.get("issue_severity", "MEDIUM"))),
                },
                "helpUri": f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}_{test_name}.html",
            }

        filename = str(issue.get("filename", "unknown"))
        line = int(issue.get("line_number") or 1)
        results.append(
            {
                "ruleId": test_id,
                "level": _level(str(issue.get("issue_severity", "MEDIUM"))),
                "message": {"text": str(issue.get("issue_text", test_name))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": filename.replace("\\", "/")},
                            "region": {"startLine": max(line, 1)},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "informationUri": "https://bandit.readthedocs.io/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("Usage: bandit_json_to_sarif.py <bandit.json> <bandit.sarif>", file=sys.stderr)
        return 2
    src = Path(argv[1])
    dst = Path(argv[2])
    if not src.is_file():
        print(f"Input not found: {src}", file=sys.stderr)
        return 1
    report = json.loads(src.read_text(encoding="utf-8"))
    sarif = convert(report)
    dst.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
