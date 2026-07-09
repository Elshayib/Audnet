"""Tests for scripts/bandit_json_to_sarif.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "bandit_json_to_sarif",
    Path(__file__).resolve().parents[1] / "scripts" / "bandit_json_to_sarif.py",
)
assert _SPEC and _SPEC.loader
_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_mod)


def test_convert_empty() -> None:
    sarif = _mod.convert({"results": []})
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_convert_issue() -> None:
    report = {
        "results": [
            {
                "test_id": "B201",
                "test_name": "flask_debug_true",
                "issue_severity": "HIGH",
                "issue_text": "A Flask app appears to be run with debug=True",
                "filename": "src/audnet/app.py",
                "line_number": 10,
            }
        ]
    }
    sarif = _mod.convert(report)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "B201"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "B201"


def test_cli_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "bandit.json"
    dst = tmp_path / "bandit.sarif"
    src.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert _mod.main(["bandit_json_to_sarif.py", str(src), str(dst)]) == 0
    data = json.loads(dst.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
