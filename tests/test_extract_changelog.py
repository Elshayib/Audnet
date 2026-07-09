from pathlib import Path

import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "extract_changelog",
    Path(__file__).resolve().parents[1] / "scripts" / "extract_changelog.py",
)
assert _SPEC and _SPEC.loader
_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_mod)


def test_normalize_version() -> None:
    assert _mod.normalize_version("v1.2.3") == "1.2.3"
    assert _mod.normalize_version("1.2.3") == "1.2.3"


def test_extract_section_middle() -> None:
    text = """# Changelog

## [Unreleased]

- pending

## [0.3.0] - 2026-06-18

### Added

- feature A

## [0.2.0] - 2026-06-13

- old
"""
    body = _mod.extract_section(text, "0.3.0")
    assert body is not None
    assert "feature A" in body
    assert "pending" not in body
    assert "old" not in body


def test_extract_section_missing() -> None:
    assert _mod.extract_section("## [1.0.0]\n\nhi\n", "9.9.9") is None
