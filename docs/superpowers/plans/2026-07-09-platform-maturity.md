# Platform Maturity (Track D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Audnet a release-safe OSS platform: lock-faithful CI, Bandit SARIF, coverage artifacts, package + Docker smoke tests, and one gated tag workflow that publishes PyPI + GHCR + GitHub Release from CHANGELOG.

**Architecture:** Day-to-day quality lives in `ci.yml` (lint → security → test matrix → smoke → docker-smoke). Tag publishing lives in a single `release.yml` that re-validates via a reusable workflow, builds once, then publishes in order. Legacy tag workflows are removed so nothing double-publishes.

**Tech Stack:** GitHub Actions, uv (`sync --locked`), hatch-vcs, Bandit SARIF + `github/codeql-action/upload-sarif`, pytest-cov, Docker buildx, PyPI Trusted Publishing (OIDC), softprops/action-gh-release.

**Spec:** `docs/superpowers/specs/2026-07-09-platform-maturity-design.md`

---

## File map

| Path | Role |
|------|------|
| `pyproject.toml` | Ensure `uv sync --locked --extra dev` installs all CI tools (optional-deps + dependency-groups) |
| `uv.lock` | Regenerate only if pyproject dependency layout changes |
| `.github/workflows/reusable-validate.yml` | Shared validate job(s) for CI reuse patterns and release gate |
| `.github/workflows/ci.yml` | PR/master: lock install, SARIF, coverage artifacts, smoke, docker-smoke |
| `.github/workflows/release.yml` | Unified `v*` orchestrator (validate → build → pypi → docker → gh release) |
| `.github/workflows/publish.yml` | **Delete** after logic moved (avoids double PyPI publish) |
| `.github/workflows/docker.yml` | **Delete** after logic moved (avoids double GHCR publish) |
| `tests/fixtures/smoke/devices.yaml` | Minimal inventory for package smoke (no real hosts needed) |
| `tests/fixtures/smoke/baseline.yaml` | Minimal baseline for dry-run validation |
| `scripts/extract_changelog.py` | Extract `## [X.Y.Z]` section from CHANGELOG for release notes |
| `CONTRIBUTING.md` | Release + required checks + `uv sync` |
| `README.md` | Fix lockfile install docs |
| `CHANGELOG.md` | `[Unreleased]` platform entries as work lands |

**No product code changes required** for smoke: existing `audnet audit --dry-run` validates inventory + baseline without SSH.

---

### Task 1: Confirm lock-faithful install command locally

**Files:**
- Read: `pyproject.toml`, `uv.lock`
- Modify: only if sync fails (see steps)

- [ ] **Step 1: From repo root, run lock-faithful sync**

```powershell
uv sync --locked --extra dev
```

Expected: succeeds; installs project + ruff, mypy, bandit, pip-audit, pytest, pytest-cov, scrapli (from `dev` extra), and default dependency group packages (`pytest-asyncio`, `pre-commit`).

If `uv` complains that lock is out of date, run `uv lock` then re-try `uv sync --locked --extra dev`.

- [ ] **Step 2: Verify tools are on PATH via uv**

```powershell
uv run ruff --version
uv run mypy --version
uv run bandit --version
uv run pip-audit --version
uv run pytest --version
```

Expected: each prints a version without "command not found".

- [ ] **Step 3: If `dev` extra is missing a CI tool, merge dependency-groups into optional-deps**

Only if Step 1–2 fail. Edit `pyproject.toml` so `[project.optional-dependencies] dev` includes every CI tool currently split across groups, for example ensure these are all listed under `dev = [...]`:

```toml
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-asyncio>=1.4.0",
    "ruff>=0.5.0",
    "mypy>=1.10",
    "bandit>=1.7",
    "pip-audit>=2.7",
    "pre-commit>=4.6.0",
    "scrapli[genie]>=2024.1.30",
]
```

Then:

```powershell
uv lock
uv sync --locked --extra dev
```

- [ ] **Step 4: Commit only if pyproject/lock changed**

```powershell
git add pyproject.toml uv.lock
git commit -m "build: normalize dev deps for uv sync --locked --extra dev"
```

If nothing changed, skip commit.

---

### Task 2: Add reusable validate workflow

**Files:**
- Create: `.github/workflows/reusable-validate.yml`

- [ ] **Step 1: Create the reusable workflow**

Write `.github/workflows/reusable-validate.yml`:

```yaml
name: Reusable Validate

on:
  workflow_call:
    inputs:
      python-version:
        description: Python version for non-matrix jobs
        required: false
        type: string
        default: "3.14"
      run-matrix-tests:
        description: If true, run full 3.12/3.13/3.14 matrix
        required: false
        type: boolean
        default: true

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ inputs.python-version }}

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          version: "latest"
          enable-cache: true

      - name: Sync dependencies (locked)
        run: uv sync --locked --extra dev

      - name: Lint with ruff
        run: uv run ruff check src/ tests/

      - name: Type check with mypy
        run: uv run mypy src/

  security:
    needs: lint
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ inputs.python-version }}

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          version: "latest"
          enable-cache: true

      - name: Sync dependencies (locked)
        run: uv sync --locked --extra dev

      - name: Run Bandit (SARIF + fail on findings)
        run: |
          uv run bandit -r src/ -c pyproject.toml -f sarif -o bandit.sarif
          # Also fail the job with human-readable output if issues exist
          uv run bandit -r src/ -c pyproject.toml

      - name: Upload Bandit SARIF
        if: always() && hashFiles('bandit.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.sarif
          category: bandit

      - name: Run pip-audit dependency check
        uses: nick-fields/retry@v3
        with:
          timeout_minutes: 5
          max_attempts: 3
          retry_wait_seconds: 30
          command: uv run pip-audit --ignore-vuln CVE-2026-44405 --ignore-vuln PYSEC-2026-196 --ignore-vuln CVE-2026-30922

  test:
    needs: security
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ${{ inputs.run-matrix-tests && fromJSON('["3.12","3.13","3.14"]') || fromJSON(format('["{0}"]', inputs.python-version)) }}
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          version: "latest"
          enable-cache: true

      - name: Sync dependencies (locked)
        run: uv sync --locked --extra dev

      - name: Run tests with coverage
        run: >
          uv run pytest tests/ -v --tb=short
          --cov=audnet
          --cov-report=term-missing
          --cov-report=xml
          --cov-fail-under=90

      - name: Upload coverage XML
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: coverage-${{ matrix.python-version }}
          path: coverage.xml
          if-no-files-found: warn
```

**Note on Bandit double-run:** First run writes SARIF; second run exits non-zero on findings with terminal output. If Bandit SARIF mode exits non-zero on findings already, the second run can be dropped—prefer keeping both until verified once in CI.

**Matrix expression fallback:** If `inputs.run-matrix-tests && fromJSON(...)` is awkward in GHA, simplify release to always call with matrix default true, or hardcode matrix in reusable and accept longer release times.

- [ ] **Step 2: Commit**

```powershell
git add .github/workflows/reusable-validate.yml
git commit -m "ci: add reusable validate workflow with locked uv sync"
```

---

### Task 3: Rewrite `ci.yml` to call reusable validate + add smoke jobs

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `tests/fixtures/smoke/devices.yaml`
- Create: `tests/fixtures/smoke/baseline.yaml`

- [ ] **Step 1: Create smoke fixtures**

`tests/fixtures/smoke/devices.yaml`:

```yaml
defaults:
  username: smoke
  device_type: cisco_ios
  port: 22
  timeout: 5

devices:
  - name: smoke-rtr-01
    host: 127.0.0.1
    password: "${SMOKE_DEVICE_PASSWORD}"
```

`tests/fixtures/smoke/baseline.yaml`:

```yaml
checks:
  ssh_v2_only:
    description: "SSHv2 must be enabled; SSHv1 is prohibited"
    severity: critical
    rule: ssh_v2_only

  password_encryption:
    description: "Password encryption service must be enabled"
    severity: high
    rule: password_encryption
```

- [ ] **Step 2: Replace `.github/workflows/ci.yml` content**

```yaml
name: CI

on:
  push:
    branches: [master, main]
  pull_request:
    branches: [master, main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  security-events: write

jobs:
  validate:
    uses: ./.github/workflows/reusable-validate.yml
    with:
      python-version: "3.14"
      run-matrix-tests: true
    permissions:
      contents: read
      security-events: write

  smoke:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          version: "latest"
          enable-cache: true

      - name: Sync build tooling
        run: uv sync --locked --extra dev

      - name: Build wheel and sdist
        run: uv build

      - name: Install wheel into clean venv and smoke-test CLI
        env:
          SMOKE_DEVICE_PASSWORD: smoke-not-real
        run: |
          set -euo pipefail
          uv venv .smoke-venv
          # shellcheck: use venv pip for a non-editable install of the built wheel only
          .smoke-venv/bin/pip install dist/*.whl
          .smoke-venv/bin/audnet --version
          .smoke-venv/bin/audnet audit \
            --inventory tests/fixtures/smoke/devices.yaml \
            --baseline tests/fixtures/smoke/baseline.yaml \
            --dry-run

  docker-smoke:
    needs: smoke
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker buildx
        uses: docker/setup-buildx-action@v3

      - name: Build image (no push)
        uses: docker/build-push-action@v6
        with:
          context: .
          push: false
          load: true
          tags: audnet:ci-smoke
          build-args: |
            AUDNET_VERSION=0.0.0+ci
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run audnet --version in container
        run: |
          docker run --rm --entrypoint audnet audnet:ci-smoke --version
```

- [ ] **Step 3: Local dry-run of smoke commands (no Docker required for this step)**

```powershell
$env:SMOKE_DEVICE_PASSWORD = "smoke-not-real"
uv sync --locked --extra dev
uv build
uv venv .smoke-venv
.\.smoke-venv\Scripts\pip install (Get-ChildItem dist\*.whl | Select-Object -First 1).FullName
.\.smoke-venv\Scripts\audnet.exe --version
.\.smoke-venv\Scripts\audnet.exe audit --inventory tests/fixtures/smoke/devices.yaml --baseline tests/fixtures/smoke/baseline.yaml --dry-run
```

Expected:
- Version string printed (not empty)
- Dry run lists `smoke-rtr-01` and checks; ends with "Dry run complete"

- [ ] **Step 4: Commit**

```powershell
git add .github/workflows/ci.yml tests/fixtures/smoke/devices.yaml tests/fixtures/smoke/baseline.yaml
git commit -m "ci: lock-faithful validate, coverage artifacts path, package and docker smoke"
```

---

### Task 4: Bandit SARIF double-invocation fix (if needed)

**Files:**
- Modify: `.github/workflows/reusable-validate.yml` (Bandit steps only)

- [ ] **Step 1: Prefer single Bandit invocation that both fails and writes SARIF**

Replace the Bandit steps with:

```yaml
      - name: Run Bandit security scan (SARIF)
        run: uv run bandit -r src/ -c pyproject.toml -f sarif -o bandit.sarif

      - name: Upload Bandit SARIF
        if: always() && hashFiles('bandit.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.sarif
          category: bandit
```

Bandit exits non-zero when issues are found even with `-f sarif`. Verify with a quick local check:

```powershell
uv run bandit -r src/ -c pyproject.toml -f sarif -o bandit.sarif; echo "exit=$LASTEXITCODE"
```

Expected on clean tree: exit 0 and `bandit.sarif` exists.

- [ ] **Step 2: Commit if changed**

```powershell
git add .github/workflows/reusable-validate.yml
git commit -m "ci: single Bandit SARIF invocation for Code Scanning"
```

---

### Task 5: CHANGELOG extraction script

**Files:**
- Create: `scripts/extract_changelog.py`
- Create: `tests/test_extract_changelog.py` (optional but preferred for reliability)

- [ ] **Step 1: Write the extractor**

`scripts/extract_changelog.py`:

```python
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
```

- [ ] **Step 2: Write unit test**

`tests/test_extract_changelog.py`:

```python
from pathlib import Path

import pytest

# Import from scripts/ by path
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
```

- [ ] **Step 3: Run tests**

```powershell
uv run pytest tests/test_extract_changelog.py -v
```

Expected: PASS

- [ ] **Step 4: Smoke script against real CHANGELOG**

```powershell
uv run python scripts/extract_changelog.py 0.3.0
```

Expected: prints the 0.3.0 section body; exit 0.

```powershell
uv run python scripts/extract_changelog.py 9.9.9
```

Expected: exit 1, stderr mentions missing section.

- [ ] **Step 5: Commit**

```powershell
git add scripts/extract_changelog.py tests/test_extract_changelog.py
git commit -m "ci: add CHANGELOG section extractor for GitHub Releases"
```

---

### Task 6: Unified release workflow

**Files:**
- Modify: `.github/workflows/release.yml` (replace entirely)
- Delete: `.github/workflows/publish.yml`
- Delete: `.github/workflows/docker.yml`

- [ ] **Step 1: Write unified `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  validate:
    uses: ./.github/workflows/reusable-validate.yml
    with:
      python-version: "3.14"
      run-matrix-tests: true
    permissions:
      contents: read
      security-events: write

  build:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          version: "latest"
          enable-cache: true

      - name: Sync dependencies (locked)
        run: uv sync --locked --extra dev

      - name: Build wheel and sdist
        run: uv build

      - name: Upload dist artifacts
        uses: actions/upload-artifact@v4
        with:
          name: python-dist
          path: dist/*
          if-no-files-found: error

  publish-pypi:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/audnet
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Download dist artifacts
        uses: actions/download-artifact@v4
        with:
          name: python-dist
          path: dist

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  publish-docker:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    env:
      REGISTRY: ghcr.io
      IMAGE_NAME: ${{ github.repository }}
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to ghcr.io
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest

      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            AUDNET_VERSION=${{ github.ref_name }}

      - name: Verify image size
        run: |
          docker pull ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          SIZE=$(docker image inspect ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest --format='{{.Size}}')
          SIZE_MB=$((SIZE / 1024 / 1024))
          echo "Image size: ${SIZE_MB}MB"
          if [ "$SIZE_MB" -gt 200 ]; then
            echo "::error::Image size ${SIZE_MB}MB exceeds 200MB limit"
            exit 1
          fi

  github-release:
    needs: [publish-pypi, publish-docker]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - name: Extract version from tag
        id: version
        run: echo "VERSION=${GITHUB_REF#refs/tags/}" >> "$GITHUB_OUTPUT"

      - name: Extract CHANGELOG section
        id: changelog
        run: |
          set -euo pipefail
          BODY_FILE=release_notes.md
          python scripts/extract_changelog.py "${{ steps.version.outputs.VERSION }}" > "$BODY_FILE"
          echo "body_file=$BODY_FILE" >> "$GITHUB_OUTPUT"

      - name: Download dist artifacts
        uses: actions/download-artifact@v4
        with:
          name: python-dist
          path: dist

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ steps.version.outputs.VERSION }}
          name: ${{ steps.version.outputs.VERSION }}
          body_path: ${{ steps.changelog.outputs.body_file }}
          files: |
            dist/*
          draft: false
          prerelease: false
          generate_release_notes: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Ordering:** `publish-pypi` and `publish-docker` both need `build` (can run in parallel after build). `github-release` waits for **both** so the Release exists only after PyPI and GHCR succeed. If one publish fails, no GitHub Release is created (PyPI may still have published—document retry).

- [ ] **Step 2: Delete legacy tag workflows**

```powershell
git rm .github/workflows/publish.yml .github/workflows/docker.yml
```

- [ ] **Step 3: Commit**

```powershell
git add .github/workflows/release.yml
git commit -m "ci: unify tag release (validate, PyPI, GHCR, CHANGELOG notes)"
```

---

### Task 7: Documentation updates

**Files:**
- Modify: `CONTRIBUTING.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update development install in `README.md`**

Replace the install block that uses `uv venv` + `uv pip install -e ".[dev]"` with:

```markdown
### Step-by-step setup

```bash
# 1. Clone the repository
git clone https://github.com/Elshayib/Audnet.git
cd audnet

# 2. Install dependencies from uv.lock (reproducible)
uv sync --locked --extra dev

# 3. Activate virtual environment
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 4. Install pre-commit hooks
pre-commit install

# 5. Verify installation
python -c "import audnet; print(audnet.__version__)"

# 6. Run the test suite
pytest tests/ -v
```

`uv sync --locked --extra dev` installs the project and all dev tools using the exact versions pinned in `uv.lock`. After changing dependencies in `pyproject.toml`, run `uv lock` and commit the updated lockfile.
```

Also fix any other sentence claiming `uv pip install` reads the lock.

Update the project structure tree if it still lists separate `publish.yml` / `docker.yml` as tag publishers—note that release is unified under `release.yml` and validate under `reusable-validate.yml`.

- [ ] **Step 2: Update `CONTRIBUTING.md` Release Process**

Replace the release steps section so it states:

1. Move `[Unreleased]` items into `## [X.Y.Z] - YYYY-MM-DD` (required; release fails without this section).
2. Commit changelog: `chore(release): prepare vX.Y.Z`.
3. Annotated tag + push tag only (or push commit then tag).
4. Tag triggers **Release** workflow: validate (full CI bar) → build → PyPI → GHCR → GitHub Release with CHANGELOG body + wheel/sdist assets.
5. No manual PyPI/GHCR/Release UI steps.

Add **Required status checks** (enable in GitHub branch protection for `master`):

- `validate / lint`
- `validate / security`
- `validate / test (3.12)`, `validate / test (3.13)`, `validate / test (3.14)` — exact names depend on GHA UI after first run; document “all jobs under CI workflow: validate + smoke + docker-smoke”.
- `smoke`
- `docker-smoke`

- [ ] **Step 3: Update `CHANGELOG.md` `[Unreleased]`**

Add under Build / CI:

```markdown
### Build

- CI uses `uv sync --locked --extra dev`; Bandit uploads SARIF to Code Scanning; coverage XML artifacts retained
- Package smoke (`audnet --version` + `audit --dry-run` on fixtures) and Docker build smoke on every PR
- Unified `v*` release workflow: validate → build → PyPI → GHCR → GitHub Release from CHANGELOG (replaces separate publish/docker tag workflows)
```

- [ ] **Step 4: Commit**

```powershell
git add CONTRIBUTING.md README.md CHANGELOG.md
git commit -m "docs: align install and release process with platform CI"
```

---

### Task 8: Local full verification before push

**Files:** none (verification only)

- [ ] **Step 1: Lint, typecheck, security, tests**

```powershell
uv sync --locked --extra dev
uv run ruff check src/ tests/
uv run mypy src/
uv run bandit -r src/ -c pyproject.toml -f sarif -o bandit.sarif
uv run pytest tests/ -v --cov=audnet --cov-report=term-missing --cov-fail-under=90
```

Expected: all pass; coverage ≥ 90%.

- [ ] **Step 2: Package smoke (Windows)**

```powershell
$env:SMOKE_DEVICE_PASSWORD = "smoke-not-real"
uv build
Remove-Item -Recurse -Force .smoke-venv -ErrorAction SilentlyContinue
uv venv .smoke-venv
.\.smoke-venv\Scripts\pip install (Get-ChildItem dist\*.whl | Select-Object -First 1).FullName
.\.smoke-venv\Scripts\audnet.exe --version
.\.smoke-venv\Scripts\audnet.exe audit --inventory tests/fixtures/smoke/devices.yaml --baseline tests/fixtures/smoke/baseline.yaml --dry-run
```

Expected: version + dry-run success.

- [ ] **Step 3: Docker smoke (if Docker Desktop available)**

```powershell
docker build --build-arg AUDNET_VERSION=0.0.0+ci -t audnet:ci-smoke .
docker run --rm --entrypoint audnet audnet:ci-smoke --version
```

Expected: version printed. If Docker is unavailable, note in PR and rely on GitHub `docker-smoke` job.

- [ ] **Step 4: Confirm legacy workflows gone**

```powershell
Test-Path .github/workflows/publish.yml   # False
Test-Path .github/workflows/docker.yml    # False
Test-Path .github/workflows/release.yml   # True
Test-Path .github/workflows/reusable-validate.yml  # True
```

- [ ] **Step 5: Push branch / master and wait for green CI**

Do **not** cut a real production tag until CI is green on the commit. First real `v*` after this change is the live test of the unified release path.

```powershell
git status
git push origin master
```

(Or open a PR if the project prefers PR flow for this change set.)

- [ ] **Step 6: After CI green, optional maintainers step**

In GitHub → Settings → Branches → protection for `master`: require the new CI jobs before merge.

---

### Task 9: Spec success-criteria checklist (close-out)

Mark each item only with evidence from CI run URL or local command output:

- [ ] CI uses `uv sync --locked`
- [ ] Bandit SARIF upload step succeeds (Code Scanning may show 0 alerts)
- [ ] `coverage-3.12` / `3.13` / `3.14` artifacts present
- [ ] `smoke` job green
- [ ] `docker-smoke` job green
- [ ] Only `Release` workflow runs on tags (no publish.yml/docker.yml)
- [ ] CONTRIBUTING/README match workflows
- [ ] Unit suite still ≥ 90% coverage

When all checked, Track D is done; next scaling tracks per design follow-on (A/B, then C product, F).

---

## Implementation notes / pitfalls

1. **Reusable workflow permissions:** Caller (`ci.yml` / `release.yml`) must pass `permissions: security-events: write` for SARIF upload to work from the reusable `security` job.
2. **Fork PRs:** SARIF upload may fail on forks without write permission—`if: always()` upload can still fail the job; if that becomes noisy, gate upload with `if: github.event.pull_request.head.repo.full_name == github.repository` (same-repo only). Prefer same-repo first.
3. **Matrix expression:** If GHA rejects the dynamic matrix expression in Task 2, hardcode `python-version: ["3.12", "3.13", "3.14"]` in the reusable workflow and drop the `run-matrix-tests` input.
4. **Dockerfile hatch-vcs:** Keep `AUDNET_VERSION` / `SETUPTOOLS_SCM_PRETEND_VERSION`; docker-smoke must pass a non-empty build-arg.
5. **Smoke inventory env var:** Fixture uses `${SMOKE_DEVICE_PASSWORD}` so strict inventory loading works; always set the env var in the smoke job.
6. **Do not test unified release with a real PyPI tag until CI is green** on the workflow commit. Prefer waiting for a planned version bump.
7. **`.smoke-venv` and `dist/`:** Add to `.gitignore` if not already ignored so local smoke debris is not committed.

---

## Spec coverage matrix

| Spec requirement | Task |
|------------------|------|
| Lock-faithful install | 1, 2, 3 |
| Bandit SARIF | 2, 4 |
| pip-audit retained | 2 |
| Coverage fail-under + artifacts | 2 |
| Package smoke | 3 |
| Docker smoke | 3 |
| Unified release | 6 |
| CHANGELOG release notes | 5, 6 |
| Delete dual tag publishers | 6 |
| Docs | 7 |
| Success verification | 8, 9 |
| Non-goals (no vendor/rules product) | — not in any task |

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-09-platform-maturity.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — execute tasks in this session with checkpoints  

Which approach?
