# Platform Maturity (Track D) Design

**Date:** 2026-07-09  
**Status:** Approved for planning (user chose full package C; approach: unified release)  
**Repo:** Audnet (`Elshayib/Audnet`)

## Context

P0 hardening is complete and CI is green on `master`. Scaling tracks A–F remain; **Track D (project/platform maturity) is first priority**, then vendor depth, compliance power, production Docker/history, and throughput.

Today Audnet already has:

- Multi-Python CI: ruff, mypy, bandit, pip-audit, pytest with `--cov-fail-under=90`
- Tag-driven PyPI publish (OIDC Trusted Publishing)
- Tag-driven GHCR Docker publish
- Tag-driven GitHub Release (auto-generated notes)

Gaps that block “serious OSS platform” maturity:

| Gap | Risk |
|-----|------|
| No release gate | A `v*` tag can publish without that commit ever passing CI |
| Install not lock-faithful | CI uses `uv pip install -e ".[dev]"`; `uv.lock` is not enforced |
| Security stays in logs | Bandit does not upload SARIF to Code Scanning |
| No durable coverage signal | Fail-under only; no retained artifacts |
| No package-level smoke | Mocks unit-test the tree; the built wheel/CLI is not exercised |
| Uncoupled tag workflows | `publish.yml`, `docker.yml`, `release.yml` fire independently |
| Docs drift | CONTRIBUTING claims CHANGELOG release notes; `release.yml` uses GitHub auto-notes; README overclaims lock usage |

## Goals

1. **Reproducible CI:** every push/PR installs from `uv.lock` with a single documented command.
2. **Visible security:** Bandit findings land in GitHub Code Scanning via SARIF; pip-audit remains a hard fail with existing CVE ignores.
3. **Retained quality signal:** coverage stays fail-under 90% and uploads report artifacts.
4. **Package smoke (e2e-lite):** built wheel installs cleanly; CLI runs against fixture inventory/baseline without real SSH.
5. **Docker smoke (CI):** image builds on PRs without pushing; `audnet --version` works inside the image.
6. **Safe releases:** one orchestrated workflow on `v*` tags: validate → build once → PyPI → GHCR → GitHub Release with CHANGELOG body; no double-publish from legacy tag workflows.
7. **Docs match reality:** CONTRIBUTING, README, and branch-protection guidance align with workflows.

## Non-goals (this sprint)

- Multi-vendor baseline packs or richer compliance rules (Tracks A/B)
- Enterprise history (DB/git locks, PEM workflows) (Track C product)
- Production Docker product hardening beyond CI smoke (non-root runtime fixes, healthcheck product work)
- Live multi-vendor hardware lab
- TestPyPI promotion environments
- Codecov (or other third-party coverage SaaS) — GitHub Actions artifacts only
- SLSA provenance / signed artifacts (follow-up)
- Changing SemVer policy or hatch-vcs versioning model

## Approach

**Unified release orchestrator + stronger CI** (not three independent tag workflows, not full TestPyPI promotion).

- **CI workflow** owns day-to-day quality for `push`/`pull_request` on `master`/`main`.
- **Release workflow** owns all `v*` tag publishing after re-validation.
- Shared validation steps live in a **reusable workflow or composite action** so CI and release cannot drift.

## Architecture

```
                    ┌─────────────────────────────────────┐
  push / PR  ──────▶│  ci.yml                             │
                    │  lint → security → test(matrix)     │
                    │       → smoke → docker-smoke        │
                    └─────────────────────────────────────┘

  tag v*     ──────▶│  release.yml                        │
                    │  validate (reuse checks)            │
                    │    → build (uv build, artifacts)    │
                    │    → publish-pypi (OIDC)            │
                    │    → publish-docker (GHCR)          │
                    │    → github-release (CHANGELOG)     │
                    └─────────────────────────────────────┘

  deleted/disabled: tag triggers on publish.yml, docker.yml, release.yml (old)
```

### Design units

| Unit | Responsibility |
|------|----------------|
| `.github/workflows/ci.yml` | PR/master quality gate graph |
| `.github/workflows/reusable-validate.yml` (or `.github/actions/setup-audnet`) | Shared install + lint/type/security/test entry so release reuses CI bar |
| `.github/workflows/release.yml` | Single tag orchestrator |
| Smoke fixtures under `tests/fixtures/` or existing inventory/baseline paths | Deterministic CLI inputs for package smoke |
| Docs: `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md` | Operator-facing truth |

## CI design

### Install (lock-faithful)

- Prefer:

  ```bash
  uv sync --all-extras --group dev
  ```

  or the minimal flags that (a) honor `uv.lock` and (b) install project + dev tools used in CI (ruff, mypy, bandit, pip-audit, pytest, pytest-cov, scrapli extra).

- If current `pyproject.toml` splits tools across `[project.optional-dependencies] dev` and `[dependency-groups] dev`, **normalize** so one sync command is correct and regenerate `uv.lock` if needed.
- Replace all CI/release `uv venv` + `uv pip install -e ".[dev]"` paths with the lock-faithful command.
- Fix README claim that `uv pip install -e ".[dev]"` reads the lock; document `uv sync` instead.

### Job graph

```
lint ──► security ──► test (matrix 3.12, 3.13, 3.14) ──► smoke ──► docker-smoke
```

| Job | Details |
|-----|---------|
| **lint** | Python 3.14; ruff check `src/ tests/`; mypy `src/` |
| **security** | Bandit with SARIF output + upload via `github/codeql-action/upload-sarif`; permissions `security-events: write`. Bandit still fails the job on findings (`bandit -r src/ -c pyproject.toml`). pip-audit with existing retry action and current `--ignore-vuln` list. |
| **test** | Matrix 3.12–3.14; `pytest` verbose; coverage run with fail-under 90 (prefer single invocation: `pytest tests/ -v --cov=audnet --cov-report=term-missing --cov-report=xml --cov-fail-under=90`). Upload `coverage.xml` (and optional HTML) as artifacts named by Python version. |
| **smoke** | Depends on `test` success. `uv build`; create clean venv; `uv pip install dist/*.whl` (or `pip install`); run `audnet --version`; run a non-network audit path against fixture inventory + baseline (mock collectors or use existing fixture patterns so no real SSH). Exit non-zero on failure. |
| **docker-smoke** | Depends on `smoke` (or `test` if smoke is pure Python-only dependency). `docker build` with a pretend version build-arg (e.g. `0.0.0+ci`); run container `audnet --version`; **do not push**. Fail if build or version command fails. Keep image size check optional here; retain hard size check on release push. |

### Permissions

- Default `contents: read`.
- `security` job: `security-events: write` for SARIF.
- No `packages: write` or `id-token: write` on CI.

### Branch protection (manual / documented)

Document required status checks after workflows land:

- `lint`
- `security`
- `test` (all matrix legs, or a single aggregate if we add one)
- `smoke`
- `docker-smoke`

Enabling protection is a repo admin step outside the code change; the design requires documenting it in CONTRIBUTING.

## Smoke (e2e-lite) design

**Intent:** prove the **packaged** CLI works, not re-test every compliance rule.

1. Build sdist/wheel with `uv build`.
2. Install wheel into a clean environment (no editable install, no `src/` on `PYTHONPATH`).
3. Assert `audnet --version` prints a non-empty version string.
4. Run audit against fixture files:
   - Inventory: small YAML under `tests/fixtures/smoke/` (or reuse `inventories/` + mocks).
   - Baseline: minimal baseline YAML.
   - Collection must not require live devices — use CLI flags already present (e.g. offline/fixture mode if any) **or** inject via existing test double patterns **or** add the smallest possible `--dry-run` / fixture hook if missing.

**Preference order for no-SSH audit:**

1. Existing CLI options that skip live connect.
2. Environment variable or documented test hook already in code.
3. Only if necessary: minimal new CLI flag (e.g. `--fixture-dir`) scoped to loading pre-canned snapshots — avoid broad product changes.

If a product flag is required, it is in scope for Track D only as far as smoke needs; no vendor/rule expansion.

## Release design

### Trigger

```yaml
on:
  push:
    tags: ['v*']
```

### Jobs

| Order | Job | Permissions / env | Behavior |
|-------|-----|-------------------|----------|
| 1 | `validate` | contents: read | Full history checkout (`fetch-depth: 0`); lock-faithful install; same bar as CI lint + security + tests + coverage (single Python or matrix — minimum: one full suite + coverage 90%). Prefer calling reusable workflow. |
| 2 | `build` | needs: validate | `uv build`; upload `dist/*` artifacts. |
| 3 | `publish-pypi` | needs: build; `id-token: write`; environment `pypi` | Download artifacts; `pypa/gh-action-pypi-publish`. Do not rebuild. |
| 4 | `publish-docker` | needs: build (or needs: publish-pypi if strict ordering preferred); `packages: write` | Buildx push to `ghcr.io/${{ github.repository }}` with semver tags + `latest`; size ≤ 200MB check from current docker.yml; `AUDNET_VERSION` from tag. |
| 5 | `github-release` | needs: [publish-pypi, publish-docker]; `contents: write` | Create GitHub Release for tag; body = extracted `CHANGELOG.md` section for that version (fallback: short message + link to CHANGELOG if section missing); attach wheel/sdist; optional append of GitHub-generated notes. |

**Ordering note:** Prefer **PyPI before Docker before GitHub Release** so the public Release exists only after artifacts are published. If Docker fails after PyPI succeeds, the workflow fails; document manual GHCR retry. PyPI yank is out of scope.

### Retire legacy tag workflows

- Remove tag `on.push.tags` from old `publish.yml` and `docker.yml`, **or delete those files** after logic is merged into `release.yml`.
- Replace old `release.yml` content with the orchestrator (same filename is fine).
- Ensure a tag never triggers two PyPI or two Docker publishes.

### CHANGELOG extraction

- Tag `v0.4.0` maps to section `## [0.4.0]` (strip leading `v`).
- Extraction via small shell/python step in the release job; fail soft to auto notes only if section absent **or** fail hard — **prefer fail hard** if section missing so releases stay disciplined with CONTRIBUTING.

## Documentation updates

| File | Updates |
|------|---------|
| `CONTRIBUTING.md` | Release: changelog section required; tag triggers validate→publish; list required CI checks; install via `uv sync`. |
| `README.md` | Dev install uses `uv sync`; CI/security notes if useful; structure tree if workflows change. |
| `CHANGELOG.md` | `[Unreleased]` entries for platform work as it lands. |
| Optional `docs/` note | Branch protection checklist for maintainers. |

## Implementation shape

Ship as ordered commits or stacked PRs:

1. **CI lock + SARIF + coverage artifacts** — no release change yet.
2. **Smoke + docker-smoke** — fixtures + jobs.
3. **Unified release + delete/disable legacy tag workflows + docs**.

Each step must keep `master` green.

## Success criteria

- [ ] CI on PR uses lockfile-based install; changing a transitive pin without `uv lock` is detectable by design of `uv sync`.
- [ ] Bandit SARIF uploads successfully on a clean tree; Code Scanning UI can show results (empty findings OK).
- [ ] Coverage XML (or HTML) artifacts appear on CI runs; fail-under 90 still enforced.
- [ ] Smoke job fails if wheel omits console script or CLI crashes on fixture run.
- [ ] Docker-smoke builds and runs `audnet --version` without registry push.
- [ ] Pushing `v*` runs only the unified release workflow; no double publish.
- [ ] Release notes body matches CHANGELOG section for that version.
- [ ] CONTRIBUTING/README match workflows.
- [ ] Existing unit/integration suite still passes; coverage ≥ 90%.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| `uv sync` doesn’t install optional-deps as expected | Normalize pyproject dependency groups; verify locally before CI change |
| SARIF upload fails on forks/PRs from forks | Use `if: always()` carefully; allow soft-fail upload on permission errors only if documented — prefer standard `pull_request` from same repo |
| Dockerfile needs git metadata for hatch-vcs | Keep `AUDNET_VERSION` / `SETUPTOOLS_SCM_PRETEND_VERSION` build-arg path used today |
| OIDC environment `pypi` misconfigured after workflow rename | Keep environment name `pypi`; test with dry-run only if available — first real tag is validation |
| CHANGELOG hard-fail blocks hotfix tags | Document required changelog step in CONTRIBUTING; no silent empty releases |

## Follow-on (out of scope, ordered after D)

1. Tracks **A/B** — vendor packs + richer rules  
2. Tracks **C/D-product** — enterprise history + production Docker hardening  
3. Track **F** — throughput / large fleets  
4. Optional platform extras — Codecov badge, SLSA, TestPyPI, Dependabot

## Decisions locked

| Decision | Choice |
|----------|--------|
| Priority | Track D first; all other scaling tracks later |
| Scope of D | Full package C |
| Architecture | Unified release + stronger CI |
| E2E | Fixture CLI smoke **and** Docker build smoke on CI |
| Coverage hosting | GitHub Actions artifacts only (no Codecov) |
| Release notes | CHANGELOG section required |
| pip-audit ignores | Preserve current CVE ignore list unless proven fixed |
