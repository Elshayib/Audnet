# Contributing to audnet

Thanks for your interest in improving audnet!

## Development Setup

```bash
git clone https://github.com/Elshayib/Audnet.git
cd audnet
uv sync --locked --extra dev
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pre-commit install
```

`uv sync --locked --extra dev` installs from the committed `uv.lock`. After changing dependencies in `pyproject.toml`, run `uv lock` and commit the updated lockfile.

## Adding Compliance Rules

1. Implement `_check_<name>(snapshot, config) -> ComplianceResult` in `src/audnet/compliance.py`
2. Register in `_RULE_DISPATCH`
3. Document in `baselines/security_baseline.yaml` and README
4. Add tests in `tests/test_compliance.py` (aim for >90% coverage)

## Testing & Quality

```bash
pytest tests/ -v --cov=audnet --cov-report=term-missing
ruff check src/ tests/
mypy src/
```

All tests must pass with mocked data. No real SSH required.

## PR Workflow

- Branch from `master`
- Small, focused PRs
- Include tests + doc updates
- Run full lint/test suite locally
- CI must be green before merge
- Use conventional commit messages (e.g. `feat: add vlan drift check`)

## Issue Linking

Every PR that fixes an issue **must** include a closing keyword in its description:

```
Closes #123
Fixes #456
Resolves #789
```

GitHub automatically closes linked issues when the PR is merged. A PR template is provided to remind you — fill in the "Related Issues" section.

If a PR partially addresses an issue, reference it without a closing keyword:

```
Related to #123
```

## Release Process

audnet uses [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH).

### When to release

Create a release when a meaningful set of changes has accumulated on `master` — typically after merging one or more feature/fix PRs.

### Steps

1. **Update `CHANGELOG.md`** (**required** — release fails without a matching CHANGELOG section): move items from `[Unreleased]` to a new version section:

   ```markdown
   ## [X.Y.Z] - YYYY-MM-DD

   ### Added
   - New feature X (#35)
   ```

2. **Commit the changelog update**:

   ```bash
   git add CHANGELOG.md
   git commit -m "chore(release): prepare vX.Y.Z"
   ```

3. **Create an annotated tag and push it**:

   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. **Tag triggers the [Release](.github/workflows/release.yml) workflow only**, which runs:

   - **validate** — full CI bar (lint, security, test matrix via reusable validate)
   - **build** — wheel and sdist
   - **PyPI** — publish via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
   - **GHCR** — Docker image publish to `ghcr.io`
   - **GitHub Release** — release notes from the CHANGELOG section, with wheel/sdist assets

   **No manual PyPI, GHCR, or GitHub Release UI steps are required.**

### Versioning guidelines

| Change type | Version bump | Example |
|-------------|-------------|---------|
| Bug fix, docs, chore | PATCH (`0.0.Z`) | `0.6.0` → `0.6.1` |
| New feature, non-breaking | MINOR (`0.Y.0`) | `0.6.0` → `0.7.0` |
| Breaking change | MAJOR (`N.0.0`) | `0.6.0` → `1.0.0` |

### Changelog maintenance

- Every PR that users should know about must include a CHANGELOG entry under `[Unreleased]`
- Group entries under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`, or `Build`
- Reference the PR number at the end of each entry: `description (#NN)`

## Required status checks (branch protection)

Configure branch protection on `master` so merges require the CI workflow jobs:

| Workflow | Required jobs |
|----------|---------------|
| [CI](.github/workflows/ci.yml) | `validate` (lint / security / test matrix), `smoke`, `docker-smoke` |

These jobs must be green before merge. The Release workflow is tag-driven and is not a PR merge gate.

## Reporting Issues

Use the issue templates for bugs and feature requests.

We follow a security-first approach for any credential or config handling.
