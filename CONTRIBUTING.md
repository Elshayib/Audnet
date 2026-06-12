# Contributing to audnet

Thanks for your interest in improving audnet!

## Development Setup

```bash
git clone https://github.com/islam666/Audnet.git
cd audnet
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

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

1. **Update `CHANGELOG.md`**: move items from `[Unreleased]` to a new version section:

   ```markdown
   ## [0.7.0] - 2026-06-11

   ### Added
   - New feature X (#35)
   ```

2. **Commit the changelog update**:

   ```bash
   git add CHANGELOG.md
   git commit -m "chore(release): prepare v0.7.0"
   ```

3. **Create an annotated tag**:

   ```bash
   git tag -a v0.7.0 -m "Release v0.7.0"
   ```

4. **Push the tag**:

   ```bash
   git push origin v0.7.0
   ```

   Pushing the tag triggers the [publish workflow](.github/workflows/publish.yml) which:
   - Builds the wheel and sdist with `uv build`
   - Publishes to PyPI automatically via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no API token needed)
   - Creates a GitHub Release with the CHANGELOG section as release notes
   - Uploads build artifacts to the release

   **No manual PyPI upload or GitHub Release creation is required.**

### Versioning guidelines

| Change type | Version bump | Example |
|-------------|-------------|---------|
| Bug fix, docs, chore | PATCH (`0.0.Z`) | `0.6.0` → `0.6.1` |
| New feature, non-breaking | MINOR (`0.Y.0`) | `0.6.0` → `0.7.0` |
| Breaking change | MAJOR (`N.0.0`) | `0.6.0` → `1.0.0` |

### Changelog maintenance

- Every PR that users should know about must include a CHANGELOG entry under `[Unreleased]`
- Group entries under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security`
- Reference the PR number at the end of each entry: `description (#NN)`

## Reporting Issues

Use the issue templates for bugs and feature requests.

We follow a security-first approach for any credential or config handling.
