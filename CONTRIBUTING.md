# Contributing to net-audit

Thanks for your interest in improving net-audit!

## Development Setup

```bash
git clone https://github.com/islam666/net-audit.git
cd net-audit
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Adding Compliance Rules

1. Implement `_check_<name>(snapshot, config) -> ComplianceResult` in `src/net_audit/compliance.py`
2. Register in `_RULE_DISPATCH`
3. Document in `baselines/security_baseline.yaml` and README
4. Add tests in `tests/test_compliance.py` (aim for >90% coverage)

## Testing & Quality

```bash
pytest tests/ -v --cov=net_audit --cov-report=term-missing
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

## Reporting Issues

Use the issue templates for bugs and feature requests.

We follow a security-first approach for any credential or config handling.
