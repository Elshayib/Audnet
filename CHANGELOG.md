# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-11

### Added

- Initial release: network security & compliance auditor with SSH-based device collection
- Parallel SSH collector (`collector.py`) using Netmiko + ThreadPoolExecutor with configurable concurrency
- Async collector prototype (`collector_async.py`) using asyncio + asyncssh for large-scale performance
- TextFSM parser with vendor-aware template selection for structured CLI output
- Pattern-based compliance engine with 4 security rules (SSH, NTP, syslog, interface) and per-vendor overrides
- Vendor registry/dispatch pattern (`VendorProfile`, `register_vendor()`) for multi-vendor support
- Jinja2 report generator producing Markdown and HTML audit reports
- Typer CLI with `--device`, `--check`, `--json`, `--dry-run`, `--strict`, `--verbose`, `--version` flags
- YAML inventory loader with environment variable resolution for credential management
- Pydantic models for baseline schema validation
- Structured exception hierarchy with retry logic for transient SSH failures
- SSH key-based authentication support
- `structlog` with secret redaction for safe logging
- Plaintext password detection with `--strict` mode for CI/CD pipelines
- Pre-commit hooks: ruff, mypy strict, bandit, and formatting checks
- GitHub Actions CI: lint, security scan (bandit + pip-audit), and multi-version testing (3.12/3.13/3.14)
- GitHub Actions auto-close workflow for linked issues on PR merge
- Comprehensive test suite: 208 tests, 98.61% coverage
- Sample device inventory and security baseline configuration
- Documentation: README with usage examples, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md

### Security

- Passwords stored as `SecretStr` (Pydantic), never rendered in logs or output
- Structlog processor redacts sensitive keys (`password`, `key_file`, `secret`, `passwd`, `token`)
- `--strict` mode enforces env-var-only passwords in CI/CD pipelines

## [Unreleased]
