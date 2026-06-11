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

### Added

- Async collector prototype (`collector_async.py`) using asyncio + asyncssh for scalable device collection (#20)
- Benchmark script (`benchmarks/bench_collectors.py`) comparing sync vs async throughput (#20)
- Tests for async collector: success, auth failure, connection lost, timeout, mixed results, empty list (#20)
- Performance & Scalability section in README with architecture comparison and migration path (#20)
- CHANGELOG.md following Keep a Changelog format with full project history (#35)
- Release process documentation in CONTRIBUTING.md (#35)
- Pre-commit hooks: trailing-whitespace, end-of-file-fixer, check-yaml, check-toml, check-added-large-files, debug-statements, mixed-line-ending, ruff (lint + format), mypy (strict) (#34)
- `uv.lock` committed for reproducible dependency installs (#34)
- Copy-paste usage examples for `--device`, `--check`, `--json`, `--dry-run`, `--strict`, `--verbose`, `--version` (#33)
- Expanded vendor extension guide with step-by-step instructions (#33)
- Retry wrapper (`nick-fields/retry`) for `pip-audit` step in CI to handle transient PyPI 503s (#32)
- Test coverage expansion: CLI filter combinations, compliance edge cases, collector retry/timeout edge cases — 201 tests, 98.61% coverage (#31)
- `--strict` mode: fail on plaintext passwords in inventory files (#30)
- Plaintext password detection in `config.py` with warning listing affected devices (#30)
- `SECURITY.md` rewrite with Vault/AWS Secrets Manager/1Password/keyring integration examples (#30)
- Broadened retry coverage in collector: 7 transient exception types (`ConnectionException`, `ReadException`, `SSHException`, `NetmikoParsingException`) (#29)
- `_is_retryable()` predicate excluding `NetmikoAuthenticationException` from retries (#29)
- Per-device `timeout` parameter on `collect_all()` with error snapshot (#29)
- `--dry-run` (`-n`) mode: validate config and preview audit without connecting to devices (#28)
- CLI refactor: simplified check filter logic, improved JSON output handling (#27)
- Multi-vendor support section in README with vendor configuration examples (#26)
- Vendor registry/dispatch pattern: `VendorProfile` dataclass, `get_commands()`, `get_template_name()`, `register_vendor()` (#25)
- Vendor-aware TextFSM template loading in parser (#25)
- Pattern-based compliance checks with per-vendor override support (#25)
- Compliance config parsing robustness against real-world device output (#24)
- GitHub Actions auto-close workflow for linked issues on PR merge (#23)
- Security scanning in CI: bandit + pip-audit (#21)
- Automatic issue/PR labeling with GitHub Actions (#20, #19)
- Structured exception hierarchy (#18)
- End-to-end integration tests: compliant, noncompliant, partial (#15)
- CLI integration tests: pass, fail, collection error, HTML-only, multi-device (#14)
- Parser error-path tests: missing template, malformed output, whitespace, no match (#13)
- Compliance edge-case tests: unknown rule, no servers, multiple violations, mixed results, empty checks (#12)
- mypy strict mode with type annotations (#11)
- GitHub Actions CI: pytest + ruff on push/PR (#10)
- Pydantic models for baseline schema validation (#6)
- SSH key-based authentication support (#5)
- `structlog` with secret redaction replacing `basicConfig` (#7)
- `CONTRIBUTING.md` with development guidelines, testing, and PR workflow (#9)
- `SECURITY.md` covering credential handling and disclosure process (#8)
- Issue templates for bugs and feature requests (#3, #4)

### Changed

- README installation docs: use `uv sync --group dev` and `pre-commit install` (#34)
- CLI options table updated with `--strict`, `--verbose`, `--version` entries (#33)

### Fixed

- Narrowed broad `except Exception` in `collect_device` (#4)
- Moved data files into `src/net_audit` and switched to `importlib.resources` (#3)
- Aligned SSH check_name with dispatch key in compliance (#2)
- Wired `parse_version` and `parse_config` in collector (#1)
- Removed unused imports flagged by ruff (#16)
- Corrected labeler overlaps and size-label config (#22)
- Made issue auto-labeler robust by creating missing labels (#20)

### Security

- Passwords stored as `SecretStr` (Pydantic), never rendered in logs or output
- Structlog processor redacts sensitive keys (`password`, `key_file`, `secret`, `passwd`, `token`)
- `--strict` mode enforces env-var-only passwords in CI/CD pipelines
