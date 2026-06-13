# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-06-12

### Changed

- Renamed package from `net-audit` / `net_audit` to `audnet` everywhere: Python package, CLI entry point, PyPI project name, env vars (`AUDNET_PASSWORD`), docs, badges (#108, #109)
- Renamed GitHub repository from `islam666/net-audit` to `Elshayib/Audnet`

### Fixed

- CI badge URL updated to match renamed repo
- Release badge URL updated to match renamed repo
- Labeler config paths updated from `src/net_audit/` to `src/audnet/`
- Sample SSH key filename in inventory updated to `audnet_id_ed25519`
- Author email in `pyproject.toml` updated to match new GitHub username
- CHANGELOG section ordering corrected (Unreleased at top, versions descending)
- README CLI options table formatting fixed (double-pipe rows)
- `--connect-timeout` flag implemented in CLI to match documented behaviour
- README dry-run sample output version updated to current release
- README test count updated to reflect current suite size

## [0.1.1] - 2026-06-12

### Added

- `--async` flag for asyncio-based collector (asyncssh) — recommended for >20 devices (#88)
- `--no-fail` flag to exit with code 0 even when compliance checks fail (default: exit code 1 on failures) (#78)
- Hostname parsing from `show version` output (#73)
- Serial number parsing from `show version` output (#72)
- PyPI publish workflow — automated build and publish to PyPI on `v*` tags via Trusted Publishing (OIDC) (#90)
- PyPI version and Python version badges in README (#90)

### Fixed

- Strict mode now also checks `secret`, `passwd`, and `token` fields for plaintext passwords (#76)
- `CheckConfig` model missing `vendor_patterns` field — added with proper validation (#85)
- SSH host key verification not configurable in async collector (#84)
- Invalid device entries in inventory no longer abort entire load — skipped with warning (#83)
- Device order not preserved in `collect_all` results — now maintains insertion order (#82)
- Missing vendor TextFSM templates silently returned empty results — now raises `ParseError` (#81)
- `connect_timeout` passed as string instead of int in async collector (#79)
- Report templates not lazy-loaded — now loaded on demand with proper error handling (#77)
- Extra TextFSM fields in `ParsedVersion` caused validation errors — now ignored (#75)
- Baseline `check_name` not propagated to `ComplianceResult` — now correctly set (#74)
- `_check_no_open_ports` backward walk logic replaced with forward-scan interface tracking for correctness (#87)
- Magic slot indices in parser replaced with `Slot` enum for type safety (#86)

### Documentation

- Added quick-install section to README (#53)
- Added quick start guide (#80)
- Added GitHub Release badge to README (#51)
- Updated CONTRIBUTING.md release process to reflect automated PyPI publish (#90)

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
