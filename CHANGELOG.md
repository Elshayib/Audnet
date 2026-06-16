# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `smtp_password` exposed as plain CLI option in `listen` command — visible in process listings and shell history (#167)
- `rollback` command name misleading — only rolls back git repo, not the actual device (#168)
- SNMP trap receiver implemented but never started by `RealtimeListener` — dead code path (#169)
- `scrapli` dependency duplicated in `pyproject.toml` — listed as both hard dep and optional extra (#170)
- `collector_async.py`: `known_hosts=None` disables SSH host key verification — should use system default (#176)

### Added

- `prompt=True, hide_input=True` for `smtp_password` CLI option with `AUDNET_SMTP_PASSWORD` env var support (#167)
- `git-rollback` command (renamed from `rollback`) with clarified docstring (#168)
- SNMP trap receiver startup in `RealtimeListener.start()` when `snmp_trap_bind_port > 0` (#169)
- `--timeout` option for `remediate` CLI command (#166)

### Documentation

- README vendor table updated: added Fortinet, Aruba, HP ProCurve, Cisco ASA (#172)
- README project structure tree updated with missing source and test files (#173)
- SECURITY.md version table updated: 0.2.x supported, 0.1.x EOL (#174)
- CHANGELOG.md updated with all recent bug fixes and features (#175)

### Build

- Added `fallback_version = "0.0.0"` to `[tool.hatch.version]` for builds without Git tags (#171)

## [0.2.0] - 2026-06-13

### Added

- **Multi-vendor support**: Juniper JunOS and Palo Alto PAN-OS with 6 new TextFSM templates (#121)
  - Juniper: `show ip interface brief`, `show version`, `show running-config`
  - Palo Alto: `show interface all`, `show system info`, `show config running`
- **NetBox dynamic inventory**: Fetch device inventory directly from NetBox API (#122)
  - `netbox://` URL scheme in inventory path with query param filters (`?site=dc1&role=router`)
  - Platform mapping for ios, iosxe, nxos, asa, junos, panos, arista_eos
  - Credential overrides via NetBox `config_context`
  - `NETBOX_TOKEN` environment variable for API authentication
- **Docker deployment**: Containerized auditing with scheduled cron support (#123)
  - Multi-stage Dockerfile (~70MB final image) using `python:3.14-slim`
  - `docker-compose.yml` with volumes for inventory, baseline, reports, and history
  - Entrypoint supports `cron` (default), `once`, and `shell` modes
  - Automatic image publish to `ghcr.io/elshayib/audnet` on `v*` tags
- **Auto-release workflow**: Automatic GitHub Release creation on `v*` tag push with generated release notes
- **SQLite audit history**: Persistent storage of audit runs with queryable history (#118)
  - `--history-dir` and `--no-history` CLI flags
  - `history` subcommand with `--device`, `--last`, `--since`, `--status`, `--format` filters (#120)
- **Drift/regression detection**: Compare current audit results against previous runs (#119)
  - Exit code 2 when new regressions detected
  - `--no-drift` flag to disable drift checking
  - Drift summary table in CLI output
- **Compliance checks**: 5 new Phase 2 compliance checks (#117)
  - `unused_iface_shutdown` (NIST CM-6)
  - `snmp_v3_only` (CIS 3.1)
  - Additional checks for banner, AAA, and NTP authentication

### Documentation

- Updated README with Docker deployment section
- Updated SECURITY.md with `NETBOX_TOKEN` documentation
- Updated CLI options table with all current flags
- Added `history` and `list-vendors` subcommand documentation
- Updated project structure tree and TextFSM template listing

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
