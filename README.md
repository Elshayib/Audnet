# Network Security & Compliance Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/islam666/net-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/islam666/net-audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/islam666/net-audit)](https://github.com/islam666/net-audit/releases/latest)

```
┌─────────────────────────────────────────────────────────────────┐
│                    NET-AUDIT ARCHITECTURE                       │
│
│  ┌──────────┐    ┌──────────────┐    ┌────────────────────┐    │
│  │  YAML     │───▶│  Collector   │───▶│  TextFSM Parser    │    │
│  │  Inventory│    │  (Netmiko +  │    │  (CLI → JSON)      │    │
│  │  +Baseline│    │   ThreadPool)│    └────────┬───────────┘    │
│  └──────────┘    └──────┬───────┘             │                │
│                         │                      ▼                │
│                         │            ┌────────────────────┐    │
│                         │            │  Compliance Engine  │    │
│                         │            │  (4 Security Rules) │    │
│                         │                     │                │
│                         ▼                     ▼                │
│              ┌──────────────────┐   ┌────────────────────┐    │
│              │  DeviceSnapshot  │──▶│  Report Generator   │    │
│              │  (Pydantic)      │   │  (Jinja2 → MD/HTML) │    │
│              └──────────────────┘   └────────────────────┘    │
│                                              │                │
│                                              ▼                │
│                                    ┌────────────────────┐    │
│                                    │  audit_report.md   │    │
│                                    │  audit_report.html │    │
│                                    └────────────────────┘    │
│                                                                 │
│  Parallel SSH ──▶ 4 devices concurrently (configurable)        │
│  All layers independently testable — no real hardware needed   │
└─────────────────────────────────────────────────────────────────┘
```

## Problem Statement

In production networks, configuration drift is inevitable. Engineers make manual changes
that bypass security baselines — enabling SSHv1, leaving switchports on default VLANs,
or pointing NTP/syslog to unauthorized servers. Traditional auditing is manual,
error-prone, and doesn't scale.

**net-audit** solves this by automating SSH-based compliance audits against security baselines.
This detects drift in real-time and prevents future drift by enforcing hardened policies.

## Solution

A Python CLI tool that:

1. **Connects in parallel** to multiple routers/switches via SSH (Netmiko + ThreadPool, with retries)
2. **Pulls live state** — `show ip interface brief`, `show version`, `show running-config`
3. **Parses unstructured CLI** into clean JSON using TextFSM templates
4. **Audits against baselines** — flags SSHv1, unauthorized VLANs, rogue NTP/syslog servers
5. **Generates reports** — professional Markdown and HTML with pass/fail summaries
6. **Supports filters & JSON** for targeted runs and CI integration

Every layer is independently testable with mocked responses — no real network hardware required.

## Installation & Deployment

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Linux/macOS environment

### Step-by-step setup

```bash
# 1. Clone the repository
git clone https://github.com/islam666/net-audit.git
cd net-audit

# 2. Install dependencies (uses uv.lock for reproducible installs)
uv venv
uv pip install -e ".[dev]"

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Install pre-commit hooks
pre-commit install

# 5. Verify installation
python -c "import net_audit; print(net_audit.__version__)"
# Expected: 0.1.0

# 6. Run the test suite
pytest tests/ -v
# Expected: 200+ passed
```

`uv pip install -e ".[dev]"` reads the committed `uv.lock` to install the exact same dependency versions across all environments. Use `uv lock` (no args) to regenerate the lockfile after adding new dependencies.

### Configure device inventory

Edit `inventories/devices.yaml` with your network devices:

```yaml
defaults:
  device_type: cisco_ios
  port: 22

devices:
  - name: core-router-01
    host: 192.168.1.1
    username: admin
    password: "${NET_AUDIT_PASSWORD}"  # resolved from environment
```

Set the password via environment variable:

```bash
export NET_AUDIT_PASSWORD="your-secret-password"
```

#### SSH key-based authentication

Instead of password authentication, use SSH keys:

```yaml
devices:
  - name: core-router-01
    host: 192.168.1.1
    username: admin
    use_keys: true
    key_file: ~/.ssh/id_ed25519
```

- `use_keys: true` — enable SSH key authentication
- `key_file` — path to the private key file (optional; uses SSH agent or default keys if omitted)

### Customize security baseline

Edit `baselines/security_baseline.yaml` to match your organization's policies:

```yaml
checks:
  ssh_version:
    severity: critical
    rule: ssh_v2_only

  inactive_ports:
    severity: high
    rule: no_open_ports
    allowed_vlans: [10, 20, 30]  # your secure VLANs

  ntp_config:
    severity: medium
    rule: ntp_approved
    approved_servers:
      - 10.0.0.50

  syslog_config:
    severity: medium
    rule: syslog_approved
    approved_servers:
      - 10.0.0.60
```

## Usage

### Run a full audit

```bash
source .venv/bin/activate
net-audit audit \
  --inventory inventories/devices.yaml \
  --baseline baselines/security_baseline.yaml \
  --output audit_report \
  --format both \
  --workers 4
```

### Advanced usage (new in this release)

Filter to one device or specific checks, output JSON for scripting:

```bash
net-audit audit --device core-router-01 --check ssh_v2_only,ntp_config --json
```

### Usage Examples

All examples below use the default inventory and baseline paths. Adjust as needed.

#### Audit a single device

```bash
net-audit audit --device core-router-01
```

#### Run specific checks only

Using comma-separated values in a single `--check`:

```bash
net-audit audit --check ssh_v2_only,ntp_config
```

Or repeat the flag:

```bash
net-audit audit --check ssh_v2_only --check ntp_config
```

#### JSON output for CI/CD pipelines

```bash
net-audit audit --json
```

Example output:

```json
[
  {
    "device_name": "core-router-01",
    "overall_pass": true,
    "checks": [
      {"check_name": "ssh_v2_only", "passed": true, "detail": "SSHv2 configured"},
      {"check_name": "ntp_approved", "passed": false, "detail": "unauthorized NTP: 10.0.0.99"}
    ]
  }
]
```

Pipe to `jq` for targeted queries:

```bash
net-audit audit --json | jq '.[] | select(.overall_pass == false) | .device_name'
```

#### Dry-run mode

Validate your config without touching devices:

```bash
net-audit audit --dry-run
```

Combine with filters to preview a targeted run:

```bash
net-audit audit --dry-run --device core-router-01 --check ssh_v2_only
```

#### Strict mode for CI

Fail immediately if any device has a plaintext password (no `${ENV_VAR}` reference):

```bash
net-audit audit --strict
```

#### Verbose debug logging

```bash
net-audit audit -v --dry-run
```

#### Combined: single device, specific check, JSON, strict

```bash
net-audit audit --device core-router-01 --check ssh_v2_only --json --strict
```

#### Show version

```bash
net-audit --version
```

### Sample Output

```text
$ net-audit audit --inventory inventories/devices.yaml
[INFO] Loaded 2 devices from inventory
[INFO] Connecting in parallel (workers=4)...
core-router-01: ✓ passed (4/4 checks)
dist-switch-02: ✗ failed (SSHv1 enabled, Gi0/3 on unauthorized VLAN 1)

Report: audit_report.md + audit_report.html generated.
Summary: 1 passed, 1 with issues.
```

### CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--inventory` | `inventories/devices.yaml` | Device inventory YAML path |
| `--baseline` | `baselines/security_baseline.yaml` | Security baseline YAML path |
| `--output` | `audit_report` | Output file prefix |
| `--format` | `both` | Output format: `md`, `html`, or `both` |
| `--workers` | `4` | Max parallel SSH connections |
| `--device` | (all) | Filter to single device by name |
| `--check` | (all) | Filter to specific checks (repeatable; comma-separated) |
| `--json` | `false` | Output JSON summary to stdout |
| `--dry-run`, `-n` | `false` | Validate config without connecting to devices |
| `--strict` | `false` | Fail on plaintext passwords (no `${ENV_VAR}` reference) |
| `-v`, `--verbose` | `false` | Enable debug logging with console output |
| `--version` | — | Show net-audit version and exit |

### Dry-run mode

Use `--dry-run` (or `-n`) to validate your inventory and baseline and preview what would be audited — no SSH connections made:

```bash
net-audit audit --inventory inventories/devices.yaml --dry-run
```

Output:
```
net-audit v0.1.0 — Starting audit...
Loaded 2 devices, 4 checks
DRY RUN — no device connections will be made
Devices that would be audited:
  • core-router-01 (192.168.1.1) — cisco_ios
  • dist-switch-02 (192.168.1.2) — cisco_ios
Checks that would be run:
  • inactive_ports
  • ntp_config
  • ssh_v2_only
  • syslog_config
Dry run complete — config and baseline are valid
```

Combine with `--device` and `--check` to filter the preview:
```bash
net-audit audit --dry-run --device core-router-01 --check ssh_v2_only
```

### Output

The tool produces:
- **Terminal summary** — Rich table with per-device pass/fail status
- **audit_report.md** — Markdown report with detailed findings table
- **audit_report.html** — Styled HTML report for sharing
- **JSON** (with --json) — Machine-readable for CI/CD

## Project Structure

```
net-audit/
├── pyproject.toml              # Build config, dependencies, pytest/ruff settings
├── CHANGELOG.md                # Release history (Keep a Changelog format)
├── CONTRIBUTING.md             # Development guidelines, testing, PR workflow
├── LICENSE                     # MIT License
├── README.md                   # This file
├── SECURITY.md                 # Security policy, credential handling, disclosure
├── uv.lock                     # Reproducible dependency lockfile
├── .pre-commit-config.yaml     # Pre-commit hooks (ruff, mypy, bandit, etc.)
├── benchmarks/
│   └── bench_collectors.py     # Sync vs async collector performance benchmarks
├── inventories/
│   └── devices.yaml            # Sample device inventory
├── baselines/
│   └── security_baseline.yaml  # Compliance rules configuration
├── src/net_audit/
│   ├── __init__.py             # Package init, version
│   ├── cli.py                  # Typer CLI entry point
│   ├── config.py               # YAML inventory/baseline loader with env resolution
│   ├── models.py               # Pydantic data models (incl. SecurityBaseline)
│   ├── exceptions.py           # Structured exception hierarchy
│   ├── vendor_registry.py      # Vendor registry for multi-vendor dispatch
│   ├── collector.py            # Parallel SSH collector (Netmiko + ThreadPool + retries)
│   ├── collector_async.py      # Asyncio collector (asyncssh + semaphore concurrency)
│   ├── parser.py               # TextFSM parser (CLI → structured JSON, vendor-aware)
│   ├── compliance.py           # Rule engine (4 security checks, vendor-pattern overrides)
│   ├── reporter.py             # Jinja2 report generator (Markdown + HTML)
│   ├── templates/
│   │   ├── __init__.py
│   │   ├── audit_report.md.j2  # Markdown report template
│   │   └── audit_report.html.j2 # HTML report template
│   └── textfsm_templates/
│       ├── __init__.py
│       ├── cisco_ios_show_ip_interface_brief.textfsm
│       ├── cisco_ios_show_version.textfsm
│       ├── cisco_ios_show_running_config.textfsm
│       ├── cisco_ios_show_interface_status.textfsm
│       └── cisco_ios_show_cdp_neighbors_detail.textfsm
└── tests/
    ├── __init__.py
    ├── conftest.py             # Shared pytest fixtures
    ├── test_models.py          # Device, ComplianceResult, AuditReport
    ├── test_config.py          # Inventory loading, env resolution
    ├── test_collector.py       # SSH collection, error handling, vendor dispatch
    ├── test_collector_async.py # Async collector: success, auth failure, timeout, mixed
    ├── test_parser.py          # TextFSM parsing, vendor-aware template selection
    ├── test_compliance.py      # All 4 rule types (pass/fail), case-insensitive
    ├── test_reporter.py        # Markdown/HTML rendering
    ├── test_vendor_registry.py # Vendor profiles, dispatch, registration
    ├── test_exceptions.py      # Exception hierarchy and inheritance
    ├── test_integration.py     # End-to-end: compliant, noncompliant, partial
    ├── test_logging.py         # Structlog configuration and secret redaction
    └── test_version.py         # Version string format and accessibility
```

## Multi-Vendor Support

net-audit uses a vendor registry/dispatch pattern (similar to NAPALM/Nornir driver architecture) for multi-vendor support. Device types are resolved automatically, with Cisco IOS as the fallback default.

### Supported vendors

| Vendor | device_type | Template prefix |
|--------|-------------|-----------------|
| Cisco IOS/IOS-XE | `cisco_ios` | `cisco_ios` |
| Cisco NX-OS | `cisco_nxos` | `cisco_nxos` |
| Arista EOS | `arista_eos` | `arista_eos` |

Unknown device types fall back to `cisco_ios` commands and templates.

### Configuring devices for different vendors

Set `device_type` per-device or as a default in your inventory YAML:

```yaml
defaults:
  device_type: cisco_ios

devices:
  - name: core-router-01
    host: 192.168.1.1
    username: admin
    password: "${NET_AUDIT_PASSWORD}"

  - name: nexus-switch-01
    host: 192.168.1.2
    device_type: cisco_nxos
    username: admin
    password: "${NET_AUDIT_PASSWORD}"

  - name: arista-leaf-01
    host: 192.168.1.3
    device_type: arista_eos
    username: admin
    password: "${NET_AUDIT_PASSWORD}"
```

### Adding a new vendor

Adding support for a new network OS takes three steps. No changes to parser, collector, or compliance code are needed — the vendor registry pattern handles dispatch automatically.

#### Step 1: Add TextFSM templates

Create one template per data slot in `textfsm_templates/`. The naming convention is `<prefix>_<slot_suffix>.textfsm`, where the suffix matches the slot names used by the built-in vendors:

| Slot | Purpose | Example suffix |
|------|---------|----------------|
| `show_ip_interface_brief` | Interface status | `show_ip_interface_brief` |
| `show_version` | Device version/info | `show_version` |
| `show_running_config` | Full running config | `show_running_config` |

For example, to add Juniper JunOS:

```
textfsm_templates/
├── juniper_junos_show_ip_interface_brief.textfsm
├── juniper_junos_show_version.textfsm
└── juniper_junos_show_running_config.textfsm
```

Each template should parse the vendor's equivalent CLI output into the same column names the compliance engine expects (e.g., `INTERFACE`, `IP_ADDRESS`, `STATUS`, `PROTOCOL` for interfaces).

**Tip:** Use the [TextFSM CLI tool](https://github.com/google/textfsm/wiki/TextFSM) to interactively test templates against sample output before committing.

#### Step 2: Register the vendor

You have two options — static registration (recommended for built-in vendors) or runtime registration (for plugins or dynamic use).

**Option A: Static registration** — add to `VENDOR_PROFILES` in `src/net_audit/vendor_registry.py`:

```python
VENDOR_PROFILES["juniper_junos"] = _profile(
    commands=[
        "show interfaces terse",
        "show version",
        "show configuration",
    ],
    prefix="juniper_junos",
    description="Juniper JunOS",
)
```

The `commands` list must have exactly three entries matching the three slots above (interface brief, version, running config). The `prefix` must match the TextFSM template filename prefix.

**Option B: Runtime registration** — call `register_vendor()` from your code or a plugin:

```python
from net_audit.vendor_registry import register_vendor

register_vendor(
    device_type="juniper_junos",
    commands=["show interfaces terse", "show version", "show configuration"],
    template_prefix="juniper_junos",
)
```

Runtime registration is useful for plugins, tests, or adding vendors without modifying the net-audit source.

#### Step 3: (Optional) Add vendor-specific compliance patterns

If the vendor uses different CLI syntax for the same security concepts, add `vendor_patterns` to your baseline YAML:

```yaml
checks:
  ssh_version:
    severity: critical
    rule: ssh_v2_only
    vendor_patterns:
      juniper_junos:
        match: "set system ssh"
        ok_value: "set system ssh protocol-v2"
```

The key under `vendor_patterns` must match the `device_type` used in the inventory. If no vendor-specific pattern is defined, the `default` pattern is used.

#### Step 4: Configure devices in inventory

Set the `device_type` on your devices to match the registered key:

```yaml
devices:
  - name: juniper-router-01
    host: 192.168.1.10
    device_type: juniper_junos
    username: admin
    password: "${NET_AUDIT_PASSWORD}"
```

That's it. The collector will automatically send the correct commands, the parser will load the correct templates, and the compliance engine will use the correct patterns.

#### Verifying your vendor

Run a dry-run to confirm the vendor is recognized:

```bash
net-audit audit --device juniper-router-01 --dry-run
```

Then run a full audit and check the output:

```bash
net-audit audit --device juniper-router-01 --json
```

### How it works

- `vendor_registry.py` maps `device_type` to CLI commands and TextFSM template prefixes
- `collector.py` calls `get_commands(device_type)` instead of a hardcoded dict
- `parser.py` calls `get_template_name(device_type, slot)` for dynamic template loading
- `compliance.py` uses pattern-based matching with optional per-vendor overrides
- All vendor resolution falls back to `cisco_ios` for unknown device types

## Performance & Scalability

### Current architecture: ThreadPool + Netmiko

The default collector (`collector.py`) uses `concurrent.futures.ThreadPoolExecutor`
with Netmiko for SSH. This works well for small-to-medium inventories (up to
~20 devices) but has limitations at scale:

- **Thread overhead**: Each concurrent connection consumes a thread (~8MB stack)
- **GIL contention**: Python's GIL limits true parallelism for CPU-bound parsing
- **Memory**: 100 devices × 4 threads = significant memory for thread stacks

### Async prototype: asyncio + asyncssh

An async collector prototype is available at `collector_async.py`. It replaces
threads with coroutines and uses `asyncssh` for SSH transport:

| Aspect | Sync (ThreadPool) | Async (asyncio) |
|--------|-------------------|-----------------|
| Concurrency model | OS threads | Coroutines |
| Memory per connection | ~8MB (thread stack) | ~1KB (coroutine) |
| Default `max_workers` | 4 | 50 |
| Scales to | ~20-50 devices | 100+ devices |
| Dependency | Netmiko | asyncssh |

### Running the benchmark

```bash
uv run python benchmarks/bench_collectors.py
```

This compares sync vs async collection across 4/8/16/32 devices with mocked
SSH responses. Results are written to `benchmarks/results.json`.

### Migration path

The async collector is a **prototype** — it produces identical `DeviceSnapshot`
output and shares the same parser, compliance, and vendor registry code.

To switch to async collection when scaling beyond ~50 devices:

1. Install asyncssh: `uv add asyncssh`
2. Change the import in `cli.py`:
   ```python
   # from net_audit.collector import collect_all
   from net_audit.collector_async import collect_all_async as collect_all
   ```
3. The `--workers` flag maps to `asyncio.Semaphore` limit (default: 50)
4. Keep the sync collector as fallback for environments without asyncssh

### Future: Scrapli

For production async deployments, consider migrating from `asyncssh` to
[Scrapli](https://github.com/scrapli/scrapli) which provides:

- Built-in multi-vendor support (replacing Netmiko's device-type abstraction)
- Both sync and async transports
- Structured parsing (replacing TextFSM for some platforms)
- Active community and regular updates

The vendor registry pattern in `vendor_registry.py` is already compatible —
Scrapli would replace only the SSH transport layer in the collector.

## Compliance Checks

| Check | Rule | Severity | What it detects |
|-------|------|----------|-----------------|
| SSH Version | `ssh_v2_only` | Critical | SSHv1 enabled or SSHv2 not configured |
| Inactive Ports | `no_open_ports` | High | Switchports in unauthorized VLANs |
| NTP Config | `ntp_approved` | Medium | NTP servers not in approved list |
| Syslog Config | `syslog_approved` | Medium | Syslog servers not in approved list |

### Adding a new compliance rule

1. Write a `_check_your_rule(snapshot, config) -> ComplianceResult` function in `compliance.py`
2. Add it to the `_RULE_DISPATCH` dict
3. Add the rule config to `baselines/security_baseline.yaml`
4. Write tests in `test_compliance.py`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, adding rules, testing, and PR workflow.

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=net_audit --cov-report=term-missing

# Run specific test file
pytest tests/test_compliance.py -v

# Lint
ruff check src/ tests/
```

All tests use mocked device responses — no real SSH connections or network hardware needed.

## Security

net-audit takes credential handling seriously. Passwords are stored as `SecretStr` (Pydantic) and are never rendered in logs or output.

### Quick Start: Environment Variables

Use `${ENV_VAR}` placeholders in inventory files:

```yaml
devices:
  - name: core-switch-01
    host: 10.0.0.1
    password: "${NET_AUDIT_PASSWORD}"
```

```bash
export NET_AUDIT_PASSWORD="your-secret"
net-audit audit
```

### Production: External Secret Stores

For production, use a dedicated secret manager instead of environment variables:

| Store             | Example                                      |
| ----------------- | -------------------------------------------- |
| HashiCorp Vault   | `export NET_AUDIT_PASSWORD=$(vault kv get ...)` |
| AWS Secrets Mgr   | `export NET_AUDIT_PASSWORD=$(aws secretsmanager ...)` |
| 1Password CLI     | `export NET_AUDIT_PASSWORD=$(op read ...)`   |
| Python keyring    | `keyring.set_password("net-audit", ...)`     |

See [SECURITY.md](SECURITY.md) for detailed integration examples.

### Strict Mode (CI/CD)

Use `--strict` in CI pipelines to enforce that no plaintext passwords exist in inventory files:

```bash
net-audit audit --strict
```

This fails with a `ConfigError` if any device has a password that is not a `${ENV_VAR}` reference. Without `--strict`, a warning is logged instead.

### SSH Key Authentication

Prefer SSH keys over passwords:

```yaml
devices:
  - name: core-switch-01
    host: 10.0.0.1
    use_keys: true
    key_file: ~/.ssh/id_ed25519
```

### Checklist

- **Never** commit inventory files with plaintext passwords
- Add `inventories/*.yaml` to `.gitignore` (commit only `inventories/example.yaml`)
- Use `.env` for local development (add `.env` to `.gitignore`)
- Use `--strict` in CI/CD
- Prefer SSH key authentication
- Rotate credentials regularly

See [SECURITY.md](SECURITY.md) for the full security policy, vulnerability reporting, and responsible disclosure.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes, new features, and bug fixes.
