# Network Security & Compliance Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/islam666/net-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/islam666/net-audit/actions/workflows/ci.yml)

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

# 2. Create virtual environment
uv venv .venv
source .venv/bin/activate

# 3. Install with development dependencies
uv pip install -e ".[dev]"

# 4. Verify installation
python -c "import net_audit; print(net_audit.__version__)"
# Expected: 0.1.0

# 5. Run the test suite
pytest tests/ -v
# Expected: 31+ passed
```

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
| `--check` | (all) | Filter to specific checks (repeatable) |
| `--json` | false | Output JSON summary |

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
├── README.md                   # This file
├── src/net_audit/
│   ├── __init__.py             # Package init, version
│   ├── cli.py                  # Typer CLI entry point
│   ├── config.py               # YAML inventory/baseline loader with env resolution
│   ├── models.py               # Pydantic data models (incl. SecurityBaseline)
│   ├── vendor_registry.py      # Vendor registry for multi-vendor dispatch
│   ├── collector.py            # Parallel SSH collector (Netmiko + ThreadPool + retries)
│   ├── parser.py               # TextFSM parser (CLI → structured JSON, vendor-aware)
│   ├── compliance.py           # Rule engine (4 security checks, vendor-pattern overrides)
│   └── reporter.py             # Jinja2 report generator (Markdown + HTML)
├── templates/
│   ├── audit_report.md.j2      # Markdown report template
│   └── audit_report.html.j2    # HTML report template
├── textfsm_templates/
│   ├── cisco_ios_show_ip_interface_brief.textfsm
│   ├── cisco_ios_show_version.textfsm
│   └── cisco_ios_show_running_config.textfsm
├── inventories/
│   └── devices.yaml            # Sample device inventory
├── baselines/
│   └── security_baseline.yaml  # Compliance rules configuration
└── tests/
    ├── conftest.py             # Shared pytest fixtures
    ├── test_models.py          # Device, ComplianceResult, AuditReport
    ├── test_config.py          # Inventory loading, env resolution
    ├── test_collector.py       # SSH collection, error handling, vendor dispatch
    ├── test_parser.py          # TextFSM parsing, vendor-aware template selection
    ├── test_compliance.py      # All 4 rule types (pass/fail), case-insensitive
    ├── test_reporter.py        # Markdown/HTML rendering
    └── test_vendor_registry.py # Vendor profiles, dispatch, registration
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

Three steps — no changes to parser, collector, or compliance code:

**1. Add TextFSM templates** following the naming convention `<prefix>_<slot_suffix>.textfsm` in `textfsm_templates/`:

```
textfsm_templates/
├── juniper_junos_show_ip_interface_brief.textfsm
├── juniper_junos_show_version.textfsm
└── juniper_junos_show_running_config.textfsm
```

**2. Register the vendor** — either add to `VENDOR_PROFILES` in `vendor_registry.py`:

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

Or register at runtime:

```python
from net_audit.vendor_registry import register_vendor

register_vendor(
    device_type="juniper_junos",
    commands=["show interfaces terse", "show version", "show configuration"],
    template_prefix="juniper_junos",
)
```

**3. (Optional) Add vendor-specific compliance patterns** in your baseline YAML if the vendor uses different CLI syntax:

```yaml
checks:
  ssh_version:
    severity: critical
    rule: ssh_v2_only
    vendor_patterns:
      default:
        match: "set system ssh"
        ok_value: "set system ssh protocol-v2"
```

### How it works

- `vendor_registry.py` maps `device_type` to CLI commands and TextFSM template prefixes
- `collector.py` calls `get_commands(device_type)` instead of a hardcoded dict
- `parser.py` calls `get_template_name(device_type, slot)` for dynamic template loading
- `compliance.py` uses pattern-based matching with optional per-vendor overrides
- All vendor resolution falls back to `cisco_ios` for unknown device types

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

See [SECURITY.md](SECURITY.md) for credential handling and vulnerability reporting.
