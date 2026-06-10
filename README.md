# Network Security & Compliance State Auditor

```
┌─────────────────────────────────────────────────────────────────┐
│                    NET-AUDIT ARCHITECTURE                       │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────────┐    │
│  │  YAML     │───▶│  Collector   │───▶│  TextFSM Parser    │    │
│  │  Inventory│    │  (Netmiko +  │    │  (CLI → JSON)      │    │
│  │  +Baseline│    │   ThreadPool)│    └────────┬───────────┘    │
│  └──────────┘    └──────┬───────┘             │                │
│                         │                      ▼                │
│                         │            ┌────────────────────┐    │
│                         │            │  Compliance Engine  │    │
│                         │            │  (4 Security Rules) │    │
│                         │            └────────┬───────────┘    │
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

**net-audit** solves this by automating the entire pipeline: connecting to infrastructure
via SSH, pulling live configurations, parsing them into structured data, and running
deterministic compliance checks against a hardened security blueprint.

## Solution

A Python CLI tool that:

1. **Connects in parallel** to multiple routers/switches via SSH (Netmiko + ThreadPool)
2. **Pulls live state** — `show ip interface brief`, `show version`, `show running-config`
3. **Parses unstructured CLI** into clean JSON using TextFSM templates
4. **Audits against baselines** — flags SSHv1, unauthorized VLANs, rogue NTP/syslog servers
5. **Generates reports** — professional Markdown and HTML with pass/fail summaries

Every layer is independently testable with mocked responses — no real network hardware required.

## Installation & Deployment

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Linux/macOS environment

### Step-by-step setup

```bash
# 1. Clone the repository
git clone <repository-url>
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
# Expected: 31 passed
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

### CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--inventory` | `inventories/devices.yaml` | Device inventory YAML path |
| `--baseline` | `baselines/security_baseline.yaml` | Security baseline YAML path |
| `--output` | `audit_report` | Output file prefix |
| `--format` | `both` | Output format: `md`, `html`, or `both` |
| `--workers` | `4` | Max parallel SSH connections |

### Output

The tool produces:
- **Terminal summary** — Rich table with per-device pass/fail status
- **audit_report.md** — Markdown report with detailed findings table
- **audit_report.html** — Styled HTML report for sharing

## Project Structure

```
net-audit/
├── pyproject.toml              # Build config, dependencies, pytest/ruff settings
├── README.md                   # This file
├── src/net_audit/
│   ├── __init__.py             # Package init, version
│   ├── cli.py                  # Typer CLI entry point
│   ├── config.py               # YAML inventory/baseline loader with env resolution
│   ├── models.py               # Pydantic data models
│   ├── collector.py            # Parallel SSH collector (Netmiko + ThreadPool)
│   ├── parser.py               # TextFSM parser (CLI → structured JSON)
│   ├── compliance.py           # Rule engine (4 security checks)
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
    ├── test_models.py          # 6 tests — Device, ComplianceResult, AuditReport
    ├── test_config.py          # 3 tests — inventory loading, env resolution
    ├── test_collector.py       # 3 tests — SSH collection, error handling
    ├── test_parser.py          # 6 tests — TextFSM parsing for all 3 commands
    ├── test_compliance.py      # 9 tests — all 4 rule types (pass/fail)
    └── test_reporter.py        # 4 tests — Markdown/HTML rendering
```

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
