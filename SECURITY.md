# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead:

1. Go to the [Security tab](https://github.com/Elshayib/Audnet/security/advisories) of this repository
2. Click "Report a vulnerability"
3. Provide detailed information (reproduction steps, impact, affected versions)

We will respond within 48 hours and coordinate disclosure.

## Credential Handling

### The Risk

Inventory YAML files can contain plaintext passwords. If committed to version control or shared, this creates credential leakage risk. Even with `SecretStr` and log redaction, the password value exists in memory and could be exposed via process inspection, core dumps, or debuggers.

### Recommended: Environment Variables (Minimum)

Use `${ENV_VAR}` placeholders in inventory files. These are resolved at runtime from the environment:

```yaml
devices:
  - name: core-switch-01
    host: 10.0.0.1
    username: admin
    password: "${AUDNET_PASSWORD}"
```

```bash
export AUDNET_PASSWORD="your-secret-password"
audnet audit
```

### Recommended: External Secret Stores (Production)

For production deployments, use a dedicated secret manager:

**HashiCorp Vault:**
```bash
# Pull password from Vault before running
export AUDNET_PASSWORD=$(vault kv get -field=password secret/audnet)
audnet audit
```

**AWS Secrets Manager:**
```bash
export AUDNET_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id audnet/password \
  --query SecretString --output text)
audnet audit
```

**1Password CLI:**
```bash
export AUDNET_PASSWORD=$(op read "op://Private/audnet/password")
audnet audit
```

**Python keyring (local development):**
```python
import keyring
keyring.set_password("audnet", "core-switch-01", "secret-password")
```
```bash
# In inventory, reference via env var that keyring populates
export AUDNET_PASSWORD=$(python -c "import keyring; print(keyring.get_password('audnet', 'core-switch-01'))")
audnet audit
```

### Strict Mode

Use `--strict` in CI/CD pipelines to enforce that no plaintext passwords exist in inventory files:

```bash
audnet audit --strict
```

This causes the audit to fail with a `ConfigError` if any device has a password that is not a `${ENV_VAR}` reference.

### SSH Key Authentication

Prefer SSH key authentication over passwords:

```yaml
devices:
  - name: core-switch-01
    host: 10.0.0.1
    username: admin
    use_keys: true
    key_file: ~/.ssh/id_ed25519
```

### What audnet Does

- Passwords are stored as `SecretStr` (Pydantic) -- never rendered in logs or output
- Log redaction filters (`_redact_secrets`) mask password values in all log output
- Plaintext passwords in inventory files trigger a warning at load time
- `--strict` mode elevates the warning to a hard failure
- `NETBOX_TOKEN` is used for NetBox API authentication (see below)
- Git-backed config history sanitizes sensitive lines before committing (see below)

### Git-Backed Config History

When Git-backed config history is enabled (default), audnet stores sanitized device running configs
in a Git repository (`~/.net-audit/git-config-history`). Before committing, the following line types
are automatically redacted:

- `password`, `enable password`, `enable secret`
- `key string`, `key hash`
- `snmp-server community`
- `ip ospf message-digest-key`, `isis password`, `bgp password`
- `ntp authkey`, `tacacs-key`, `radius-key`, `pre-shared-key`, `auth-key`, `priv-key`
- `-----BEGIN ... PRIVATE KEY-----` blocks

Redacted lines are replaced with `! [REDACTED by audnet — <device_name>]`. The original config
on the device is not modified — only the stored snapshot is sanitized.

**Local vs remote repos:** By default, configs are stored in a local-only Git repo. If you
configure a remote (`git remote add origin ...`) and use `--git-push`, configs are pushed to
the remote. Ensure the remote repository is private and access-controlled — even though
configs are sanitized, device hostnames, interface names, and network topology information
is visible in the stored configs.

**Encrypting the Git repo:** For sensitive environments, consider encrypting the Git repository
at rest (e.g., `git-crypt`, `age`, or an encrypted filesystem). This provides defense-in-depth
in case the storage medium is compromised.

### NetBox Integration

When using `--inventory netbox://host`, audnet authenticates to NetBox via the `NETBOX_TOKEN` environment variable:

```bash
export NETBOX_TOKEN="your-netbox-api-token"
audnet audit --inventory netbox://netbox.example.com
audnet audit --inventory netbox://netbox.example.com?site=dc1&role=router
```

- The token is never logged or written to disk
- Treat it like a password: use a secret manager in production
- Generate tokens at `/api/users/tokens/` in NetBox
- Use read-only tokens with minimal permissions (`dcim > device > read`)

### What You Must Do

- **Never** commit inventory files with plaintext passwords to version control
- Add `inventories/*.yaml` to `.gitignore` (use `inventories/example.yaml` for templates)
- Use `.env` files for local development (add `.env` to `.gitignore`)
- Rotate passwords regularly
- Use dedicated service accounts with minimal privileges for auditing
- Audit who has access to inventory files and secret stores
- If using `--git-push`, ensure the remote Git repo is private and access-controlled
- Consider encrypting the Git config history repo at rest for sensitive environments

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless anonymity requested).
