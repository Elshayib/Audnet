# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead:

1. Go to the [Security tab](https://github.com/islam666/net-audit/security/advisories) of this repository
2. Click "Report a vulnerability"
3. Provide detailed information (reproduction steps, impact, affected versions)

We will respond within 48 hours and coordinate disclosure.

## Credential Handling

### The Risk

Inventory YAML files can contain plaintext passwords. If committed to version control or shared, this creates credential leakage risk. Even with `SecretStr` and log redaction, the password value exists in the file on disk.

### Recommended: Environment Variables (Minimum)

Use `${ENV_VAR}` placeholders in inventory files. These are resolved at runtime from the environment:

```yaml
devices:
  - name: core-switch-01
    host: 10.0.0.1
    username: admin
    password: "${NET_AUDIT_PASSWORD}"
```

```bash
export NET_AUDIT_PASSWORD="your-secret-password"
net-audit audit
```

### Recommended: External Secret Stores (Production)

For production deployments, use a dedicated secret manager:

**HashiCorp Vault:**
```bash
# Pull password from Vault before running
export NET_AUDIT_PASSWORD=$(vault kv get -field=password secret/net-audit)
net-audit audit
```

**AWS Secrets Manager:**
```bash
export NET_AUDIT_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id net-audit/password \
  --query SecretString --output text)
net-audit audit
```

**1Password CLI:**
```bash
export NET_AUDIT_PASSWORD=$(op read "op://Private/net-audit/password")
net-audit audit
```

**Python keyring (local development):**
```python
import keyring
keyring.set_password("net-audit", "core-switch-01", "secret-password")
```
```bash
# In inventory, reference via env var that keyring populates
export NET_AUDIT_PASSWORD=$(python -c "import keyring; print(keyring.get_password('net-audit', 'core-switch-01'))")
net-audit audit
```

### Strict Mode

Use `--strict` in CI/CD pipelines to enforce that no plaintext passwords exist in inventory files:

```bash
net-audit audit --strict
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

### What net-audit Does

- Passwords are stored as `SecretStr` (Pydantic) — never rendered in logs or output
- Log redaction filters (`_redact_secrets`) mask password values in all log output
- Plaintext passwords in inventory files trigger a warning at load time
- `--strict` mode elevates the warning to a hard failure

### What You Must Do

- **Never** commit inventory files with plaintext passwords to version control
- Add `inventories/*.yaml` to `.gitignore` (use `inventories/example.yaml` for templates)
- Use `.env` files for local development (add `.env` to `.gitignore`)
- Rotate passwords regularly
- Use dedicated service accounts with minimal privileges for auditing
- Audit who has access to inventory files and secret stores

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless anonymity requested).
