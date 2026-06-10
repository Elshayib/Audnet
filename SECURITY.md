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

- **Never** hardcode passwords, API keys, or SSH private keys in code, configs, or git history.
- Use environment variables (e.g. `NET_AUDIT_PASSWORD`) or SSH agent/keys.
- Inventory files should reference secrets via `${VAR}` placeholders (resolved at runtime).
- Prefer SSH key authentication (`use_keys: true`) over password auth.
- Review `.env.example` and never commit `.env` files.

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless anonymity requested).
