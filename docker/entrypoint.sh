#!/usr/bin/env bash
# ============================================================
# audnet Docker entrypoint
#
# Commands:
#   cron  — run audnet on a schedule (default)
#   once  — run a single audit and exit
#   shell — drop into an interactive shell
# ============================================================
set -euo pipefail

INVENTORY="${AUDNET_INVENTORY:-/app/inventory/devices.yaml}"
BASELINE="${AUDNET_BASELINE:-/app/baselines/security_baseline.yaml}"
REPORTS="${AUDNET_REPORTS:-/app/reports}"
HISTORY_DIR="${AUDNET_HISTORY_DIR:-/app/.net-audit}"
CRON_SCHEDULE="${AUDIT_CRON:-0 * * * *}"

# Strict cron schedule allowlist (standard 5-field crontab expression)
_CRON_RE='^([0-9*,/-]+[[:space:]]+){4}[0-9*,/-A-Za-z]+$'

# Env vars that must be available to the audit process (credentials, etc.)
# Passed explicitly — never via unquoted string interpolation into shell -c.
_PASS_ENV_VARS=(
    AUDNET_INVENTORY
    AUDNET_BASELINE
    AUDNET_REPORTS
    AUDNET_HISTORY_DIR
    NETBOX_TOKEN
    AUDNET_PASSWORD
    AUDNET_SSH_STRICT_KEY
    AUDNET_SMTP_PASSWORD
    CORE_RTR_01_PASSWORD
    DIST_SW_01_PASSWORD
    EDGE_FW_01_PASSWORD
)

validate_paths() {
    # Reject path values that could break out of quoting / inject commands
    local p
    for p in "${INVENTORY}" "${BASELINE}" "${REPORTS}" "${HISTORY_DIR}"; do
        if [[ "${p}" == *$'\n'* ]] || [[ "${p}" == *$'\r'* ]]; then
            echo "[audnet] ERROR: path values must not contain newlines" >&2
            exit 1
        fi
        if [[ "${p}" == *'`'* ]] || [[ "${p}" == *'$('* ]]; then
            echo "[audnet] ERROR: path values must not contain command substitutions" >&2
            exit 1
        fi
    done
}

validate_cron() {
    if [[ ! "${CRON_SCHEDULE}" =~ ${_CRON_RE} ]]; then
        echo "[audnet] ERROR: invalid AUDIT_CRON schedule: ${CRON_SCHEDULE}" >&2
        echo "[audnet] Expected a 5-field crontab expression, e.g. '0 * * * *'" >&2
        exit 1
    fi
    if [[ "${CRON_SCHEDULE}" == *$'\n'* ]]; then
        echo "[audnet] ERROR: AUDIT_CRON must be a single line" >&2
        exit 1
    fi
}

run_as_audnet() {
    # Run a command as the audnet user while preserving allowlisted env vars.
    # Uses `su` WITHOUT login (-) so the environment is not wiped.
    # Arguments are passed as separate argv elements (no shell -c string build).
    local -a env_args=()
    local var
    for var in "${_PASS_ENV_VARS[@]}"; do
        if [[ -n "${!var-}" ]]; then
            env_args+=("${var}=${!var}")
        fi
    done
    # Always set the standard path vars from entrypoint defaults
    env_args+=(
        "AUDNET_INVENTORY=${INVENTORY}"
        "AUDNET_BASELINE=${BASELINE}"
        "AUDNET_REPORTS=${REPORTS}"
        "AUDNET_HISTORY_DIR=${HISTORY_DIR}"
    )
    # Prefer runuser if available; fall back to su without login shell
    if command -v runuser >/dev/null 2>&1; then
        runuser -u audnet -- env "${env_args[@]}" "$@"
    else
        # su without '-' preserves most env; we still set critical vars via env
        su audnet -s /bin/bash -c 'exec env "$@"' -- env "${env_args[@]}" "$@"
    fi
}

run_audit() {
    echo "[audnet] Starting audit at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[audnet] Inventory: ${INVENTORY}"
    echo "[audnet] Baseline:  ${BASELINE}"
    echo "[audnet] Reports:   ${REPORTS}"

    local exit_code=0
    run_as_audnet audnet audit \
        --inventory "${INVENTORY}" \
        --baseline "${BASELINE}" \
        --output "${REPORTS}/audit_report" \
        --history-dir "${HISTORY_DIR}" \
        --format both \
        2>&1 || exit_code=$?

    echo "[audnet] Audit complete at $(date -u +%Y-%m-%dT%H:%M:%SZ) (exit=${exit_code})"
    return "${exit_code}"
}

write_crontab() {
    # Write a controlled crontab that re-invokes this entrypoint with a fixed
    # command ('once'). Paths are baked as env assignments with single-quoted
    # values so they cannot expand shell metacharacters at cron runtime.
    local cron_file
    cron_file="$(mktemp)"
    # Escape single quotes in path values for safe single-quoting
    _sq() { printf "%s" "${1//\'/\'\\\'\'}"; }

    {
        echo "AUDNET_INVENTORY='$(_sq "${INVENTORY}")'"
        echo "AUDNET_BASELINE='$(_sq "${BASELINE}")'"
        echo "AUDNET_REPORTS='$(_sq "${REPORTS}")'"
        echo "AUDNET_HISTORY_DIR='$(_sq "${HISTORY_DIR}")'"
        # Token/password env vars are inherited from the process environment
        # when cron is started; they are not written into the crontab file.
        echo "${CRON_SCHEDULE} /usr/local/bin/entrypoint.sh once >> /var/log/audnet.log 2>&1"
    } > "${cron_file}"

    crontab -u root "${cron_file}"
    rm -f "${cron_file}"
    crontab -l
}

validate_paths

case "${1:-cron}" in
    once)
        run_audit
        exit $?
        ;;
    cron)
        validate_cron
        echo "[audnet] Scheduling audits with cron: ${CRON_SCHEDULE}"
        echo "[audnet] Inventory: ${INVENTORY}"
        echo "[audnet] Baseline:  ${BASELINE}"

        write_crontab

        # Run once immediately on startup
        run_audit || true

        # Start cron in foreground and tail logs
        echo "[audnet] Cron daemon started. Tailing logs..."
        touch /var/log/audnet.log
        chown audnet:audnet /var/log/audnet.log 2>/dev/null || true
        cron
        exec tail -f /var/log/audnet.log
        ;;
    shell|bash|sh)
        # Interactive shell as audnet (not root) when possible
        if command -v runuser >/dev/null 2>&1; then
            exec runuser -u audnet -- /bin/bash
        fi
        exec su audnet -s /bin/bash
        ;;
    *)
        # Allow arbitrary commands as audnet (e.g. `docker run audnet audnet version`)
        run_as_audnet "$@"
        ;;
esac
