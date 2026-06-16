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

run_audit() {
    echo "[audnet] Starting audit at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[audnet] Inventory: ${INVENTORY}"
    echo "[audnet] Baseline:  ${BASELINE}"
    echo "[audnet] Reports:   ${REPORTS}"

    # Run audit as non-root user
    su - audnet -s /bin/bash -c "audnet audit \
        --inventory \"${INVENTORY}\" \
        --baseline \"${BASELINE}\" \
        --output \"${REPORTS}/audit_report\" \
        --history-dir \"${HISTORY_DIR}\" \
        --format both" 2>&1 || true

    echo "[audnet] Audit complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

case "${1:-cron}" in
    once)
        run_audit
        ;;
    cron)
        echo "[audnet] Scheduling audits with cron: ${CRON_SCHEDULE}"
        echo "[audnet] Inventory: ${INVENTORY}"
        echo "[audnet] Baseline:  ${BASELINE}"

        # Write the cron schedule (runs as root, drops to audnet for audit)
        CRON_CMD="${CRON_SCHEDULE} cd /app && AUDNET_INVENTORY=${INVENTORY} AUDNET_BASELINE=${BASELINE} AUDNET_REPORTS=${REPORTS} AUDNET_HISTORY_DIR=${HISTORY_DIR} su - audnet -s /bin/bash -c '/usr/local/bin/entrypoint.sh once' >> /var/log/audnet.log 2>&1"
        echo "${CRON_CMD}" | crontab -
        crontab -l

        # Run once immediately on startup
        run_audit

        # Start cron in foreground
        echo "[audnet] Cron daemon started. Tailing logs..."
        touch /var/log/audnet.log
        cron && tail -f /var/log/audnet.log
        ;;
    shell|bash|sh)
        exec /bin/bash
        ;;
    *)
        # Allow arbitrary commands (e.g. `docker run audnet audnet --version)
        exec "$@"
        ;;
esac
