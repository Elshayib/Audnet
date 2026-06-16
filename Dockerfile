# ============================================================
# Dockerfile for audnet — Network Security & Compliance Auditor
# ============================================================
# Multi-stage build to keep the final image small.
# Target: < 200MB
# ------------------------------------------------------------

# Stage 1: build wheel with uv
FROM python:3.14-slim AS builder

RUN pip install --no-cache-dir uv

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

ARG AUDNET_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${AUDNET_VERSION}

RUN uv build --wheel --out-dir /wheels

# Stage 2: runtime
FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="audnet"
LABEL org.opencontainers.image.description="Network Security & Compliance Auditor"
LABEL org.opencontainers.image.source="https://github.com/Elshayib/Audnet"
LABEL org.opencontainers.image.license="MIT"

# Install cron for scheduled audits
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash audnet

# Install audnet wheel
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Copy entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Volume mount points for config and output
RUN mkdir -p /app/inventory /app/baselines /app/reports /app/.net-audit && \
    chown -R audnet:audnet /app

WORKDIR /app

# Default cron schedule: hourly
ENV AUDIT_CRON="0 * * * *" \
    AUDNET_INVENTORY=/app/inventory/devices.yaml \
    AUDNET_BASELINE=/app/baselines/security_baseline.yaml \
    AUDNET_REPORTS=/app/reports \
    AUDNET_HISTORY_DIR=/app/.net-audit

VOLUME ["/app/inventory", "/app/baselines", "/app/reports", "/app/.net-audit"]

ENTRYPOINT ["entrypoint.sh"]
CMD ["cron"]
