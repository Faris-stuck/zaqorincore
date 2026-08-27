# Multi-stage build for the ZaqorinCore server.
# Final image is ~150MB, runs as non-root, hardened defaults.

FROM python:3.11-slim AS builder
WORKDIR /build

# Install build deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies into a prefix we can copy.
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

# ---- Final image ----
FROM python:3.11-slim
WORKDIR /app

# Create a non-root user.
RUN groupadd -r zaqorin && useradd -r -g zaqorin -d /app zaqorin

# Copy the installed packages from the builder.
COPY --from=builder /install /usr/local

# Copy the source so the package is discoverable.
COPY --chown=zaqorin:zaqorin src ./src
COPY --chown=zaqorin:zaqorin alembic.ini ./
COPY --chown=zaqorin:zaqorin migrations ./migrations

USER zaqorin
EXPOSE 8000

# Healthcheck hits the in-process liveness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3).read()" || exit 1

CMD ["python", "-m", "zaqorincore_server.main"]
