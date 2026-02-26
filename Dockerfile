FROM python:3.12-slim

WORKDIR /app

# System deps: gpg for signing, curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install capauth with service extras
COPY pyproject.toml MANIFEST.in README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[service]"

# Data directory for SQLite keystore
RUN mkdir -p /data && chmod 777 /data

ENV CAPAUTH_DB_PATH=/data/keys.db
ENV CAPAUTH_SERVICE_ID=capauth.local
ENV CAPAUTH_BASE_URL=https://capauth.local

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8420/capauth/v1/status || exit 1

CMD ["capauth-service", "--host", "0.0.0.0", "--port", "8420"]
