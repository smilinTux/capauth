# DEPRECATED (2026-09-26): this image builds the standalone CapAuth
# verification-service container (published as ghcr.io/smilintux/capauth),
# used only by deploy/capauth-service/ and deploy/forgejo-capauth/. Chef
# decided 2026-09-26 that capauth runs on localhost as the existing loopback
# authz PDP (systemd --user unit, see SOP.md Scenario A); the standalone
# public verification-service mode this image serves is deprecated. PGP
# passwordless login for apps is covered by
# ghcr.io/smilintux/authentik-capauth (Dockerfile.authentik-capauth, a
# different image) instead. Not deleted, not changed in behavior: it still
# builds and runs the same as before.
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

# Phone-signer PWA static assets (served at /bunker/ by the service). app.py
# resolves these relative to the package root → /app/phone-signer.
COPY phone-signer/ ./phone-signer/

RUN pip install --no-cache-dir -e ".[service]"
RUN pip install --no-cache-dir python-multipart>=0.0.6

# Data directory for SQLite keystore
RUN mkdir -p /data && chmod 777 /data

ENV CAPAUTH_DB_PATH=/data/keys.db
ENV CAPAUTH_SERVICE_ID=capauth.local
ENV CAPAUTH_BASE_URL=https://capauth.local

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8420/capauth/v1/status || exit 1

CMD ["capauth-service", "--host", "0.0.0.0", "--port", "8420"]
