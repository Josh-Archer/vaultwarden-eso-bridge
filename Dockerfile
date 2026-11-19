# Base image is pinned by digest (tag kept for readability). Renovate/Dependabot
# or a manual bump should update both together.
FROM python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67

# The Bitwarden CLI version and integrity hashes come from bw-cli/package.json
# and bw-cli/package-lock.json (single source of truth for the pin).
# Install scripts are disabled; if a dependency ever needs a postinstall step,
# allow it for that package by name rather than dropping --ignore-scripts.
COPY bw-cli/package.json bw-cli/package-lock.json /opt/bw-cli/

RUN apk add --no-cache nodejs npm \
    && cd /opt/bw-cli \
    && npm ci --ignore-scripts --omit=dev --no-audit --no-fund \
    && ln -s /opt/bw-cli/node_modules/.bin/bw /usr/local/bin/bw \
    && npm cache clean --force \
    && bw --version >/dev/null

WORKDIR /app

CMD ["python", "/app/bridge_server.py"]
