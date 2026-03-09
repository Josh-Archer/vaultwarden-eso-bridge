FROM python:3.14-alpine

ARG BW_CLI_VERSION=2025.12.0

RUN apk add --no-cache nodejs npm \
    && npm install -g "@bitwarden/cli@${BW_CLI_VERSION}" \
    && bw --version >/dev/null

WORKDIR /app

CMD ["python", "/app/bridge_server.py"]
