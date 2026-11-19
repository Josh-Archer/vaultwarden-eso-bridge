FROM python:3.14-alpine

ARG BW_CLI_VERSION=2025.12.0

RUN apk add --no-cache nodejs npm \
    && npm install -g "@bitwarden/cli@${BW_CLI_VERSION}" \
    && bw --version >/dev/null

# Run as a fixed non-root user. The bw CLI keeps its state (and HOME/npm
# caches) under /data, which the chart mounts as an emptyDir so the root
# filesystem can stay read-only.
RUN addgroup -g 10001 -S bridge \
    && adduser -u 10001 -S -G bridge -h /data -s /sbin/nologin bridge \
    && mkdir -p /data/bw \
    && chown -R 10001:10001 /data

ENV HOME=/data \
    BITWARDENCLI_APPDATA_DIR=/data/bw

WORKDIR /app

USER 10001:10001

CMD ["python", "/app/bridge_server.py"]
