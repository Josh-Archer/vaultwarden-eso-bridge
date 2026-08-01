# Vaultwarden ESO Bridge

Reusable Helm chart and tests for a Vaultwarden/Bitwarden-backed
External Secrets Operator (ESO) webhook bridge.

The default chart image is a purpose-built container that already includes
Python, Node.js, npm, and the pinned `bw` CLI version so the bridge does not
perform package installs at pod startup.

## Security Defaults

- Internal-only by default: chart `service.type` defaults to `ClusterIP`.
- Guardrail: setting `service.type` to `NodePort`/`LoadBalancer` fails unless
  `exposure.allowExternalService=true` is explicitly set.
- Optional ingress lock-down: enable `networkPolicy.enabled=true` and restrict
  callers with `networkPolicy.allowedPeers`.
- No internet exposure: run this bridge only inside trusted cluster networks.
- Bearer token limits: `BRIDGE_TOKEN` is a shared secret; rotate it regularly
  and scope network access so only ESO callers can reach the service.
- Token matching is strict by default (exact `Authorization: Bearer` value
  equals `BRIDGE_TOKEN`). Optional legacy quote/base64 expansion can mask
  misconfigured secrets—keep `auth.legacyTokenVariants=false` unless migrating.
- TLS recommendation: terminate TLS at your internal ingress/mesh/proxy if
  traffic crosses untrusted segments.

## Bearer Token Matching

| Mode | Env / chart | Accepted forms | Why |
| --- | --- | --- | --- |
| **Strict (default)** | `BRIDGE_TOKEN_LEGACY_VARIANTS=false` / `auth.legacyTokenVariants: false` | Exact equality of the bearer token string to `BRIDGE_TOKEN` (after normal header parse/trim of the `Bearer ` prefix) | Surfaces double-quoted, base64-encoded, or otherwise mis-set secrets immediately as `401` instead of appearing to work |
| **Legacy expand** | `BRIDGE_TOKEN_LEGACY_VARIANTS=true` / `auth.legacyTokenVariants: true` | Exact match, **or** (1) one layer of surrounding `"`/`'` stripped from the presented token, **or** (2) one strict base64 decode of the raw/unquoted form decoded as UTF-8 | Temporary bridge for callers or secret stores that historically wrapped or encoded the shared token; emits a **warning** log when a non-exact variant matches |

Prefer fixing the stored `BRIDGE_TOKEN` and client `Authorization` header so values match exactly, then leave legacy mode off.

## Required Secrets and Values

Required at minimum:
- `auth.existingSecret` with key `auth.tokenKey` containing `BRIDGE_TOKEN`
- `backend.itemNameTemplate` (default `{namespace}/{secret}`)
- `backend.mode` (`mock` or `bw-cli`)

For `backend.mode=bw-cli`, set:
- `backend.vaultwarden.server` (or secret key `BW_SERVER`)
- `backend.bwCli.existingSecret` with:
  - `BW_EMAIL`
  - `BW_PASSWORD`
  - optional `BW_SESSION`

Primary override points:
- `service.*` for port/type/annotations
- `exposure.allowExternalService` for explicit external exposure opt-in
- `networkPolicy.*` for ingress restrictions
- `probes.*` for liveness/readiness timing
- `resources` for CPU/memory constraints
- `backend.bwCli.itemCacheTtlSeconds` for optional hot-key caching (see below)

## Optional Hot-Key Cache (TTL)

In `bw-cli` mode the bridge can keep a short in-process cache of resolved
Vaultwarden items to cut repeated `bw` CLI latency when ESO reconciles the same
secrets in a burst.

| Setting | Env | Default | Notes |
| --- | --- | --- | --- |
| `backend.bwCli.itemCacheTtlSeconds` | `BW_ITEM_CACHE_TTL_SECONDS` | `0` (off) | Seconds to retain an item after a successful lookup |

**Staleness tradeoffs:** while an entry is cached, callers receive the last
resolved item fields even if the secret was rotated in Vaultwarden. Prefer
`0` (live lookups) unless you are mitigating ESO storms; if you enable it, keep
TTL short (for example `15`–`60` seconds) and accept delayed visibility of
rotations until the entry expires.

**Tenant safety:** cache entries are keyed by Kubernetes `namespace` + `secret`
name, so concurrent tenants never share a cache slot.

## Health probes and metrics

The bridge exposes three unauthenticated operational endpoints:

| Path | Purpose |
|------|---------|
| `/healthz` | Liveness. Always returns 200 while the HTTP server is up. |
| `/readyz` | Readiness. Returns 200 when the backend can serve lookups; **503** when the bw-cli session is invalid. |
| `/metrics` | Prometheus text metrics, including session-refresh counters. |

### Why readiness is separate from liveness

In `backend.mode=bw-cli`, the Bitwarden CLI session can die at runtime (logout,
expired unlock, vault lock). When that happens the bridge records a failed
auth refresh and marks itself not ready:

- **Readiness** (`/readyz`) fails so Kubernetes removes the pod from Service
  endpoints. External Secrets Operator (ESO) then stops hammering a bridge that
  cannot authenticate.
- **Liveness** (`/healthz`) stays healthy so the pod is not restart-looped
  while credentials or Vaultwarden recover.

Mock mode always reports ready.

### Chart probe configuration

```yaml
probes:
  readiness:
    # null keeps mode-aware defaults (45s for bw-cli, 5s for mock)
    initialDelaySeconds: null
    periodSeconds: 10
    failureThreshold: 3
  liveness:
    # null keeps mode-aware defaults (90s for bw-cli, 10s for mock)
    initialDelaySeconds: null
    periodSeconds: 20
    failureThreshold: 3

backend:
  bwCli:
    # Startup uses /readyz so the pod is not marked Ready until login succeeds.
    startupProbe:
      enabled: true
      periodSeconds: 10
      failureThreshold: 60
```

### Session refresh metrics

`GET /metrics` exposes (Prometheus exposition format):

- `bridge_auth_refresh_success_total` — successful runtime session refresh/login/unlock
- `bridge_auth_refresh_failure_total` — failed runtime session refresh attempts
- `bridge_bw_session_ready` — gauge `1`/`0` for current readiness (bw-cli only)

Initial startup auth does not increment the refresh counters; only runtime
re-auth after a lost session does.

## Tests

### Unit tests (default CI)

Mock-backed contract tests for path parsing, auth helpers, and bw-cli backend
behavior. These are the default gate and do not require Docker or Vaultwarden:

```bash
./scripts/test-eso-bridge-unit.sh
```

### Integration tests (optional, real Vaultwarden)

Optional docker-compose stack that stands up a real Vaultwarden with TLS, seeds
an account/item, runs the bridge in `bw-cli` mode, and asserts:

1. Missing/wrong bearer token → HTTP 401
2. Valid bearer token + secret path → HTTP 200 with the seeded value

```bash
# Prerequisites: Docker Compose, Python 3 with cryptography (for local cert gen)
./scripts/test-eso-bridge-integration.sh

# Leave the stack up for debugging
./scripts/test-eso-bridge-integration.sh --keep
```

Compose file: `tests/integration/docker-compose.yml`.

In GitHub Actions, unit tests run on every push/PR. The integration job is
opt-in via **Actions → tests → Run workflow → run_integration**.

Kind is not required for the compose path above; the same bridge image and
values can be exercised in a kind cluster if you already have a Vaultwarden
endpoint, but compose is the supported automated path.

## Repository Contents

- `chart/vaultwarden-eso-bridge`: reusable Helm chart
- `examples`: end-to-end ESO webhook and ExternalSecret samples
- `tests`: bridge unit/contract tests
- `tests/integration`: optional Vaultwarden docker-compose integration harness
- `scripts/test-eso-bridge-unit.sh`: unit test entrypoint
- `scripts/test-eso-bridge-integration.sh`: optional real-Vaultwarden integration test
- `scripts/publish-secrets-platform-bridge-chart.sh`: OCI publish helper
- `docs/eso-integration.md`: ESO integration walkthrough
- `docs/secrets-platform-extraction.md`: standalone extraction guidance
- `CHECKLIST.md`: first external-repo bootstrap and release checklist

## Container image platforms

Published bridge images are multi-arch (`linux/amd64` and `linux/arm64`) as of chart `0.1.8`.
