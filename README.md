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
- `resources` for CPU/memory constraints

## Quick start (ESO examples)

Copy-paste `ClusterSecretStore` / `ExternalSecret` manifests and Helm values:

- [`examples/`](./examples/) — webhook store, ExternalSecrets, mock and `bw-cli` values
- [`docs/eso-integration.md`](./docs/eso-integration.md) — mock and Vaultwarden
  walkthroughs, NetworkPolicy guidance, and `BRIDGE_TOKEN` rotation

## Repository Contents

- `chart/vaultwarden-eso-bridge`: reusable Helm chart
- `examples`: end-to-end ESO webhook and ExternalSecret samples
- `tests`: bridge unit/contract tests
- `scripts/test-eso-bridge-unit.sh`: unit test entrypoint
- `scripts/publish-secrets-platform-bridge-chart.sh`: OCI publish helper
- `docs/eso-integration.md`: ESO integration walkthrough
- `docs/secrets-platform-extraction.md`: standalone extraction guidance
- `CHECKLIST.md`: first external-repo bootstrap and release checklist
