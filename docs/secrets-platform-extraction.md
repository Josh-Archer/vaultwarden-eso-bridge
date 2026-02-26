# Bridge Extraction Boundary

## Goal

Keep the Vaultwarden ESO bridge reusable as a standalone chart and test bundle,
with no coupling to any single cluster repository layout.

## Portable Components

1. `chart/vaultwarden-eso-bridge/`
2. `tests/`
3. `scripts/test-eso-bridge-unit.sh`
4. `scripts/publish-secrets-platform-bridge-chart.sh`
5. `docs/secrets-platform-extraction.md`
6. `CHECKLIST.md`

## Local Integration Components (Keep Outside This Bundle)

1. Cluster-specific `ClusterSecretStore` and `ExternalSecret` manifests
2. Environment-specific overlay/kustomization files
3. Secret bootstrap manifests and sealed/encrypted secrets
4. Platform routing and certificate policy manifests

## Bridge API Contract

Required behavior:

1. Endpoint: `GET /v1/secret/{namespace}/{secret}/{key}`
2. Auth: `Authorization: Bearer <token>`
3. Success response: JSON object containing string field `value`
4. Key mapping: `{namespace}/{secret}` + `{key}` resolves one backend field

## Helm Values Contract

Required keys:

1. `backend.itemNameTemplate` (required string)
2. `backend.vaultwarden.server` (required for `bw-cli` mode)
3. `backend.vaultwarden.organizationId` (required key, may be empty)
4. `backend.vaultwarden.folderName` (required key, may be empty)
5. `backend.bwCli.sessionKey` (required key, may be empty; default `""`)

## Compatibility Matrix

| Consumer side | Bridge side | Required fields |
| --- | --- | --- |
| Webhook URL path `/v1/secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}` | HTTP route `GET /v1/secret/{namespace}/{secret}/{key}` | `remoteRef.key`, `remoteRef.property` |
| `remoteRef.key` format `<namespace>/<secret-name>` | `backend.itemNameTemplate` (default `{namespace}/{secret}`) | `remoteRef.key`, `backend.itemNameTemplate` |
| `remoteRef.property` | JSON response body field | `value` |
| Auth secret for bridge | `BRIDGE_TOKEN` env | token key configured by `auth.tokenKey` |
| Backend auth secret (`bw-cli`) | bw-cli bootstrap env | `BW_SERVER`, `BW_EMAIL`, `BW_PASSWORD` |

## OCI Pin/Upgrade Procedure

Pre-checks:

1. Confirm current pinned chart/version in your deployment manifests.
2. Confirm target chart exists:
   `helm show chart oci://ghcr.io/<org>/<repo>/vaultwarden-eso-bridge --version <new-version>`
3. Run unit tests: `./scripts/test-eso-bridge-unit.sh`

Change points:

1. Update only the pinned chart version in your environment manifests.
2. If API/values contracts change, update this document and tests in `tests/`.

Validation:

1. Render and validate your environment manifests against the new chart version.
2. Run `./scripts/test-eso-bridge-unit.sh`.
3. Run your platform integration tests for ESO webhook resolution.

Rollback:

1. Revert the chart version pin in your environment manifests.
2. Re-run render/unit/integration checks.

## Security Notes

1. Keep bridge service internal; avoid internet exposure.
2. Use `networkPolicy.enabled=true` plus explicit peers where supported.
3. Treat `BRIDGE_TOKEN` as a shared bearer credential and rotate regularly.
4. Prefer TLS for any hop that traverses untrusted network segments.
