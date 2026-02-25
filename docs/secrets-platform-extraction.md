# Secrets Platform Extraction Boundary

## Goal

Finalize the Phase 3 extraction boundary so the bridge is reusable as a pinned OCI chart without changing cluster-local secret manifests.

## Extractable Components

1. `grok-servaar/infra/secrets-platform/bridge/chart/vaultwarden-eso-bridge/`
2. `grok-servaar/infra/secrets-platform/bridge/tests/`
3. `scripts/test-eso-bridge-unit.sh`
4. `scripts/export-secrets-platform-bridge.sh`
5. `scripts/publish-secrets-platform-bridge-chart.sh`

## Cluster-Local Components (Do Not Extract)

1. `grok-servaar/infra/secrets-platform/clustersecretstore-vaultwarden-webhook.yaml`
2. `grok-servaar/infra/*externalsecret*.yaml`
3. `grok-servaar/mailu/*externalsecret*.yaml`
4. `grok-servaar/auth/*externalsecret*.yaml`
5. `grok-servaar/infra/secrets-platform/bootstrap-sealed/`

## Source Overlays

1. Active source: `grok-servaar/infra/secrets-platform/kustomization.yaml` -> `external-chart/`
2. OCI source: `grok-servaar/infra/secrets-platform/external-chart/kustomization.yaml` with pinned `vaultwarden-eso-bridge`
3. `local-chart/` remains in-repo only as fallback/test fixture and must not be the active source path.

## Frozen Bridge API Contract

`PHASE3_CONTRACT_API_FROZEN`

Required API behavior:

1. Endpoint: `GET /v1/secret/{namespace}/{secret}/{key}`
2. Auth: bearer token via `Authorization: Bearer <token>`
3. Success response: JSON object with required field `value` (string)
4. Key mapping rule: `{namespace}/{secret}` + `{key}` resolves one Vaultwarden field

## Frozen Helm Values Contract

`PHASE3_CONTRACT_HELM_VALUES_FROZEN`

Required values keys:

1. `backend.itemNameTemplate` (required, string)
2. `backend.vaultwarden.server` (required, string)
3. `backend.vaultwarden.organizationId` (required, string, may be empty)
4. `backend.vaultwarden.folderName` (required, string, may be empty)
5. `backend.bwCli.sessionKey` (required key, cluster default must be `""`)

## Frozen Compatibility Matrix

`PHASE3_CONTRACT_COMPAT_MATRIX_FROZEN`

| Local contract side | Bridge contract side | Required fields |
| --- | --- | --- |
| `ClusterSecretStore.spec.provider.webhook.url` path `/v1/secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}` | HTTP route `GET /v1/secret/{namespace}/{secret}/{key}` | `remoteRef.key`, `remoteRef.property` |
| `ExternalSecret.spec.data[].remoteRef.key` format `<namespace>/<secret-name>` | `backend.itemNameTemplate` (default `{namespace}/{secret}`) | `remoteRef.key`, `backend.itemNameTemplate` |
| `ExternalSecret.spec.data[].remoteRef.property` | JSON response body | `value` |
| Secret `vaultwarden-bridge-auth` | Bridge auth env | `BRIDGE_TOKEN` |
| Secret `vaultwarden-bridge-bw` | `bw-cli` bootstrap env | `BW_SERVER`, `BW_EMAIL`, `BW_PASSWORD` |

## OCI Version Pin Update Procedure

`PHASE3_OCI_PIN_UPDATE_PROCEDURE`

Pre-checks:

1. Confirm current pinned chart/version in `grok-servaar/infra/secrets-platform/external-chart/kustomization.yaml`.
2. Confirm new chart exists in GHCR: `helm show chart oci://ghcr.io/<org>/charts/vaultwarden-eso-bridge --version <new-version>`.
3. Run baseline contract checks:
- `scripts/test-eso-bridge-unit.sh`
- `scripts/test-eso-phase3-extraction-contract.sh`

Change points:

1. Update pinned chart version only in `grok-servaar/infra/secrets-platform/external-chart/kustomization.yaml`.
2. If contract keys changed, update:
- `docs/secrets-platform-extraction.md` (this file)
- `scripts/test-eso-phase3-extraction-contract.sh`

Validation commands:

1. `scripts/test-secrets-platform-render.sh grok-servaar/infra/secrets-platform/external-chart`
2. `scripts/test-eso-phase3-extraction-contract.sh`
3. `scripts/test-eso-vaultwarden-flow.sh`

Rollback:

1. Revert the pin in `grok-servaar/infra/secrets-platform/external-chart/kustomization.yaml` to the previous version.
2. Re-run:
- `scripts/test-secrets-platform-render.sh grok-servaar/infra/secrets-platform/external-chart`
- `scripts/test-eso-phase3-extraction-contract.sh`

## Required Validation Set

1. `scripts/test-eso-bootstrap-contract.sh`
2. `scripts/test-eso-phase1-infra-contract.sh`
3. `scripts/test-eso-phase2-auth-contract.sh`
4. `scripts/test-eso-phase3-extraction-contract.sh`
5. `scripts/test-eso-vaultwarden-flow.sh`

## Export Bundle Bootstrap Artifact

When running `scripts/export-secrets-platform-bridge.sh`, the generated bundle now includes:

1. `chart/vaultwarden-eso-bridge`
2. `tests`
3. `scripts/test-eso-bridge-unit.sh`
4. `scripts/publish-secrets-platform-bridge-chart.sh`
5. `docs/secrets-platform-extraction.md`
6. `CHECKLIST.md`

`CHECKLIST.md` is generated with concrete first-release commands (initialize repo, run tests, publish OCI chart, tag, and verify pull). Commands use placeholders and environment variables so the artifact stays reusable and non-cluster-specific.
