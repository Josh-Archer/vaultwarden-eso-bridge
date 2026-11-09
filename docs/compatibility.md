<!-- Generated from compat/matrix.json by scripts/check-compat-matrix.sh. Do not edit by hand. -->

# Compatibility matrix

Supported External Secrets Operator (ESO) releases and Bitwarden `bw` CLI
versions for this bridge. Recorded on 2026-11-09.

Regenerate this page after editing [`compat/matrix.json`](../compat/matrix.json):

```bash
python3 scripts/compat_matrix.py --write
./scripts/check-compat-matrix.sh
```

1.0 gates that depend on this matrix are in [v1-release-criteria.md](v1-release-criteria.md).

## How a version gets on this list

ESO rows are release-manifest checks, not cluster installs. For each release,
CI downloads `external-secrets.yaml` from `external-secrets/external-secrets` and reads the CRDs:

- `ExternalSecret`, `SecretStore`, and `ClusterSecretStore` serve the APIs in the table.
- The webhook provider schema includes `url`, `method`, `headers`, `secrets`, `result`. `result` includes `jsonPath`.
- Those webhook schemas omit `serviceAccountRef`.
- `PushSecret` serves the API in the table.

ESO 0.16.0 is the first release whose ExternalSecret storage version is `v1`.
Example manifests use `external-secrets.io/v1`. Releases older than that are outside this matrix.
From ESO 0.10.0 onward, webhook Secrets need the label `external-secrets.io/type: webhook`.
Every release below is newer than 0.10.0, and `examples/01-bridge-auth-secret.yaml` carries that label.

`bw` rows start from the npm package `@bitwarden/cli`.
CI confirms the version is published. The compatibility workflow then installs it
and checks `bw --help` for the subcommands the bridge invokes. That check does not
log in and does not talk to Vaultwarden. Vaultwarden coverage is the opt-in integration
test for the image pin only.

The bridge image bakes one CLI (`Dockerfile` `BW_CLI_VERSION`). Helm
`backend.bwCli.cliVersion` records that pin. The chart does not install a
different CLI when the value changes. Pin locations: `Dockerfile`, `chart/vaultwarden-eso-bridge/values.yaml`, `examples/values-bw-cli.yaml`, `.github/workflows/publish-chart.yml`.

## External Secrets Operator

| Release | Role | ExternalSecret / SecretStore / ClusterSecretStore served | PushSecret served | Notes |
| --- | --- | --- | --- | --- |
| 0.16.2 | Oldest release checked in CI | `v1`, `v1beta1` | `v1alpha1` | Last 0.16 patch. v1 is the storage version and v1beta1 is still served. ESO 0.16.0 is the first release that stores ExternalSecret as v1. ESO 0.15.1 serves v1beta1 only. |
| 1.3.2 | Latest 1.x checked in CI | `v1` | `v1alpha1` | v1beta1 is still declared on the CRD and is not served. |
| 2.14.0 | Latest 2.x when this matrix was recorded | `v1` | `v1alpha1` | Newest External Secrets release on 2026-11-09. v1beta1 is not served. |

The bridge lists ExternalSecrets at `external-secrets.io/v1` and, on HTTP 404,
tries `v1beta1` (`chart/vaultwarden-eso-bridge/files/bridge_server.py`).
0.16.2 serves both, so the `v1` list succeeds. The 1.x and 2.x rows serve
`v1` only, so that list also stops on the first response.

### Webhook contract these releases serve

The ClusterSecretStore and SecretStore CRDs on each row above accept:

- `spec.provider.webhook.url`
- `spec.provider.webhook.method`
- `spec.provider.webhook.headers`
- `spec.provider.webhook.secrets`
- `spec.provider.webhook.result.jsonPath`

That is the contract `examples/03-clustersecretstore.yaml` uses.
PushSecret examples use `external-secrets.io/v1alpha1`. ESO still marks that
API alpha on every row in this table.

### TokenReview and `serviceAccountRef`

The bridge validates a Kubernetes ServiceAccount token when the caller sends
one in `Authorization`. The webhook CRDs for the releases in this table omit
`serviceAccountRef`. `examples/08-clustersecretstore-tokenreview.yaml` sets
`webhook.serviceAccountRef`. That field is outside the schema CI checks, so
the apiserver drops it on apply. The supported way to give the webhook a bearer
token is a Secret labeled `external-secrets.io/type: webhook`, as in
`examples/01-bridge-auth-secret.yaml` and `examples/03-clustersecretstore.yaml`.

## bw CLI

| Version | Shipped in the bridge image | Vaultwarden coverage |
| --- | --- | --- |
| 2025.12.0 | yes | Opt-in CI runs scripts/test-eso-bridge-integration.sh. The bridge image bakes this CLI and talks to vaultwarden/server:1.34.3. |
| 2025.12.1 | no | npm metadata and CLI help only. No Vaultwarden login. |
| 2026.10.1 | no | npm metadata and CLI help only, on Node 22 or newer (package engines). The published image ships 2025.12.0. |

Commands the bridge runs: `config`, `login`, `unlock`, `sync`, `list`, `get`, `create`, `edit`, `delete`.
Login and unlock use `--passwordenv` plus the global `--raw` flag.
`bw config server` sets the Vaultwarden URL. Attachment reads use
`bw get attachment --itemid --output`. Create, edit, and delete pass
base64 JSON that the bridge encodes itself (`bw encode` is not required).

Integration image: `vaultwarden/server:1.34.3` in `tests/integration/docker-compose.yml`.
The compose bridge service builds the Dockerfile, so it runs the pinned CLI.

## Example manifests

| Kind | apiVersion |
| --- | --- |
| `ExternalSecret` | `external-secrets.io/v1` |
| `ClusterSecretStore` | `external-secrets.io/v1` |
| `SecretStore` | `external-secrets.io/v1` |
| `ClusterExternalSecret` | `external-secrets.io/v1` |
| `PushSecret` | `external-secrets.io/v1alpha1` |

CI reads every `examples/*.yaml` document. An `external-secrets.io` object
whose kind or version is absent from this table fails the check.
