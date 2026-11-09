# 1.0 release criteria

The published chart is 0.9.x (`chart/vaultwarden-eso-bridge/Chart.yaml`). Tag `v1.0.0` when every gate below is true on the commit release-please tags. Supported versions are the [compatibility matrix](compatibility.md).

## Contract frozen at 1.0

These stay compatible for the whole 1.x line:

- Webhook paths and JSON bodies in [eso-integration.md](eso-integration.md): single-key `{"value":"..."}`, bulk data, and attachment responses.
- Auth defaults: exact `BRIDGE_TOKEN` match. TokenReview runs when the caller presents a Kubernetes ServiceAccount token.
- Backends: `mock`, `bw-cli`, and `bws`.
- Example `ExternalSecret` and `ClusterSecretStore` manifests use `external-secrets.io/v1`. `PushSecret` stays on `external-secrets.io/v1alpha1` while the matrix shows ESO serving that version.
- The image ships the single `bw` CLI pin in the matrix. `backend.bwCli.cliVersion` matches that pin. Changing the Helm value does not install a different CLI.

A break in that contract is a major release.

## Required before the 1.0 tag

1. **Matrix CI is green.** `scripts/check-compat-matrix.sh` passes on the release commit. The script checks that every External Secrets release and `@bitwarden/cli` version in `compat/matrix.json` still exists, that each release manifest still serves the APIs the matrix names, that example manifests still use those APIs, and that the image pin matches the Dockerfile, chart values, example values, and publish workflow. The CI job installs each listed `bw` CLI and checks help text for the commands the bridge runs.
2. **Unit tests pass.** `scripts/test-eso-bridge-unit.sh` is green on that commit.
3. **Vaultwarden integration has run on the candidate.** `scripts/test-eso-bridge-integration.sh` has passed on the 1.0 commit against the pinned `bw` CLI and the Vaultwarden image named in the matrix (`vaultwarden/server:1.34.3`). Link that Actions run in the release pull request. Ordinary pushes keep this job opt-in (`workflow_dispatch` input `run_integration`) because it needs Docker.
4. **Docs point here.** README and CHECKLIST link this page and the compatibility matrix.
5. **Security defaults stay in place.** Service type defaults to `ClusterIP`. `NodePort` and `LoadBalancer` still require `exposure.allowExternalService`. Bearer comparison stays strict unless `auth.legacyTokenVariants` is set. Examples keep placeholder credentials.
6. **Version metadata matches.** release-please sets the chart version and changelog from the tag. `Chart.yaml` `version` is `1.0.0` on the tagged commit.
7. **PushSecret stays best-effort.** Every ESO release in the matrix serves PushSecret as `external-secrets.io/v1alpha1`. 1.0 keeps write-back working against that alpha API. A stable PushSecret promise waits until ESO marks the API stable and the matrix records that version.

## Outside the 1.0 gate

- Cluster installs of every ESO release. The gate reads CRDs from each release's `external-secrets.yaml`.
- Bitwarden Secrets Manager or live Vaultwarden credentials in the default CI job.
- ESO releases older than 0.16.0. Those releases serve `external-secrets.io/v1beta1` as the storage version. The examples use `v1`.
- `bw` CLI versions absent from the matrix. Help-text coverage for a non-pinned version is a CLI surface check. Vaultwarden protocol coverage for 1.0 is the integration run of the image pin.
- `webhook.serviceAccountRef` as an ESO feature. The releases in the matrix omit that field. The supported webhook credential is a Secret labeled `external-secrets.io/type: webhook`.

## Keeping the matrix current after 1.0

Edit `compat/matrix.json`, regenerate the page, and run the check:

```bash
python3 scripts/compat_matrix.py --write
./scripts/check-compat-matrix.sh
```

Within 1.x, keep the pinned CLI's behavior and the webhook response shapes compatible. Dropping an ESO or `bw` version that this document still lists as supported is a major change.
