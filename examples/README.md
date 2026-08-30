# Example manifests

Copy-paste Kubernetes and Helm samples for integrating this bridge with
External Secrets Operator (ESO).

Full walkthrough (mock mode, `bw-cli` mode, NetworkPolicy, token rotation):
[docs/eso-integration.md](../docs/eso-integration.md).

| File | Description |
| --- | --- |
| `00-namespace.yaml` | Optional `secrets-platform` namespace |
| `01-bridge-auth-secret.yaml` | Bridge + webhook bearer token Secret |
| `02-bridge-bw-credentials.secret.yaml` | Vaultwarden CLI credentials (`bw-cli`) |
| `03-clustersecretstore.yaml` | Webhook `ClusterSecretStore` |
| `04-externalsecret.yaml` | Single-key `ExternalSecret` |
| `05-externalsecret-multi-key.yaml` | Multi-key `ExternalSecret` |
| `06-externalsecret-bulk-datafrom.yaml` | Bulk multi-key `ExternalSecret` via `dataFrom.extract` |
| `07-admin-cronjob.yaml` | Lightweight `curlimages/curl` CronJob for admin ensure/rotate |
| `08-clustersecretstore-tokenreview.yaml` | Zero-shared-secret `ClusterSecretStore` via TokenReview SA auth |
 | `09-bridge-bws-credentials.secret.yaml` | Bitwarden Secrets Manager machine access token (`BWS_ACCESS_TOKEN`) |
 | `values-mock.yaml` | Helm values for mock backend |
 | `values-bw-cli.yaml` | Helm values for Vaultwarden backend |
 | `values-bws.yaml` | Helm values for Bitwarden Secrets Manager (BWS) native backend |
 
 Replace placeholder secrets before apply. Do not commit production credentials.
