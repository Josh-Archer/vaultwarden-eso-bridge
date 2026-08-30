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
| `values-mock.yaml` | Helm values for mock backend |
| `values-bw-cli.yaml` | Helm values for Vaultwarden backend |

Replace placeholder secrets before apply. Do not commit production credentials.
