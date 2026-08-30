# End-to-end ESO integration walkthrough

Copy-paste manifests live under [`examples/`](../examples/). This guide walks
through mock and `bw-cli` modes, NetworkPolicy hardening, and `BRIDGE_TOKEN`
rotation.

## Prerequisites

- Kubernetes cluster with [External Secrets Operator](https://external-secrets.io/) installed
- Helm 3
- This repository (chart + examples)
- For `bw-cli` mode: a reachable Vaultwarden/Bitwarden server and an account
  that can read the target items

## Bridge ↔ ESO contract

| ESO field | Bridge behavior |
| --- | --- |
| Webhook URL path `/v1/secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}` | `GET /v1/secret/{namespace}/{secret}/{key}` (Single-key lookup) |
| Webhook URL path `/v1/secret/{{ .remoteRef.key }}` | `GET /v1/secret/{namespace}/{secret}` (Bulk multi-key JSON dictionary for `dataFrom.extract`) |
| Webhook URL path `/v1/secret/{{ .remoteRef.key }}/attachment/{{ .remoteRef.property }}` | `GET /v1/secret/{namespace}/{secret}/attachment/{filename}` (Binary file attachment) |
| `remoteRef.key` | `{namespace}/{secret}` item path (must match `backend.itemNameTemplate`) |
| `remoteRef.property` | Field / custom field / attachment name resolved by the backend |
| Success body (Single) | JSON `{"value":"<string>"}` via `result.jsonPath: "$.value"` |
| Success body (Bulk) | JSON `{"data":{"<key>":"<value>",...}}` and flat key-value pairs |
| Success body (Attachment) | JSON `{"value":"<base64>", "filename":"...", "size":N}` or binary octet-stream |
| Auth | `Authorization: Bearer <BRIDGE_TOKEN>` |

Keep the bridge `ClusterIP`-only. Do not expose it on the public internet.

---

## Path A — mock mode (local / CI)

Use this when you want deterministic ESO resolution without Vaultwarden.

### 1. Namespace and bridge token

```bash
kubectl apply -f examples/00-namespace.yaml
# Edit examples/01-bridge-auth-secret.yaml and set a strong token first.
kubectl apply -f examples/01-bridge-auth-secret.yaml
```

### 2. Install the chart with mock secrets

```bash
helm upgrade --install vaultwarden-eso-bridge ./chart/vaultwarden-eso-bridge \
  -n secrets-platform \
  -f examples/values-mock.yaml
```

`examples/values-mock.yaml` preloads paths used by the sample ExternalSecrets:

- `default/demo-app` → `password`, `username`
- `media/plex` → `username`, `password`, `token`

### 3. Register the ClusterSecretStore

```bash
kubectl apply -f examples/03-clustersecretstore.yaml
```

Confirm the store is ready:

```bash
kubectl get clustersecretstore vaultwarden-eso-bridge
```

### 4. Sync an ExternalSecret

```bash
kubectl apply -f examples/04-externalsecret.yaml
kubectl get externalsecret -n default demo-app-credentials
kubectl get secret -n default demo-app-credentials -o jsonpath='{.data.password}' | base64 -d
# expect: <example-only-mock-demo-password>
```

Optional multi-key sample (also covered by mock data):

```bash
kubectl create namespace media --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f examples/05-externalsecret-multi-key.yaml
```

### 5. Quick HTTP check (from inside the cluster)

```bash
TOKEN="$(kubectl get secret eso-bridge-auth -n secrets-platform -o jsonpath='{.data.token}' | base64 -d)"
kubectl run -n secrets-platform curl --rm -it --restart=Never --image=curlimages/curl -- \
  curl -sS -H "Authorization: Bearer ${TOKEN}" \
  "http://vaultwarden-eso-bridge.secrets-platform.svc:8080/v1/secret/default/demo-app/password"
# {"value":"<example-only-mock-demo-password>"}
```

---

## Path B — bw-cli mode (Vaultwarden)

### 1. Prepare Vaultwarden items

Default `backend.itemNameTemplate` is `{namespace}/{secret}`.

Create (or rename) items so names match ExternalSecret keys, for example:

- Item name: `default/demo-app`
  - Custom field `password` (or login password)
  - Optional custom field `username`
- Optional folder: set `backend.vaultwarden.folderName` (sample: `k8s-secrets`)
  and place items in that folder

Supported key aliases (see bridge implementation):

- Custom fields by exact `name`
- `username` / `login.username`, `password` / `login.password`
- `totp` / `login.totp`, `uri` / `login.uri`, `notes`

### 2. Credentials and chart install

```bash
kubectl apply -f examples/00-namespace.yaml
# Strong random token:
kubectl apply -f examples/01-bridge-auth-secret.yaml
# Edit BW_SERVER / BW_EMAIL / BW_PASSWORD:
kubectl apply -f examples/02-bridge-bw-credentials.secret.yaml

helm upgrade --install vaultwarden-eso-bridge ./chart/vaultwarden-eso-bridge \
  -n secrets-platform \
  -f examples/values-bw-cli.yaml
```

Wait for readiness (startup probe allows slow `bw` unlock/login):

```bash
kubectl rollout status deploy/vaultwarden-eso-bridge -n secrets-platform
kubectl logs -n secrets-platform deploy/vaultwarden-eso-bridge --tail=50
```

### 3. ESO store and ExternalSecret

Same store/ExternalSecret manifests as mock mode:

```bash
kubectl apply -f examples/03-clustersecretstore.yaml
kubectl apply -f examples/04-externalsecret.yaml
kubectl describe externalsecret -n default demo-app-credentials
```

If the ExternalSecret stays `SecretSyncedError`, check bridge logs for
`Secret path ... not found` / `Key ... not found` and verify item names and
field names in Vaultwarden. Newly created items may need a vault sync; the
bridge retries with `bw sync` on the first miss.

---

## NetworkPolicy notes

Sample values enable:

```yaml
networkPolicy:
  enabled: true
  allowSameNamespace: false
  allowedPeers:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: external-secrets
      podSelector:
        matchLabels:
          app.kubernetes.io/name: external-secrets
```

Guidance:

1. Prefer **deny-by-default ingress** to the bridge (`enabled: true`).
2. Set `allowSameNamespace: false` unless debug pods in the bridge namespace
   must call it.
3. Restrict `allowedPeers` to the ESO controller namespace and labels used by
   your install (Helm chart label names vary — confirm with
   `kubectl get pods -n external-secrets --show-labels`).
4. Health probes come from the kubelet on the node network; if your CNI
   enforces NetworkPolicy against probe traffic and probes fail, add the
   vendor-recommended probe exception or temporarily relax policy while
   debugging.
5. The chart still refuses `NodePort` / `LoadBalancer` unless
   `exposure.allowExternalService=true`.

---

## BRIDGE_TOKEN rotation

`BRIDGE_TOKEN` is a **shared bearer credential** used by:

1. Bridge Deployment env (`auth.existingSecret` / `auth.tokenKey`)
2. ESO webhook `Authorization` header (same Secret keys via ClusterSecretStore
   `secrets[].secretRef`)

Recommended rotation:

1. Generate a new high-entropy token.
2. Update the Kubernetes Secret (`eso-bridge-auth` key `token`) in place.
3. Restart bridge pods so they pick up the new env value:

   ```bash
   kubectl rollout restart deploy/vaultwarden-eso-bridge -n secrets-platform
   kubectl rollout status deploy/vaultwarden-eso-bridge -n secrets-platform
   ```

4. ESO reads the auth Secret on each webhook call (templated from
   `secretRef`); no ClusterSecretStore recreate is required if only the Secret
   data changed. Force a refresh if your ESO version caches aggressively:

   ```bash
   kubectl annotate externalsecret -n default demo-app-credentials \
     force-sync="$(date +%s)" --overwrite
   ```

5. Confirm ExternalSecrets return to `SecretSynced` and that unauthorized
   callers with the old token receive `401`.

Operational tips:

- Rotate on a schedule and after any suspected leak of the token Secret.
- Scope network access so only ESO can reach the Service (NetworkPolicy above).
- Prefer TLS (mesh / internal ingress) if traffic crosses untrusted segments;
  the sample URL is plain HTTP inside the cluster network.
- Do not commit real tokens; keep `examples/01-bridge-auth-secret.yaml` as a
  placeholder only.

---

## File map

| Path | Purpose |
| --- | --- |
| `examples/00-namespace.yaml` | `secrets-platform` namespace |
| `examples/01-bridge-auth-secret.yaml` | `BRIDGE_TOKEN` + ESO webhook label |
| `examples/02-bridge-bw-credentials.secret.yaml` | `BW_*` for `bw-cli` |
| `examples/03-clustersecretstore.yaml` | Webhook `ClusterSecretStore` |
| `examples/04-externalsecret.yaml` | Single-key `ExternalSecret` |
| `examples/05-externalsecret-multi-key.yaml` | Multi-key sample |
| `examples/values-mock.yaml` | Chart values: mock + NetworkPolicy |
| `examples/values-bw-cli.yaml` | Chart values: bw-cli + NetworkPolicy |

## Related docs

- [Security defaults and required values](../README.md)
- [Extraction boundary and API contract](./secrets-platform-extraction.md)
