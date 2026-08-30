# Bitwarden Secrets Manager (BWS) Native Provider Integration

`vaultwarden-eso-bridge` supports native Bitwarden Secrets Manager (`BWS`) machine account authentication (`backend.mode: bws`) alongside classic Vaultwarden/Bitwarden Password Manager (`bw-cli`).

---

## Key Benefits of BWS Backend

1. **Zero Interactive Credentials**:
   * Uses machine access tokens (`BWS_ACCESS_TOKEN`) scoped to specific projects.
   * Does **not** require master passwords, personal user emails, or 2FA session unlocks.
2. **Machine-to-Machine Least Privilege**:
   * Machine accounts have read-only or read/write access restricted to explicitly granted projects.
3. **High Performance & Resilience**:
   * Native HTTP client lookups with in-memory positive and negative caching.
   * No heavy CLI subprocess initialization or session lock renewal required.

---

## 1. Machine Account Setup

1. In the Bitwarden Secrets Manager web UI, navigate to **Machine Accounts** and create a new machine account (e.g. `eso-bridge-worker`).
2. Grant access to the target projects containing your Kubernetes application secrets.
3. Generate and copy the **Access Token** (`0.00000000-0000-0000-0000-000000000000:Base64Secret...`).

---

## 2. Kubernetes Secret Provisioning

Create a secret in the `external-secrets` namespace containing your token:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: eso-bridge-bws
  namespace: external-secrets
type: Opaque
stringData:
  BWS_ACCESS_TOKEN: "0.00000000-0000-0000-0000-000000000000:YourBwsMachineAccessTokenHere"
```

---

## 3. Helm Deployment

Enable `backend.mode: bws` in your `values.yaml`:

```yaml
backend:
  mode: bws
  bws:
    enabled: true
    existingSecret: eso-bridge-bws
    accessTokenKey: BWS_ACCESS_TOKEN
    serverUrl: "https://vault.bitwarden.com/api" # Use https://vault.bitwarden.eu/api for EU cloud
    projectId: "" # Optional default project filter
    itemCacheTtlSeconds: 120
    negativeCacheTtlSeconds: 15
    commandTimeoutSeconds: 60
```

---

## 4. Secret Resolution Mapping

When ExternalSecrets queries the bridge (`GET /v1/secret/{namespace}/{secret}/{key}` or `GET /v1/secret/{namespace}/{secret}`):

1. **JSON Payload Secrets**:
   * Secret name in BWS: `{namespace}/{secret}` (e.g. `media/plex`)
   * Value in BWS: `{"token": "xyz", "client_id": "abc"}`
   * Resolves single keys or full bulk dictionary.
2. **Plain String Secrets**:
   * Secret name in BWS: `{namespace}/{secret}` or `{namespace}/{secret}/{key}`
   * Returns string value directly.
3. **Project-Scoped Secrets**:
   * Project name in BWS: `{namespace}`
   * Secret name in BWS: `{secret}`
