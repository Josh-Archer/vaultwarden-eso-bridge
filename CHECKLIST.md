# Vaultwarden ESO Bridge Bootstrap Checklist

Use this checklist after copying this export bundle into an empty external repository.

## 1. Initialize the repository

```bash
git init
git add .
git commit -m "Bootstrap Vaultwarden ESO bridge package"
```

Optional (GitHub CLI):

```bash
gh repo create <owner>/<repo> --source=. --remote=origin --push
```

## 2. Run tests before first release

```bash
./scripts/test-eso-bridge-unit.sh
```

Optional (Docker required) real-Vaultwarden integration check:

```bash
./scripts/test-eso-bridge-integration.sh
```

## 3. Set release metadata and registry target

```bash
export RELEASE_VERSION="0.1.0"
export GHCR_REPOSITORY="<owner>/<charts-repo>"
export GHCR_USERNAME="<github-username-or-actor>"
export GHCR_TOKEN="<token-with-packages:write>"
```

## 4. Publish first OCI chart release

```bash
GHCR_REPOSITORY="${GHCR_REPOSITORY}" \
GHCR_USERNAME="${GHCR_USERNAME}" \
GHCR_TOKEN="${GHCR_TOKEN}" \
./scripts/publish-secrets-platform-bridge-chart.sh --version "${RELEASE_VERSION}"
```

## 5. Tag and push the release

```bash
git tag "vaultwarden-eso-bridge-v${RELEASE_VERSION}"
git push origin main
git push origin "vaultwarden-eso-bridge-v${RELEASE_VERSION}"
```

## 6. Post-release verification

```bash
helm pull "oci://ghcr.io/${GHCR_REPOSITORY}/vaultwarden-eso-bridge" --version "${RELEASE_VERSION}"
```

## Compatibility and 1.0

Supported External Secrets Operator and `bw` CLI versions:
[docs/compatibility.md](docs/compatibility.md).

Gates that must be true before tagging 1.0:
[docs/v1-release-criteria.md](docs/v1-release-criteria.md).

Check the matrix locally (needs network; installs each listed `bw` CLI and does not log in):

```bash
./scripts/check-compat-matrix.sh
```
