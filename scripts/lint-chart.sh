#!/usr/bin/env bash
# Lint and render the Vaultwarden ESO bridge chart.
#
# Shared by the tests workflow job `chart` and by publish-chart.yml (directly
# and through scripts/publish-secrets-platform-bridge-chart.sh). Both paths
# must keep calling this file so render checks cannot drift.
#
# kubeconform runs with -strict and without -ignore-missing-schemas.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${REPO_ROOT}/chart/vaultwarden-eso-bridge"
EXAMPLES_DIR="${REPO_ROOT}/examples"

# Pinned tools and schemas. Bump these on purpose; do not float to latest.
HELM_VERSION="${HELM_VERSION:-v3.16.1}"
KUBECONFORM_VERSION="${KUBECONFORM_VERSION:-v0.8.0}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.32.0}"
CRDS_CATALOG_REF="${CRDS_CATALOG_REF:-784ec895547a36e548e6810b41f27baade3a0890}"
SCHEMA_LOCATION="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRDS_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

TOOL_DIR="${REPO_ROOT}/.artifacts/tools"
mkdir -p "${TOOL_DIR}"

install_kubeconform() {
  if command -v kubeconform >/dev/null 2>&1; then
    local found
    found="$(kubeconform -v 2>&1 || true)"
    if [[ "${found}" == *"${KUBECONFORM_VERSION#v}"* ]]; then
      return 0
    fi
  fi

  local os arch asset url checksums sum
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "ERROR: unsupported architecture for kubeconform: $(uname -m)"
      exit 1
      ;;
  esac
  asset="kubeconform-${os}-${arch}.tar.gz"
  url="https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/${asset}"
  echo "Installing kubeconform ${KUBECONFORM_VERSION} (${asset})..."
  curl -fsSL -o "${TOOL_DIR}/${asset}" "${url}"
  curl -fsSL -o "${TOOL_DIR}/kubeconform-checksums.txt" \
    "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/CHECKSUMS"
  sum="$(awk -v f="${asset}" '$2 == f {print $1}' "${TOOL_DIR}/kubeconform-checksums.txt")"
  if [[ -z "${sum}" ]]; then
    echo "ERROR: checksum for ${asset} not found in kubeconform ${KUBECONFORM_VERSION} CHECKSUMS."
    exit 1
  fi
  echo "${sum}  ${TOOL_DIR}/${asset}" | sha256sum -c -
  tar -C "${TOOL_DIR}" -xzf "${TOOL_DIR}/${asset}" kubeconform
  chmod +x "${TOOL_DIR}/kubeconform"
  export PATH="${TOOL_DIR}:${PATH}"
}

if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: helm ${HELM_VERSION} is required on PATH."
  exit 1
fi

install_kubeconform
if ! command -v kubeconform >/dev/null 2>&1; then
  export PATH="${TOOL_DIR}:${PATH}"
fi

echo "helm: $(helm version --short)"
echo "kubeconform: $(kubeconform -v 2>&1)"
echo "kubernetes schemas: ${KUBERNETES_VERSION}"
echo "CRDs-catalog: ${CRDS_CATALOG_REF}"

shopt -s nullglob
example_files=("${EXAMPLES_DIR}"/values-*.yaml)
shopt -u nullglob
if [[ ${#example_files[@]} -eq 0 ]]; then
  echo "ERROR: no examples/values-*.yaml files found. Refusing to skip chart render."
  exit 1
fi

echo "Linting chart..."
helm lint "${CHART_DIR}"

kubeconform_cmd=(
  kubeconform
  -strict
  -summary
  -kubernetes-version "${KUBERNETES_VERSION}"
  -schema-location default
  -schema-location "${SCHEMA_LOCATION}"
  -output text
)

# Guard against a future edit that weakens schema checks.
for arg in "${kubeconform_cmd[@]}"; do
  if [[ "${arg}" == "-ignore-missing-schemas" || "${arg}" == "--ignore-missing-schemas" ]]; then
    echo "ERROR: -ignore-missing-schemas is not allowed."
    exit 1
  fi
done

render() {
  local label="$1"
  shift
  local rendered summary code
  # kubeconform ignores inputs that do not end in .yaml, .yml, or .json.
  rendered="$(mktemp --suffix=.yaml)"
  echo "Rendering ${label}..."
  helm template vaultwarden-eso-bridge "${CHART_DIR}" \
    --namespace secrets-platform \
    "$@" > "${rendered}"
  if [[ ! -s "${rendered}" ]]; then
    echo "ERROR: ${label} rendered empty output."
    rm -f "${rendered}"
    exit 1
  fi
  set +e
  summary="$("${kubeconform_cmd[@]}" "${rendered}" 2>&1)"
  code=$?
  set -e
  echo "${summary}"
  if [[ "${code}" -ne 0 ]]; then
    echo "ERROR: kubeconform failed for ${label} (exit ${code})."
    rm -f "${rendered}"
    exit "${code}"
  fi
  if [[ "${summary}" == *"0 resource found"* || "${summary}" != *"Invalid: 0"* ]]; then
    echo "ERROR: kubeconform did not validate resources for ${label}."
    rm -f "${rendered}"
    exit 1
  fi
  rm -f "${rendered}"
}

echo "Rendering default values..."
render "default values"

for values_file in "${example_files[@]}"; do
  helm lint "${CHART_DIR}" -f "${values_file}"
  render "example $(basename "${values_file}")" -f "${values_file}"
done

# Flag combinations. Each one exercises a conditional template path that the
# example values files do not all cover (RBAC, TLS volume, NetworkPolicy peers,
# ServiceMonitor, PrometheusRule, auto-generate RBAC, PDB).
render "flag tokenReview" \
  --set auth.mode=tokenReview \
  --set auth.tokenReview.enabled=true

render "flag dual" \
  --set auth.mode=dual \
  --set auth.tokenReview.enabled=true

render "flag tls" \
  --set tls.enabled=true \
  --set tls.existingSecret=eso-bridge-tls

render "flag networkPolicy" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.allowSameNamespace=false \
  --set-json 'networkPolicy.allowedPeers=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"external-secrets"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"external-secrets"}}}]'

render "flag networkPolicy deny-all peers" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.allowSameNamespace=false \
  --set-json 'networkPolicy.allowedPeers=[]'

render "flag serviceMonitor" \
  --set serviceMonitor.enabled=true

render "flag prometheusRule" \
  --set prometheusRule.enabled=true

render "flag autoGenerate" \
  --set provisioning.autoGenerate.enabled=true

# Both RBAC blocks (TokenReview and ExternalSecret list) in one render.
render "flag tokenReview+autoGenerate" \
  --set auth.mode=tokenReview \
  --set auth.tokenReview.enabled=true \
  --set provisioning.autoGenerate.enabled=true

render "flag podDisruptionBudget" \
  --set replicaCount=2 \
  --set podDisruptionBudget.enabled=true

render "flag combination" \
  --set auth.mode=dual \
  --set auth.tokenReview.enabled=true \
  --set tls.enabled=true \
  --set tls.existingSecret=eso-bridge-tls \
  --set networkPolicy.enabled=true \
  --set serviceMonitor.enabled=true \
  --set prometheusRule.enabled=true \
  --set provisioning.autoGenerate.enabled=true \
  --set replicaCount=2 \
  --set podDisruptionBudget.enabled=true

# External exposure is valid only with the documented opt-in.
render "allowExternalService LoadBalancer" \
  --set exposure.allowExternalService=true \
  --set service.type=LoadBalancer

# Negative cases. These must make `helm template` exit non-zero.
# Documented invalid combo: service.type other than ClusterIP without
# exposure.allowExternalService (README security defaults; templates/service.yaml).
expect_template_failure() {
  local label="$1"
  local needle="$2"
  shift 2
  local err_file
  err_file="$(mktemp)"
  echo "Expecting helm template failure: ${label}..."
  set +e
  helm template vaultwarden-eso-bridge "${CHART_DIR}" \
    --namespace secrets-platform \
    "$@" > /dev/null 2> "${err_file}"
  local code=$?
  set -e
  if [[ "${code}" -eq 0 ]]; then
    echo "ERROR: ${label} was expected to fail helm template, but it exited 0."
    rm -f "${err_file}"
    exit 1
  fi
  if ! grep -q "${needle}" "${err_file}"; then
    echo "ERROR: ${label} failed, but stderr did not contain: ${needle}"
    cat "${err_file}"
    rm -f "${err_file}"
    exit 1
  fi
  echo "Negative case exited ${code} as expected: ${label}"
  rm -f "${err_file}"
}

expect_template_failure \
  "NodePort without exposure.allowExternalService" \
  "Refusing external service exposure" \
  --set service.type=NodePort

expect_template_failure \
  "LoadBalancer without exposure.allowExternalService" \
  "Refusing external service exposure" \
  --set service.type=LoadBalancer

echo "Chart lint and kubeconform checks passed."
