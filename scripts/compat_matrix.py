#!/usr/bin/env python3
"""Check and render the ESO / bw CLI compatibility matrix.

Source of truth: compat/matrix.json
Generated page:  docs/compatibility.md

Remote checks confirm each listed External Secrets release exists and that
its install manifest serves the claimed CRDs. bw CLI checks confirm each
version is on npm. With --exercise-cli, each version is installed and its
help text is checked for the commands the bridge calls. No vault login and
no secret material is required.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


USER_AGENT = "vaultwarden-eso-bridge-compat-check"
MATRIX_REL = "compat/matrix.json"


class CompatError(Exception):
    """One matrix check failed."""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_matrix(root: Path) -> dict:
    path = root / MATRIX_REL
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise CompatError(f"{MATRIX_REL} must be a JSON object")
    return data


def render_markdown(matrix: dict) -> str:
    eso = matrix["eso"]
    bw = matrix["bw_cli"]
    vault = matrix["vaultwarden_integration"]
    recorded = matrix["recorded_on"]
    commands = ", ".join(f"`{cmd}`" for cmd in bw["required_commands"])
    pin_paths = ", ".join(f"`{item['path']}`" for item in matrix["pin_checks"])
    webhook_props = ", ".join(f"`{name}`" for name in eso["webhook_properties"])
    result_fields = ", ".join(f"`{name}`" for name in eso["webhook_result_fields"])
    absent = ", ".join(f"`{name}`" for name in eso["webhook_properties_absent"])

    eso_rows = []
    for release in eso["releases"]:
        stores = ", ".join(f"`{name}`" for name in release["store_apis_served"])
        push = ", ".join(f"`{name}`" for name in release["pushsecret_served"])
        eso_rows.append(
            "| {version} | {role} | {stores} | {push} | {notes} |".format(
                version=release["version"],
                role=release["role"],
                stores=stores,
                push=push,
                notes=release["notes"],
            )
        )

    bw_rows = []
    for item in bw["versions"]:
        shipped = "yes" if item["in_image"] else "no"
        bw_rows.append(
            f"| {item['version']} | {shipped} | {item['integration']} |"
        )

    lines = [
        "<!-- Generated from compat/matrix.json by scripts/check-compat-matrix.sh. Do not edit by hand. -->",
        "",
        "# Compatibility matrix",
        "",
        "Supported External Secrets Operator (ESO) releases and Bitwarden `bw` CLI",
        "versions for this bridge. Recorded on {recorded}.".format(recorded=recorded),
        "",
        "Regenerate this page after editing [`compat/matrix.json`](../compat/matrix.json):",
        "",
        "```bash",
        "python3 scripts/compat_matrix.py --write",
        "./scripts/check-compat-matrix.sh",
        "```",
        "",
        "1.0 gates that depend on this matrix are in [v1-release-criteria.md](v1-release-criteria.md).",
        "",
        "## How a version gets on this list",
        "",
        "ESO rows are release-manifest checks, not cluster installs. For each release,",
        "CI downloads `{asset}` from `{repo}` and reads the CRDs:".format(
            asset=eso["manifest_asset"],
            repo=eso["repository"],
        ),
        "",
        "- `ExternalSecret`, `SecretStore`, and `ClusterSecretStore` serve the APIs in the table.",
        f"- The webhook provider schema includes {webhook_props}. `result` includes {result_fields}.",
        f"- Those webhook schemas omit {absent}.",
        "- `PushSecret` serves the API in the table.",
        "",
        "ESO {since} is the first release whose ExternalSecret storage version is `v1`.".format(
            since=eso["v1_storage_since"]
        ),
        "Example manifests use `external-secrets.io/v1`. Releases older than that are outside this matrix.",
        "From ESO 0.10.0 onward, webhook Secrets need the label `external-secrets.io/type: webhook`.",
        "Every release below is newer than 0.10.0, and `examples/01-bridge-auth-secret.yaml` carries that label.",
        "",
        "`bw` rows start from the npm package `{pkg}`.".format(pkg=bw["package"]),
        "CI confirms the version is published. The compatibility workflow then installs it",
        "and checks `bw --help` for the subcommands the bridge invokes. That check does not",
        "log in and does not talk to Vaultwarden. Vaultwarden coverage is the opt-in integration",
        "test for the image pin only.",
        "",
        "The bridge image bakes one CLI (`Dockerfile` `BW_CLI_VERSION`). Helm",
        "`backend.bwCli.cliVersion` records that pin. The chart does not install a",
        "different CLI when the value changes. Pin locations: {paths}.".format(paths=pin_paths),
        "",
        "## External Secrets Operator",
        "",
        "| Release | Role | ExternalSecret / SecretStore / ClusterSecretStore served | PushSecret served | Notes |",
        "| --- | --- | --- | --- | --- |",
        *eso_rows,
        "",
        "The bridge lists ExternalSecrets at `external-secrets.io/v1` and, on HTTP 404,",
        "tries `v1beta1` (`chart/vaultwarden-eso-bridge/files/bridge_server.py`).",
        "0.16.2 serves both, so the `v1` list succeeds. The 1.x and 2.x rows serve",
        "`v1` only, so that list also stops on the first response.",
        "",
        "### Webhook contract these releases serve",
        "",
        "The ClusterSecretStore and SecretStore CRDs on each row above accept:",
        "",
        "- `spec.provider.webhook.url`",
        "- `spec.provider.webhook.method`",
        "- `spec.provider.webhook.headers`",
        "- `spec.provider.webhook.secrets`",
        "- `spec.provider.webhook.result.jsonPath`",
        "",
        "That is the contract `examples/03-clustersecretstore.yaml` uses.",
        "PushSecret examples use `external-secrets.io/v1alpha1`. ESO still marks that",
        "API alpha on every row in this table.",
        "",
        "### TokenReview and `serviceAccountRef`",
        "",
        "The bridge validates a Kubernetes ServiceAccount token when the caller sends",
        "one in `Authorization`. The webhook CRDs for the releases in this table omit",
        f"{absent}. `examples/08-clustersecretstore-tokenreview.yaml` sets",
        "`webhook.serviceAccountRef`. That field is outside the schema CI checks, so",
        "the apiserver drops it on apply. The supported way to give the webhook a bearer",
        "token is a Secret labeled `external-secrets.io/type: webhook`, as in",
        "`examples/01-bridge-auth-secret.yaml` and `examples/03-clustersecretstore.yaml`.",
        "",
        "## bw CLI",
        "",
        "| Version | Shipped in the bridge image | Vaultwarden coverage |",
        "| --- | --- | --- |",
        *bw_rows,
        "",
        f"Commands the bridge runs: {commands}.",
        "Login and unlock use `--passwordenv` plus the global `--raw` flag.",
        "`bw config server` sets the Vaultwarden URL. Attachment reads use",
        "`bw get attachment --itemid --output`. Create, edit, and delete pass",
        "base64 JSON that the bridge encodes itself (`bw encode` is not required).",
        "",
        f"Integration image: `{vault['image']}` in `{vault['compose_file']}`.",
        "The compose bridge service builds the Dockerfile, so it runs the pinned CLI.",
        "",
        "## Example manifests",
        "",
        "| Kind | apiVersion |",
        "| --- | --- |",
    ]
    for kind, api in matrix["eso"]["example_kinds"].items():
        lines.append(f"| `{kind}` | `{api}` |")
    lines.extend(
        [
            "",
            "CI reads every `examples/*.yaml` document. An `external-secrets.io` object",
            "whose kind or version is absent from this table fails the check.",
            "",
        ]
    )
    return "\n".join(lines)


def extract_crd(manifest: str, name: str) -> str:
    manifest = manifest.replace("\r\n", "\n")
    token = f"\n  name: {name}\n"
    idx = manifest.find(token)
    if idx < 0:
        raise CompatError(f"CRD {name} not found in manifest")
    start = manifest.rfind("\n---", 0, idx)
    start = 0 if start < 0 else start
    end = manifest.find("\n---", idx)
    if end < 0:
        end = len(manifest)
    return manifest[start:end]


def parse_versions(doc: str) -> list[dict]:
    """Return CRD version entries from a single manifest document."""
    lines = doc.replace("\r\n", "\n").splitlines()
    start = None
    for index, line in enumerate(lines):
        if line == "  versions:":
            start = index + 1
            break
    if start is None:
        raise CompatError("CRD versions block missing")
    entries: list[dict] = []
    current: dict | None = None
    for line in lines[start:]:
        if re.match(r"^  [A-Za-z]", line):
            break
        if line.startswith("    - "):
            if current is not None:
                entries.append(current)
            current = {
                "name": None,
                "served": True,
                "storage": False,
                "deprecated": False,
            }
            continue
        if current is None:
            continue
        name_match = re.match(r"^      name: (\S+)\s*$", line)
        if name_match and name_match.group(1).startswith("v"):
            current["name"] = name_match.group(1)
            continue
        flag_match = re.match(r"^      (served|storage|deprecated): (true|false)\s*$", line)
        if flag_match:
            current[flag_match.group(1)] = flag_match.group(2) == "true"
    if current is not None:
        entries.append(current)
    named = [entry for entry in entries if entry["name"]]
    if not named:
        raise CompatError("CRD versions block had no version names")
    return named


def _webhook_result_fields(block_lines: list[str]) -> list[str]:
    fields: list[str] = []
    in_result = False
    for line in block_lines:
        if re.match(r"^                        result:\s*$", line):
            in_result = True
            continue
        if in_result and re.match(r"^                        [A-Za-z0-9]+:\s*$", line):
            break
        if in_result:
            match = re.match(r"^                            ([A-Za-z0-9]+):\s*$", line)
            if match:
                fields.append(match.group(1))
    return fields


def webhook_blocks(doc: str) -> list[dict]:
    """Return webhook provider schema blocks inside one CRD document."""
    lines = doc.replace("\r\n", "\n").splitlines()
    found: list[dict] = []
    index = 0
    while index < len(lines):
        if lines[index] != "                    webhook:":
            index += 1
            continue
        block: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() == "" or line.startswith("                     "):
                block.append(line)
                index += 1
                continue
            break
        properties = []
        for line in block:
            match = re.match(r"^                        ([A-Za-z0-9]+):\s*$", line)
            if match:
                properties.append(match.group(1))
        found.append(
            {
                "properties": properties,
                "result_fields": _webhook_result_fields(block),
            }
        )
    return found


def check_webhook_blocks(blocks: list[dict], eso: dict, label: str) -> list[str]:
    errors: list[str] = []
    if not blocks:
        return [f"{label}: webhook provider schema not found"]
    required = list(eso["webhook_properties"])
    absent = list(eso["webhook_properties_absent"])
    result_fields = list(eso["webhook_result_fields"])
    for index, block in enumerate(blocks, start=1):
        props = block["properties"]
        missing = [name for name in required if name not in props]
        if missing:
            errors.append(f"{label} webhook #{index} missing properties {missing}")
        present_absent = [name for name in absent if name in props]
        if present_absent:
            errors.append(
                f"{label} webhook #{index} now defines {present_absent}; update the matrix"
            )
        got_fields = block["result_fields"]
        missing_fields = [name for name in result_fields if name not in got_fields]
        if missing_fields:
            errors.append(f"{label} webhook #{index} result missing {missing_fields}")
    return errors


def served_names(entries: list[dict]) -> list[str]:
    return sorted(entry["name"] for entry in entries if entry["served"])


def check_manifest_against_release(manifest: str, release: dict, eso: dict) -> list[str]:
    errors: list[str] = []
    version = release["version"]
    expected_stores = sorted(release["store_apis_served"])
    for crd_name in eso["store_crds"]:
        try:
            doc = extract_crd(manifest, crd_name)
            got = served_names(parse_versions(doc))
        except CompatError as exc:
            errors.append(f"ESO {version} {crd_name}: {exc}")
            continue
        if got != expected_stores:
            errors.append(
                f"ESO {version} {crd_name} serves {got}, matrix expects {expected_stores}"
            )
    try:
        push_doc = extract_crd(manifest, eso["pushsecret_crd"])
        push_got = served_names(parse_versions(push_doc))
    except CompatError as exc:
        errors.append(f"ESO {version} PushSecret: {exc}")
    else:
        expected_push = sorted(release["pushsecret_served"])
        if push_got != expected_push:
            errors.append(
                f"ESO {version} PushSecret serves {push_got}, matrix expects {expected_push}"
            )
    for crd_name in eso["webhook_crds"]:
        try:
            doc = extract_crd(manifest, crd_name)
        except CompatError as exc:
            errors.append(f"ESO {version} {crd_name}: {exc}")
            continue
        errors.extend(
            check_webhook_blocks(webhook_blocks(doc), eso, f"ESO {version} {crd_name}")
        )
    return errors


def _field(doc: str, field: str) -> str | None:
    match = re.search(rf"(?m)^{field}:\s*(\S+)\s*$", doc)
    return match.group(1) if match else None


def check_examples(root: Path, expected_kinds: dict) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for path in sorted((root / "examples").glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for doc in re.split(r"\n---\n", text):
            api = _field(doc, "apiVersion")
            kind = _field(doc, "kind")
            if not api or not api.startswith("external-secrets.io/"):
                continue
            if kind not in expected_kinds:
                errors.append(f"{path.name}: kind {kind} api {api} is not in the matrix")
                continue
            seen.add(kind)
            if api != expected_kinds[kind]:
                errors.append(
                    f"{path.name}: {kind} uses {api}, matrix requires {expected_kinds[kind]}"
                )
    for kind in ("ExternalSecret", "ClusterSecretStore", "PushSecret"):
        if kind not in seen:
            errors.append(f"examples/*.yaml contain no {kind}")
    return errors


def check_static(root: Path, matrix: dict) -> list[str]:
    errors: list[str] = []
    pinned = matrix["bw_cli"]["pinned"]
    image_versions = [item["version"] for item in matrix["bw_cli"]["versions"] if item["in_image"]]
    if image_versions != [pinned]:
        errors.append(
            f"exactly one bw CLI version must set in_image and match the pin {pinned}, got {image_versions}"
        )
    listed = [item["version"] for item in matrix["bw_cli"]["versions"]]
    if pinned not in listed:
        errors.append(f"pinned bw CLI {pinned} is absent from bw_cli.versions")
    if len(listed) != len(set(listed)):
        errors.append(f"duplicate bw CLI versions: {listed}")

    for item in matrix["pin_checks"]:
        path = root / item["path"]
        if not path.is_file():
            errors.append(f"pin file missing: {item['path']}")
            continue
        found = re.findall(item["regex"], path.read_text(encoding="utf-8"))
        if not found:
            errors.append(f"{item['path']} has no version matching the pin regex")
        elif any(value != pinned for value in found):
            errors.append(f"{item['path']} versions {found} differ from pin {pinned}")

    for link in matrix["doc_links"]:
        path = root / link["path"]
        if not path.is_file():
            errors.append(f"doc link target missing: {link['path']}")
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in link["must_contain"]:
            if snippet not in text:
                errors.append(f"{link['path']} is missing {snippet}")

    criteria_rel = matrix["criteria_doc"]
    criteria_path = root / criteria_rel
    if not criteria_path.is_file():
        errors.append(f"missing {criteria_rel}")
    else:
        criteria = criteria_path.read_text(encoding="utf-8")
        for snippet in matrix["criteria_required_snippets"]:
            if snippet not in criteria:
                errors.append(f"{criteria_rel} is missing {snippet!r}")
        image = matrix["vaultwarden_integration"]["image"]
        if image not in criteria:
            errors.append(f"{criteria_rel} must name integration image {image}")

    label = matrix["webhook_secret_label"]
    label_path = root / label["path"]
    if not label_path.is_file():
        errors.append(f"missing {label['path']}")
    elif label["contains"] not in label_path.read_text(encoding="utf-8"):
        errors.append(f"{label['path']} is missing {label['contains']}")

    workflow = matrix["workflow"]
    workflow_path = root / workflow["path"]
    if not workflow_path.is_file():
        errors.append(f"missing {workflow['path']}")
    else:
        workflow_text = workflow_path.read_text(encoding="utf-8")
        for snippet in workflow["must_contain"]:
            if snippet not in workflow_text:
                errors.append(f"{workflow['path']} is missing {snippet}")

    compose_rel = matrix["vaultwarden_integration"]["compose_file"]
    compose_path = root / compose_rel
    image = matrix["vaultwarden_integration"]["image"]
    if not compose_path.is_file():
        errors.append(f"missing {compose_rel}")
    elif image not in compose_path.read_text(encoding="utf-8"):
        errors.append(f"{compose_rel} does not reference {image}")

    errors.extend(check_examples(root, matrix["eso"]["example_kinds"]))

    generated_rel = matrix["generated_doc"]
    generated_path = root / generated_rel
    expected = render_markdown(matrix)
    if not generated_path.is_file():
        errors.append(f"missing generated doc {generated_rel}")
    else:
        actual = generated_path.read_text(encoding="utf-8")
        if actual != expected:
            errors.append(
                f"{generated_rel} is stale. Run: python3 scripts/compat_matrix.py --write"
            )
    return errors


def github_token() -> str:
    """Return a token for public GitHub API reads.

    GH_ADMIN_TOKEN is ignored on purpose. This check only reads public
    releases and must not pick up an admin credential.
    """
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def fetch_bytes(url: str, *, token: str = "", accept: str = "*/*") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise CompatError(f"GET {url} failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise CompatError(f"GET {url} failed: {exc.reason}") from exc


def check_eso_remote(matrix: dict) -> list[str]:
    errors: list[str] = []
    eso = matrix["eso"]
    token = github_token()
    repo = eso["repository"]
    asset = eso["manifest_asset"]
    for release in eso["releases"]:
        version = release["version"].lstrip("v")
        tag = f"v{version}"
        api = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
        try:
            payload = json.loads(fetch_bytes(api, token=token, accept="application/vnd.github+json"))
        except (CompatError, json.JSONDecodeError) as exc:
            errors.append(f"ESO release {tag} lookup failed: {exc}")
            continue
        names = [item.get("name") for item in payload.get("assets", [])]
        if asset not in names:
            errors.append(f"ESO release {tag} has no asset {asset} (found {names})")
            continue
        manifest_url = (
            f"https://github.com/{repo}/releases/download/{tag}/{asset}"
        )
        try:
            manifest = fetch_bytes(manifest_url, token="").decode("utf-8", "replace")
        except CompatError as exc:
            errors.append(str(exc))
            continue
        errors.extend(check_manifest_against_release(manifest, release, eso))
        print(f"checked ESO {tag} manifest ({len(manifest)} bytes)")
    return errors


def check_npm_versions(matrix: dict) -> list[str]:
    errors: list[str] = []
    package = matrix["bw_cli"]["package"]
    for item in matrix["bw_cli"]["versions"]:
        version = item["version"]
        url = f"https://registry.npmjs.org/{package}/{version}"
        try:
            payload = json.loads(fetch_bytes(url, accept="application/json"))
        except (CompatError, json.JSONDecodeError) as exc:
            errors.append(f"npm {package}@{version} lookup failed: {exc}")
            continue
        published = payload.get("version")
        if published != version:
            errors.append(f"npm {package}@{version} returned version {published!r}")
            continue
        print(f"checked npm {package}@{version}")
    return errors


def _scrub_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("BW_", "BWS_", "BRIDGE_")) or key == "GH_ADMIN_TOKEN":
            env.pop(key, None)
    env["npm_config_update_notifier"] = "false"
    return env


def _redact(text: str) -> str:
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]+", r"\1[redacted]", text)
    text = re.sub(r"(?i)(_authToken|token|password|secret)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    return text


def _run_bw(binary: str, args: list[str], env: dict[str, str]) -> tuple[str, str]:
    try:
        proc = subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise CompatError(f"bw {' '.join(args)} timed out") from exc
    if proc.returncode != 0:
        detail = _redact((proc.stderr or proc.stdout or "").strip())
        raise CompatError(f"bw {' '.join(args)} exited {proc.returncode}: {detail[:500]}")
    return proc.stdout, proc.stdout + "\n" + proc.stderr


def exercise_bw_cli(matrix: dict) -> list[str]:
    errors: list[str] = []
    package = matrix["bw_cli"]["package"]
    commands = matrix["bw_cli"]["required_commands"]
    help_checks = matrix["bw_cli"]["help_checks"]
    env = _scrub_env()
    for item in matrix["bw_cli"]["versions"]:
        version = item["version"]
        dest = Path(tempfile.mkdtemp(prefix=f"bw-{version}-"))
        try:
            try:
                proc = subprocess.run(
                    [
                        "npm",
                        "install",
                        "--prefix",
                        str(dest),
                        "--no-fund",
                        "--no-audit",
                        "--loglevel=error",
                        f"{package}@{version}",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                errors.append(f"npm install {package}@{version} timed out")
                continue
            except FileNotFoundError:
                errors.append("npm is not on PATH; cannot exercise bw CLI help")
                return errors
            if proc.returncode != 0:
                detail = _redact((proc.stderr or proc.stdout or "").strip())
                errors.append(f"npm install {package}@{version} failed: {detail[-800:]}")
                continue
            binary = dest / "node_modules" / ".bin" / "bw"
            if not binary.is_file():
                errors.append(f"{package}@{version} installed without a bw binary")
                continue
            try:
                stdout, _combined = _run_bw(str(binary), ["--version"], env)
                if version not in stdout.split():
                    errors.append(f"{version}: bw --version printed {stdout!r}")
                    continue
                help_stdout, help_combined = _run_bw(str(binary), ["--help"], env)
                for command in commands:
                    if not re.search(rf"(?m)^\s{{2}}{re.escape(command)}(?:\s|\[|$)", help_stdout):
                        errors.append(f"{version}: bw --help is missing command {command}")
                for check in help_checks:
                    args = list(check["args"])
                    if args == ["--help"]:
                        combined = help_combined
                    else:
                        _stdout, combined = _run_bw(str(binary), args, env)
                    for needle in check["contains"]:
                        if needle not in combined:
                            errors.append(
                                f"{version}: bw {' '.join(args)} is missing {needle}"
                            )
            except CompatError as exc:
                errors.append(f"{version}: {exc}")
                continue
            print(f"exercised bw CLI {version}")
        finally:
            shutil.rmtree(dest, ignore_errors=True)
    return errors


def write_doc(root: Path, matrix: dict) -> Path:
    path = root / matrix["generated_doc"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(matrix), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate docs/compatibility.md from compat/matrix.json",
    )
    parser.add_argument(
        "--exercise-cli",
        action="store_true",
        help="npm-install each bw CLI version and check help text",
    )
    parser.add_argument(
        "--skip-remote",
        action="store_true",
        help="skip npm and GitHub lookups (static checks only)",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    try:
        matrix = load_matrix(root)
    except (OSError, json.JSONDecodeError, CompatError) as exc:
        print(f"ERROR: {exc}")
        return 1
    if args.write:
        path = write_doc(root, matrix)
        print(f"wrote {path.relative_to(root)}")
    errors = check_static(root, matrix)
    if not args.skip_remote:
        errors.extend(check_npm_versions(matrix))
        errors.extend(check_eso_remote(matrix))
        if args.exercise_cli:
            errors.extend(exercise_bw_cli(matrix))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("compatibility matrix checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
