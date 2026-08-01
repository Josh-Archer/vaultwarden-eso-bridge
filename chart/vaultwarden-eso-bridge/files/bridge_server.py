#!/usr/bin/env python3
"""Vaultwarden ESO webhook bridge.

This bridge is intentionally backend-agnostic:
- mock mode for deterministic CI and local tests
- bw-cli mode for Vaultwarden/Bitwarden-backed lookups
"""

import base64
import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple, List
from urllib.parse import unquote, urlparse


LOGGER = logging.getLogger(__name__)


class BridgeError(RuntimeError):
    """Base class for bridge operational errors with optional operator hints."""

    code = "bridge_error"

    def __init__(self, message: str, *, hint: str = ""):
        super().__init__(message)
        self.hint = hint

    def log_message(self) -> str:
        """Format message plus actionable next steps for operators."""
        if self.hint:
            return f"{self} | next_steps: {self.hint}"
        return str(self)


class SecretLookupError(BridgeError):
    """Raised when a secret/item/key cannot be resolved."""

    code = "secret_not_found"


class AuthError(BridgeError):
    """Raised when bw CLI authentication/session/unlock fails."""

    code = "auth_error"


class InvalidJsonError(BridgeError):
    """Raised when bw CLI returns stdout that is not valid JSON."""

    code = "invalid_json"


class BwCliError(BridgeError):
    """Raised for non-auth bw CLI command failures."""

    code = "bw_cli_error"


# (substring, error class, operator hint) — first match wins (case-insensitive).
_BW_ERROR_RULES: Tuple[Tuple[str, type, str], ...] = (
    (
        "not logged in",
        AuthError,
        "Re-authenticate: refresh BW_SESSION or set BW_EMAIL/BW_PASSWORD so the bridge can login.",
    ),
    (
        "vault is locked",
        AuthError,
        "Unlock the vault: provide BW_PASSWORD (or a valid unlocked BW_SESSION).",
    ),
    (
        "session key is invalid",
        AuthError,
        "Refresh BW_SESSION or re-login with BW_EMAIL/BW_PASSWORD.",
    ),
    (
        "session has expired",
        AuthError,
        "Refresh BW_SESSION or re-login with BW_EMAIL/BW_PASSWORD.",
    ),
    (
        "invalid master password",
        AuthError,
        "Check BW_PASSWORD; unlock/login credentials are wrong.",
    ),
    (
        "username or password is incorrect",
        AuthError,
        "Check BW_EMAIL and BW_PASSWORD.",
    ),
    (
        "authentication failed",
        AuthError,
        "Re-authenticate against Vaultwarden (BW_SESSION or BW_EMAIL/BW_PASSWORD).",
    ),
    (
        "unauthorized",
        AuthError,
        "Re-authenticate against Vaultwarden (BW_SESSION or BW_EMAIL/BW_PASSWORD).",
    ),
    (
        "already logged in",
        AuthError,
        "Account is already logged in; bridge will unlock with BW_PASSWORD if configured.",
    ),
    (
        "econnrefused",
        AuthError,
        "Verify VAULTWARDEN_SERVER/BW_SERVER is reachable from the bridge pod.",
    ),
    (
        "enotfound",
        AuthError,
        "Verify VAULTWARDEN_SERVER/BW_SERVER hostname resolves and is correct.",
    ),
    (
        "getaddrinfo",
        AuthError,
        "Verify VAULTWARDEN_SERVER/BW_SERVER hostname resolves and is correct.",
    ),
    (
        "certificate",
        AuthError,
        "Check TLS trust for VAULTWARDEN_SERVER/BW_SERVER (custom CA or NODE_EXTRA_CA_CERTS).",
    ),
    (
        "self signed",
        AuthError,
        "Check TLS trust for VAULTWARDEN_SERVER/BW_SERVER (custom CA or NODE_EXTRA_CA_CERTS).",
    ),
)


def classify_bw_cli_failure(detail: str) -> BridgeError:
    """Map bw CLI stderr/stdout detail to a distinct bridge error class."""
    text = (detail or "").strip() or "unknown bw CLI failure"
    lowered = text.lower()
    for needle, exc_type, hint in _BW_ERROR_RULES:
        if needle in lowered:
            return exc_type(f"bw CLI failed: {text}", hint=hint)
    return BwCliError(
        f"bw CLI failed: {text}",
        hint="Inspect bridge logs and bw CLI output; confirm server URL, auth, and network.",
    )


def load_mock_secrets(raw: str) -> Dict[str, Dict[str, str]]:
    """Parse mock secret map from JSON string."""
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("MOCK_SECRETS_JSON must be a JSON object")
    normalized: Dict[str, Dict[str, str]] = {}
    for path, values in parsed.items():
        if not isinstance(path, str) or not isinstance(values, dict):
            raise ValueError("MOCK_SECRETS_JSON items must be path -> object")
        normalized[path] = {str(k): str(v) for k, v in values.items()}
    return normalized


def extract_value_from_bw_item(item: Dict, key: str) -> Optional[str]:
    """Resolve a key from a Bitwarden item object."""
    for field in item.get("fields", []) or []:
        if field.get("name") == key and field.get("value") is not None:
            return str(field.get("value"))

    login = item.get("login", {}) or {}
    if key in ("username", "login.username") and login.get("username"):
        return str(login["username"])
    if key in ("password", "login.password") and login.get("password"):
        return str(login["password"])
    if key in ("totp", "login.totp") and login.get("totp"):
        return str(login["totp"])
    if key in ("uri", "login.uri"):
        uris = login.get("uris") or []
        if uris and isinstance(uris[0], dict) and uris[0].get("uri"):
            return str(uris[0]["uri"])

    if key == "notes" and item.get("notes"):
        return str(item["notes"])

    return None


def parse_positive_int_env(name: str, default: int) -> int:
    """Parse a positive integer environment value with fallback."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def parse_bool_env(name: str, default: bool) -> bool:
    """Parse a boolean environment value with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if not value:
        return default
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default


@dataclass
class BridgeConfig:
    """Runtime config for bridge server."""

    token: str
    token_legacy_variants: bool
    backend_mode: str
    item_name_template: str
    mock_secrets: Dict[str, Dict[str, str]]
    vaultwarden_folder: str
    vaultwarden_org_id: str
    bw_server: str
    bw_email: str
    bw_password: str
    bw_session: str
    bw_path: str
    bw_item_cache_ttl_seconds: int
    bw_command_timeout_seconds: int


class AuthMetrics:
    """Thread-safe counters for bw-cli session refresh outcomes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.auth_refresh_success_total = 0
        self.auth_refresh_failure_total = 0

    def record_success(self) -> None:
        with self._lock:
            self.auth_refresh_success_total += 1

    def record_failure(self) -> None:
        with self._lock:
            self.auth_refresh_failure_total += 1

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return {
                "auth_refresh_success_total": self.auth_refresh_success_total,
                "auth_refresh_failure_total": self.auth_refresh_failure_total,
            }

    def render_prometheus(self, *, session_ready: Optional[bool] = None) -> str:
        snap = self.snapshot()
        lines = [
            "# HELP bridge_auth_refresh_success_total Successful bw-cli session refresh attempts",
            "# TYPE bridge_auth_refresh_success_total counter",
            f"bridge_auth_refresh_success_total {snap['auth_refresh_success_total']}",
            "# HELP bridge_auth_refresh_failure_total Failed bw-cli session refresh attempts",
            "# TYPE bridge_auth_refresh_failure_total counter",
            f"bridge_auth_refresh_failure_total {snap['auth_refresh_failure_total']}",
        ]
        if session_ready is not None:
            lines.extend(
                [
                    "# HELP bridge_bw_session_ready Whether the bw-cli session is currently ready (1/0)",
                    "# TYPE bridge_bw_session_ready gauge",
                    f"bridge_bw_session_ready {1 if session_ready else 0}",
                ]
            )
        return "\n".join(lines) + "\n"


class SecretBackend:
    """Secret backend interface."""

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        raise NotImplementedError

    def is_ready(self) -> bool:
        """Return True when the backend can serve secret lookups."""
        return True

    def metrics_text(self) -> str:
        """Prometheus text exposition for backend-specific metrics."""
        return (
            "# HELP bridge_auth_refresh_success_total Successful bw-cli session refresh attempts\n"
            "# TYPE bridge_auth_refresh_success_total counter\n"
            "bridge_auth_refresh_success_total 0\n"
            "# HELP bridge_auth_refresh_failure_total Failed bw-cli session refresh attempts\n"
            "# TYPE bridge_auth_refresh_failure_total counter\n"
            "bridge_auth_refresh_failure_total 0\n"
        )


class MockBackend(SecretBackend):
    """In-memory backend for deterministic tests."""

    def __init__(self, secrets: Dict[str, Dict[str, str]]):
        self.secrets = secrets

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            raise SecretLookupError(f"Secret path '{secret_path}' not found")
        if key not in self.secrets[secret_path]:
            raise SecretLookupError(
                f"Key '{key}' not found in secret path '{secret_path}'"
            )
        return self.secrets[secret_path][key]


class BwCliBackend(SecretBackend):
    """Vaultwarden/Bitwarden lookup via bw CLI."""

    def __init__(
        self,
        bw_path: str,
        folder_name: str,
        org_id: str,
        item_template: str,
        bw_server: str,
        bw_email: str,
        bw_password: str,
        bw_session: str,
        cache_ttl_seconds: int,
        command_timeout_seconds: int,
        metrics: Optional[AuthMetrics] = None,
    ):
        self.bw_path = bw_path
        self.folder_name = folder_name
        self.org_id = org_id
        self.item_template = item_template
        self.bw_server = bw_server
        self.bw_email = bw_email
        self.bw_password = bw_password
        self.session = bw_session
        self.cache_ttl_seconds = max(cache_ttl_seconds, 1)
        self.command_timeout_seconds = max(command_timeout_seconds, 1)
        self.metrics = metrics or AuthMetrics()
        self._folder_id: Optional[str] = None
        self._cache_lock = threading.RLock()
        self._bw_lock = threading.Lock()
        self._item_cache: Dict[str, Tuple[float, Dict]] = {}
        self._session_ready = False
        self._ready_lock = threading.Lock()

        self._bootstrap_auth(record_metric=False)
        self._set_session_ready(True)

    def _set_session_ready(self, ready: bool) -> None:
        with self._ready_lock:
            self._session_ready = ready

    def is_ready(self) -> bool:
        with self._ready_lock:
            return self._session_ready and bool(self.session)

    def metrics_text(self) -> str:
        return self.metrics.render_prometheus(session_ready=self.is_ready())

    def _run_bw_raw(
        self,
        args: List[str],
        *,
        include_session: bool = True,
        extra_env: Optional[Dict[str, str]] = None,
        tolerate_failure: bool = False,
    ) -> str:
        command = [self.bw_path, *args]
        if include_session and self.session and "--session" not in args:
            command.extend(["--session", self.session])
        env = os.environ.copy()
        if include_session and self.session:
            env["BW_SESSION"] = self.session
        if extra_env:
            env.update(extra_env)
        try:
            with self._bw_lock:
                proc = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=self.command_timeout_seconds,
                )
        except subprocess.TimeoutExpired as exc:
            raise BwCliError(
                f"bw CLI timed out after {self.command_timeout_seconds}s",
                hint="Increase BW_COMMAND_TIMEOUT_SECONDS or check Vaultwarden connectivity.",
            ) from exc
        if proc.returncode != 0 and not tolerate_failure:
            detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
            raise classify_bw_cli_failure(detail)
        return proc.stdout.strip()

    def _refresh_session(self) -> None:
        """Re-bootstrap auth and record success/failure metrics."""
        try:
            self._bootstrap_auth(record_metric=False)
            self._set_session_ready(True)
            self.metrics.record_success()
            LOGGER.info("bw-cli session refresh succeeded")
        except Exception as exc:
            self._set_session_ready(False)
            self.metrics.record_failure()
            LOGGER.error("bw-cli session refresh failed: %s", exc)
            raise

    def _run_bw_json(self, args: List[str]) -> Dict:
        for attempt in range(2):
            try:
                stdout = self._run_bw_raw(args)
            except AuthError as exc:
                # bw CLI can lose auth state at runtime; re-bootstrap and retry once.
                if attempt == 0 and "You are not logged in." in str(exc):
                    self._refresh_session()
                    continue
                LOGGER.error("bw auth failure (%s)", exc.log_message())
                raise
            except BridgeError:
                raise

            try:
                return json.loads(stdout)
            except json.JSONDecodeError as exc:
                # Some bw-cli auth failures can surface as non-JSON stdout.
                if attempt == 0:
                    self._refresh_session()
                    continue
                raise InvalidJsonError(
                    f"bw CLI returned invalid JSON: {exc}",
                    hint=(
                        "bw stdout was not JSON after re-auth. Confirm BW_SESSION unlock state, "
                        "BW_EMAIL/BW_PASSWORD, and VAULTWARDEN_SERVER/BW_SERVER."
                    ),
                ) from exc

        raise InvalidJsonError(
            "bw CLI JSON lookup exhausted retries",
            hint="Re-auth (BW_SESSION or BW_EMAIL/BW_PASSWORD) and verify the server URL.",
        )

    def _validate_session(self, session: str) -> bool:
        """Check whether a bw session can execute JSON-list commands."""
        if not session:
            return False
        try:
            stdout = self._run_bw_raw(
                ["list", "items", "--search", "__bridge_session_probe__", "--session", session],
                include_session=False,
            )
            parsed = json.loads(stdout)
        except (BridgeError, json.JSONDecodeError):
            return False
        return isinstance(parsed, list)

    def _configure_server(self) -> None:
        """Point bw-cli at the configured Vaultwarden server before auth."""
        if not self.bw_server:
            return
        self._run_bw_raw(
            ["config", "server", self.bw_server],
            include_session=False,
        )

    def _bootstrap_auth(self, *, record_metric: bool = False) -> None:
        try:
            self._configure_server()
            if self.session and self._validate_session(self.session):
                try:
                    self._run_bw_raw(["sync"])
                    if record_metric:
                        self.metrics.record_success()
                        self._set_session_ready(True)
                    return
                except SecretLookupError:
                    # Fall back to email/password auth when a preseeded session cannot sync.
                    self.session = ""
            self.session = ""
            if not self.bw_email or not self.bw_password:
                raise RuntimeError("bw-cli backend requires BW_SESSION or BW_EMAIL/BW_PASSWORD")

            password_env = {"BW_BRIDGE_PASSWORD": self.bw_password}
            try:
                session = self._run_bw_raw(
                    ["login", self.bw_email, "--passwordenv", "BW_BRIDGE_PASSWORD", "--raw"],
                    include_session=False,
                    extra_env=password_env,
                ).strip()
            except SecretLookupError as exc:
                # bw may persist account metadata and require unlock instead of login.
                if "already logged in" not in str(exc).lower():
                    raise
                session = self._run_bw_raw(
                    ["unlock", "--passwordenv", "BW_BRIDGE_PASSWORD", "--raw"],
                    include_session=False,
                    extra_env=password_env,
                ).strip()
            if not session or not self._validate_session(session):
                raise RuntimeError("bw-cli login/unlock did not produce a valid session")
            self.session = session
            self._run_bw_raw(["sync"])
            if record_metric:
                self.metrics.record_success()
                self._set_session_ready(True)
        except Exception:
            if record_metric:
                self.metrics.record_failure()
                self._set_session_ready(False)
            raise

    def _resolve_folder_id(self) -> Optional[str]:
        if self._folder_id is not None:
            return self._folder_id
        if not self.folder_name:
            return None
        folders = self._run_bw_json(["list", "folders"])
        if not isinstance(folders, list):
            return None
        for folder in folders:
            if folder.get("name") == self.folder_name:
                self._folder_id = folder.get("id")
                return self._folder_id
        return None

    def _select_item(self, items: List[Dict], item_name: str) -> Dict:
        if not isinstance(items, list) or not items:
            raise SecretLookupError(f"Vaultwarden item '{item_name}' not found")

        folder_id = self._resolve_folder_id()
        selected = None
        for item in items:
            if item.get("name") != item_name:
                continue
            if self.org_id and item.get("organizationId") != self.org_id:
                continue
            if folder_id and item.get("folderId") != folder_id:
                continue
            selected = item
            break

        if selected is None:
            selected = items[0]
        return selected

    def _get_item_cached(self, item_name: str) -> Dict:
        now = time.time()
        with self._cache_lock:
            cached = self._item_cache.get(item_name)
            if cached and cached[0] > now:
                return cached[1]

            for attempt in range(2):
                items = self._run_bw_json(["list", "items", "--search", item_name])
                try:
                    selected = self._select_item(items, item_name)
                    self._item_cache[item_name] = (now + self.cache_ttl_seconds, selected)
                    return selected
                except SecretLookupError:
                    if attempt == 0:
                        # Newly created Vaultwarden items can require an explicit sync.
                        self._run_bw_raw(["sync"], tolerate_failure=True)
                        continue
                    raise

            raise SecretLookupError(f"Vaultwarden item '{item_name}' not found")

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        item_name = self.item_template.format(namespace=namespace, secret=secret)
        selected = self._get_item_cached(item_name)

        value = extract_value_from_bw_item(selected, key)
        if value is None:
            raise SecretLookupError(f"Key '{key}' not found on item '{item_name}'")
        return value


def parse_secret_path(path: str) -> Tuple[str, str, str]:
    """Parse /v1/secret/{namespace}/{secret}/{key} path."""
    parsed = urlparse(path)
    prefix = "/v1/secret/"
    if not parsed.path.startswith(prefix):
        raise ValueError("Expected /v1/secret/{namespace}/{secret}/{key}")
    remainder = parsed.path[len(prefix) :]
    if "/" not in remainder:
        raise ValueError("Expected /v1/secret/{namespace}/{secret}/{key}")
    secret_path_enc, key_enc = remainder.rsplit("/", 1)
    secret_path = unquote(secret_path_enc)
    key = unquote(key_enc)
    if "/" not in secret_path:
        raise ValueError("Expected /v1/secret/{namespace}/{secret}/{key}")
    namespace, secret = secret_path.split("/", 1)
    if not namespace or not secret or not key:
        raise ValueError("Expected /v1/secret/{namespace}/{secret}/{key}")
    return namespace, secret, key


def extract_bearer_token(header: str) -> Optional[str]:
    """Extract bearer token from Authorization header."""
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


def expand_token_variants(token: str) -> Tuple[str, ...]:
    """Return legacy token forms derived from a presented bearer value.

    Used only when BRIDGE_TOKEN_LEGACY_VARIANTS is enabled. Forms:

    1. Raw bearer value (after surrounding whitespace strip)
    2. One layer of surrounding double or single quotes removed
    3. One base64 decode (strict validate) of (1) or (2), UTF-8 decoded + strip

    Strict mode does not use this helper; prefer exact BRIDGE_TOKEN equality.
    """
    variants = []
    raw = token.strip()
    if raw:
        variants.append(raw)
    quoted = raw.strip("\"'")
    if quoted and quoted not in variants:
        variants.append(quoted)

    for value in tuple(variants):
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8").strip()
        except Exception:
            continue
        if decoded and decoded not in variants:
            variants.append(decoded)

    return tuple(variants)


def token_matches(
    configured: str,
    presented: Optional[str],
    *,
    legacy_variants: bool = False,
) -> bool:
    """Return True when the presented bearer token authorizes the request.

    Strict mode (default, legacy_variants=False):
      - Accept only exact equality of presented token to configured BRIDGE_TOKEN.
      - Reject quoted and base64-encoded presentations even if they decode to
        the configured secret. This surfaces misconfigured secrets early.

    Legacy expand mode (legacy_variants=True):
      - Accept exact match without logging.
      - Also accept forms from expand_token_variants(presented) that equal
        configured BRIDGE_TOKEN, and emit a warning when a non-exact form
        is what matched (so operators can fix encoding mistakes).
    """
    if presented is None or not configured:
        return False
    if presented == configured:
        return True
    if not legacy_variants:
        return False
    variants = expand_token_variants(presented)
    if configured in variants:
        LOGGER.warning(
            "bridge token matched via legacy variant expansion "
            "(presented form differed from BRIDGE_TOKEN); "
            "prefer exact bearer values and set BRIDGE_TOKEN_LEGACY_VARIANTS=false "
            "once secrets are corrected"
        )
        return True
    return False


def build_config_from_env() -> BridgeConfig:
    """Build BridgeConfig from environment."""
    token = os.getenv("BRIDGE_TOKEN", "").strip()
    if not token:
        raise RuntimeError("BRIDGE_TOKEN is required")
    return BridgeConfig(
        token=token,
        # Default false: strict exact match. Opt into legacy quote/base64 expand.
        token_legacy_variants=parse_bool_env("BRIDGE_TOKEN_LEGACY_VARIANTS", False),
        backend_mode=os.getenv("BACKEND_MODE", "mock").strip(),
        item_name_template=os.getenv("ITEM_NAME_TEMPLATE", "{namespace}/{secret}").strip(),
        mock_secrets=load_mock_secrets(os.getenv("MOCK_SECRETS_JSON", "").strip()),
        vaultwarden_folder=os.getenv("VAULTWARDEN_FOLDER", "").strip(),
        vaultwarden_org_id=os.getenv("VAULTWARDEN_ORGANIZATION_ID", "").strip(),
        bw_server=os.getenv("VAULTWARDEN_SERVER", os.getenv("BW_SERVER", "")).strip(),
        bw_email=os.getenv("BW_EMAIL", "").strip(),
        bw_password=os.getenv("BW_PASSWORD", "").strip(),
        bw_session=os.getenv("BW_SESSION", "").strip(),
        bw_path=os.getenv("BW_CLI_PATH", "bw").strip(),
        bw_item_cache_ttl_seconds=parse_positive_int_env("BW_ITEM_CACHE_TTL_SECONDS", 120),
        bw_command_timeout_seconds=parse_positive_int_env("BW_COMMAND_TIMEOUT_SECONDS", 120),
    )


def build_backend(config: BridgeConfig) -> SecretBackend:
    """Create backend implementation from config."""
    if config.backend_mode == "mock":
        return MockBackend(config.mock_secrets)
    if config.backend_mode == "bw-cli":
        return BwCliBackend(
            bw_path=config.bw_path,
            folder_name=config.vaultwarden_folder,
            org_id=config.vaultwarden_org_id,
            item_template=config.item_name_template,
            bw_server=config.bw_server,
            bw_email=config.bw_email,
            bw_password=config.bw_password,
            bw_session=config.bw_session,
            cache_ttl_seconds=config.bw_item_cache_ttl_seconds,
            command_timeout_seconds=config.bw_command_timeout_seconds,
        )
    raise RuntimeError(f"Unsupported BACKEND_MODE: {config.backend_mode}")


class BridgeRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for secret lookups."""

    token: str = ""
    token_legacy_variants: bool = False
    backend: SecretBackend

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        # Keep stdout quiet; callers should inspect structured response codes.
        return

    def _write_json(self, status: int, payload: Dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, status: int, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        presented = extract_bearer_token(header)
        return token_matches(
            self.token,
            presented,
            legacy_variants=self.token_legacy_variants,
        )

    def do_GET(self) -> None:  # noqa: N802
        # Liveness: process is up. Keep this independent of session health so a
        # dead bw session marks the pod NotReady without thrashing restarts.
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"ok": True})
            return

        # Readiness: for bw-cli, fail when the session is invalid so Service
        # endpoints drop the pod and ESO stops hammering a dead bridge.
        if self.path in ("/readyz", "/ready"):
            ready = self.backend.is_ready()
            if ready:
                self._write_json(HTTPStatus.OK, {"ok": True, "ready": True})
            else:
                self._write_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"ok": False, "ready": False, "error": "backend session not ready"},
                )
            return

        if self.path == "/metrics":
            self._write_text(
                HTTPStatus.OK,
                self.backend.metrics_text(),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return

        if not self._authorized():
            self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        try:
            namespace, secret, key = parse_secret_path(self.path)
            value = self.backend.get_value(namespace, secret, key)
            self._write_json(HTTPStatus.OK, {"value": value})
        except ValueError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except AuthError as exc:
            LOGGER.error(
                "auth failure path=%s code=%s error=%s",
                self.path,
                exc.code,
                exc.log_message(),
            )
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": str(exc), "code": exc.code, "hint": exc.hint},
            )
        except InvalidJsonError as exc:
            LOGGER.error(
                "invalid bw JSON path=%s code=%s error=%s",
                self.path,
                exc.code,
                exc.log_message(),
            )
            self._write_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": str(exc), "code": exc.code, "hint": exc.hint},
            )
        except SecretLookupError as exc:
            LOGGER.warning(
                "secret lookup failed path=%s code=%s error=%s",
                self.path,
                exc.code,
                exc.log_message(),
            )
            self._write_json(
                HTTPStatus.NOT_FOUND,
                {"error": str(exc), "code": exc.code, "hint": exc.hint},
            )
        except BwCliError as exc:
            LOGGER.error(
                "bw CLI failure path=%s code=%s error=%s",
                self.path,
                exc.code,
                exc.log_message(),
            )
            self._write_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": str(exc), "code": exc.code, "hint": exc.hint},
            )
        except Exception as exc:  # pragma: no cover
            LOGGER.exception("bridge request failed path=%s", self.path)
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})


def run() -> None:
    """Start the bridge server."""
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = build_config_from_env()
    backend = build_backend(config)
    port = int(os.getenv("BRIDGE_PORT", "8080"))
    LOGGER.info(
        "starting vaultwarden bridge backend_mode=%s port=%s cache_ttl=%ss "
        "cmd_timeout=%ss token_legacy_variants=%s",
        config.backend_mode,
        port,
        config.bw_item_cache_ttl_seconds,
        config.bw_command_timeout_seconds,
        config.token_legacy_variants,
    )
    if config.token_legacy_variants:
        LOGGER.warning(
            "BRIDGE_TOKEN_LEGACY_VARIANTS enabled: quoted/base64 bearer forms "
            "are accepted and may mask misconfigured secrets; prefer strict matching"
        )

    BridgeRequestHandler.token = config.token
    BridgeRequestHandler.token_legacy_variants = config.token_legacy_variants
    BridgeRequestHandler.backend = backend
    server = ThreadingHTTPServer(("0.0.0.0", port), BridgeRequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()
