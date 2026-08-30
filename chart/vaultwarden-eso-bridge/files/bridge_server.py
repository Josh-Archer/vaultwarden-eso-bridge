#!/usr/bin/env python3
"""Vaultwarden External Secrets Operator (ESO) HTTP Bridge.

Serves a single-purpose HTTP endpoint that resolves Vaultwarden secrets by path
for External Secrets Operator Webhook providers.

  GET /v1/secret/{namespace}/{secret}/{key}             - Single value lookup
  GET /v1/secret/{namespace}/{secret}                   - Multi-key bulk JSON dictionary
  GET /v1/secret/{namespace}/{secret}/attachment/{file} - Binary file attachment
  POST /v1/admin/ensure                                 - Verify/create items and populate missing fields
  POST /v1/admin/rotate                                 - Rotate passwords/fields on targeted items
  GET /healthz                                          - Liveness probe
  GET /readyz (or /ready)                               - Readiness probe
  GET /metrics                                          - Prometheus metrics
"""

from __future__ import annotations

import base64
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
import re
import secrets as secrets_mod
import string
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse

LOGGER = logging.getLogger("vaultwarden-eso-bridge")


class BridgeError(RuntimeError):
    """Base error for bridge exceptions."""

    code = "bridge_error"

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        hint: Optional[str] = None,
    ):
        super().__init__(message)
        if code:
            self.code = code
        self.hint = hint

    def log_message(self) -> str:
        if self.hint:
            return f"{self} | next_steps: {self.hint}"
        return str(self)


class SecretLookupError(BridgeError):
    """Raised when a secret path, key, or attachment is not found."""

    code = "secret_not_found"


class AuthError(BridgeError):
    """Raised on authentication or authorization failure with Vaultwarden."""

    code = "auth_error"


class InvalidJsonError(BridgeError):
    """Raised when bw CLI returns invalid JSON stdout."""

    code = "invalid_json"


class BwCliError(BridgeError):
    """Generic failure executing bw CLI command."""

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


def extract_value_from_bw_item(item: Dict, key: str) -> Optional[str]:
    """Resolve a single key from a Bitwarden item object."""
    for field in item.get("fields", []) or []:
        if field.get("name") == key and field.get("value") is not None:
            return str(field.get("value"))

    login = item.get("login", {}) or {}
    if key in ("username", "login.username") and login.get("username") is not None:
        return str(login["username"])
    if key in ("password", "login.password") and login.get("password") is not None:
        return str(login["password"])
    if key in ("totp", "login.totp") and login.get("totp") is not None:
        return str(login["totp"])
    if key in ("uri", "login.uri"):
        uris = login.get("uris") or []
        if uris and isinstance(uris[0], dict) and uris[0].get("uri") is not None:
            return str(uris[0]["uri"])

    if key == "notes" and item.get("notes") is not None:
        return str(item["notes"])

    return None


def extract_all_values_from_bw_item(item: Dict) -> Dict[str, str]:
    """Extract all resolvable properties and custom fields from a Bitwarden item."""
    data: Dict[str, str] = {}

    login = item.get("login", {}) or {}
    if login.get("username") is not None:
        val = str(login["username"])
        data["username"] = val
        data["login.username"] = val
    if login.get("password") is not None:
        val = str(login["password"])
        data["password"] = val
        data["login.password"] = val
    if login.get("totp") is not None:
        val = str(login["totp"])
        data["totp"] = val
        data["login.totp"] = val

    uris = login.get("uris") or []
    if uris and isinstance(uris[0], dict) and uris[0].get("uri") is not None:
        val = str(uris[0]["uri"])
        data["uri"] = val
        data["login.uri"] = val

    if item.get("notes") is not None:
        data["notes"] = str(item["notes"])

    for field in item.get("fields", []) or []:
        fname = field.get("name")
        fval = field.get("value")
        if fname and fval is not None:
            data[str(fname)] = str(fval)

    return data


def parse_bool_env(name: str, default: bool = False) -> bool:
    """Parse a boolean environment value with fallback."""
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return default


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


def parse_non_negative_int_env(name: str, default: int) -> int:
    """Parse a non-negative integer environment value with fallback.

    Zero is valid and typically means "feature disabled".
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def load_mock_secrets(raw_json: str) -> Dict[str, Dict[str, str]]:
    """Parse MOCK_SECRETS_JSON mapping."""
    if not raw_json:
        return {
            "default/app-secrets": {
                "api_key": "mock-api-key-12345",
                "database_url": "postgres://user:pass@db:5432/app",
                "username": "mock-user",
                "password": "mock-password",
            }
        }
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid MOCK_SECRETS_JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("MOCK_SECRETS_JSON must be a JSON object")

    normalized: Dict[str, Dict[str, str]] = {}
    for secret_path, fields in data.items():
        if not isinstance(fields, dict):
            raise RuntimeError(f"Secret entry '{secret_path}' must be a JSON object")
        normalized[secret_path] = {str(k): str(v) for k, v in fields.items()}
    return normalized


class BridgeConfig:
    """Runtime config for bridge server."""

    def __init__(
        self,
        token: str,
        token_legacy_variants: bool,
        backend_mode: str,
        item_name_template: str,
        mock_secrets: Dict[str, Dict[str, str]],
        vaultwarden_folder: str,
        vaultwarden_org_id: str,
        bw_server: str,
        bw_email: str,
        bw_password: str,
        bw_session: str,
        bw_path: str,
        bw_item_cache_ttl_seconds: int,
        bw_command_timeout_seconds: int,
        bw_negative_cache_ttl_seconds: int = 15,
    ):
        self.token = token
        self.token_legacy_variants = token_legacy_variants
        self.backend_mode = backend_mode
        self.item_name_template = item_name_template
        self.mock_secrets = mock_secrets
        self.vaultwarden_folder = vaultwarden_folder
        self.vaultwarden_org_id = vaultwarden_org_id
        self.bw_server = bw_server
        self.bw_email = bw_email
        self.bw_password = bw_password
        self.bw_session = bw_session
        self.session = bw_session
        self.bw_path = bw_path
        self.bw_item_cache_ttl_seconds = bw_item_cache_ttl_seconds
        self.bw_negative_cache_ttl_seconds = bw_negative_cache_ttl_seconds
        self.bw_command_timeout_seconds = bw_command_timeout_seconds


class AuthMetrics:
    """Thread-safe counters and latency histograms for bridge requests and auth."""

    HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.auth_refresh_success_total = 0
        self.auth_refresh_failure_total = 0
        self.cache_hits_total = 0
        self.cache_misses_total = 0
        self.negative_cache_hits_total = 0
        self.request_latencies: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def record_success(self) -> None:
        with self._lock:
            self.auth_refresh_success_total += 1

    def record_failure(self) -> None:
        with self._lock:
            self.auth_refresh_failure_total += 1

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits_total += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses_total += 1

    def record_negative_cache_hit(self) -> None:
        with self._lock:
            self.negative_cache_hits_total += 1

    def record_request(self, path: str, status: int, duration_seconds: float) -> None:
        with self._lock:
            key = (path, status)
            if key not in self.request_latencies:
                self.request_latencies[key] = {
                    "count": 0,
                    "sum": 0.0,
                    "buckets": {b: 0 for b in self.HISTOGRAM_BUCKETS},
                    "inf": 0,
                }
            entry = self.request_latencies[key]
            entry["count"] += 1
            entry["sum"] += duration_seconds
            entry["inf"] += 1
            for b in self.HISTOGRAM_BUCKETS:
                if duration_seconds <= b:
                    entry["buckets"][b] += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "auth_refresh_success_total": self.auth_refresh_success_total,
                "auth_refresh_failure_total": self.auth_refresh_failure_total,
                "cache_hits_total": self.cache_hits_total,
                "cache_misses_total": self.cache_misses_total,
                "negative_cache_hits_total": self.negative_cache_hits_total,
            }

    def render_prometheus(self, *, session_ready: Optional[bool] = None) -> str:
        with self._lock:
            auth_success = self.auth_refresh_success_total
            auth_failure = self.auth_refresh_failure_total
            cache_hits = self.cache_hits_total
            cache_misses = self.cache_misses_total
            neg_hits = self.negative_cache_hits_total
            latencies = {
                k: {
                    "count": v["count"],
                    "sum": v["sum"],
                    "inf": v["inf"],
                    "buckets": dict(v["buckets"]),
                }
                for k, v in self.request_latencies.items()
            }

        lines = [
            "# HELP bridge_auth_refresh_success_total Successful bw-cli session refresh attempts",
            "# TYPE bridge_auth_refresh_success_total counter",
            f"bridge_auth_refresh_success_total {auth_success}",
            "# HELP bridge_auth_refresh_failure_total Failed bw-cli session refresh attempts",
            "# TYPE bridge_auth_refresh_failure_total counter",
            f"bridge_auth_refresh_failure_total {auth_failure}",
            "# HELP bridge_cache_hits_total In-process secret cache hit counter",
            "# TYPE bridge_cache_hits_total counter",
            f"bridge_cache_hits_total {cache_hits}",
            "# HELP bridge_cache_misses_total In-process secret cache miss counter",
            "# TYPE bridge_cache_misses_total counter",
            f"bridge_cache_misses_total {cache_misses}",
            "# HELP bridge_negative_cache_hits_total In-process negative (404) cache hit counter",
            "# TYPE bridge_negative_cache_hits_total counter",
            f"bridge_negative_cache_hits_total {neg_hits}",
        ]
        if session_ready is not None:
            lines.extend(
                [
                    "# HELP bridge_bw_session_ready Whether the bw-cli session is currently ready (1/0)",
                    "# TYPE bridge_bw_session_ready gauge",
                    f"bridge_bw_session_ready {1 if session_ready else 0}",
                ]
            )

        if latencies:
            lines.extend(
                [
                    "# HELP bridge_request_duration_seconds HTTP request latency histogram in seconds",
                    "# TYPE bridge_request_duration_seconds histogram",
                ]
            )
            for (path, status), entry in sorted(latencies.items()):
                for b in self.HISTOGRAM_BUCKETS:
                    lines.append(
                        f'bridge_request_duration_seconds_bucket{{path="{path}",status="{status}",le="{b}"}} {entry["buckets"][b]}'
                    )
                lines.append(
                    f'bridge_request_duration_seconds_bucket{{path="{path}",status="{status}",le="+Inf"}} {entry["inf"]}'
                )
                lines.append(
                    f'bridge_request_duration_seconds_sum{{path="{path}",status="{status}"}} {entry["sum"]:.6f}'
                )
                lines.append(
                    f'bridge_request_duration_seconds_count{{path="{path}",status="{status}"}} {entry["count"]}'
                )

        return "\n".join(lines) + "\n"



def generate_password(length: int = 32) -> str:
    """Generate a cryptographically random alphanumeric+symbol password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets_mod.choice(alphabet) for _ in range(length))

class SecretBackend:
    """Secret backend interface."""

    metrics: AuthMetrics

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        raise NotImplementedError

    def get_all_values(self, namespace: str, secret: str) -> Dict[str, str]:
        raise NotImplementedError

    def get_attachment(self, namespace: str, secret: str, filename: str) -> Tuple[bytes, str]:
        raise NotImplementedError

    def ensure_item(
        self, item_name: str, fields: Dict[str, str]
    ) -> Dict[str, Any]:
        """Verify item exists and populate missing fields. Returns action report."""
        raise NotImplementedError

    def rotate_item(
        self, item_name: str, field_names: List[str], length: int = 32
    ) -> Dict[str, Any]:
        """Rotate specified fields on an item with new random values. Returns action report."""
        raise NotImplementedError

    def is_ready(self) -> bool:
        """Return True when the backend can serve secret lookups."""
        return True

    def metrics_text(self) -> str:
        """Prometheus text exposition for backend-specific metrics."""
        return self.metrics.render_prometheus(session_ready=self.is_ready())


class MockBackend(SecretBackend):
    """In-memory backend for deterministic tests."""

    def __init__(
        self,
        secrets: Dict[str, Dict[str, str]],
        attachments: Optional[Dict[str, Dict[str, Union[bytes, str]]]] = None,
        metrics: Optional[AuthMetrics] = None,
    ):
        self.secrets = secrets
        self.attachments = attachments or {}
        self.metrics = metrics or AuthMetrics()

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            raise SecretLookupError(f"Secret path '{secret_path}' not found")
        if key not in self.secrets[secret_path]:
            raise SecretLookupError(
                f"Key '{key}' not found in secret path '{secret_path}'"
            )
        return self.secrets[secret_path][key]

    def get_all_values(self, namespace: str, secret: str) -> Dict[str, str]:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            raise SecretLookupError(f"Secret path '{secret_path}' not found")
        return dict(self.secrets[secret_path])

    def get_attachment(self, namespace: str, secret: str, filename: str) -> Tuple[bytes, str]:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.attachments or filename not in self.attachments[secret_path]:
            raise SecretLookupError(f"Attachment '{filename}' not found on item '{secret_path}'")
        val = self.attachments[secret_path][filename]
        if isinstance(val, str):
            val = val.encode("utf-8")
        return val, "application/octet-stream"

    def ensure_item(
        self, item_name: str, fields: Dict[str, str]
    ) -> Dict[str, Any]:
        created = item_name not in self.secrets
        if created:
            self.secrets[item_name] = {}
        populated: List[str] = []
        for key, default_value in fields.items():
            if key not in self.secrets[item_name]:
                self.secrets[item_name][key] = default_value
                populated.append(key)
        return {"item": item_name, "created": created, "populated": populated}

    def rotate_item(
        self, item_name: str, field_names: List[str], length: int = 32
    ) -> Dict[str, Any]:
        if item_name not in self.secrets:
            raise SecretLookupError(f"Item '{item_name}' not found")
        rotated: List[str] = []
        for field in field_names:
            self.secrets[item_name][field] = generate_password(length)
            rotated.append(field)
        return {"item": item_name, "rotated": rotated}


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
        negative_cache_ttl_seconds: int = 15,
    ):
        self.bw_path = bw_path
        self.folder_name = folder_name
        self.org_id = org_id
        self.item_template = item_template
        self.bw_server = bw_server
        self.bw_email = bw_email
        self.bw_password = bw_password
        self.session = bw_session
        self.cache_ttl_seconds = max(int(cache_ttl_seconds), 0)
        self.negative_cache_ttl_seconds = max(int(negative_cache_ttl_seconds), 0)
        self.command_timeout_seconds = max(command_timeout_seconds, 1)
        self.metrics = metrics or AuthMetrics()
        self._folder_id: Optional[str] = None
        self._cache_lock = threading.RLock()
        self._bw_lock = threading.Lock()
        self._ready_lock = threading.Lock()
        self._session_ready = False
        # Cache entries: (expiry_timestamp, Optional[Dict[item]], Optional[SecretLookupError])
        self._item_cache: Dict[Tuple[str, str], Tuple[float, Optional[Dict], Optional[SecretLookupError]]] = {}

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
                    self.session = ""
            self.session = ""
            if not self.bw_email or not self.bw_password:
                raise AuthError(
                    "bw-cli backend requires BW_SESSION or BW_EMAIL/BW_PASSWORD",
                    hint=(
                        "Set BW_SESSION (unlocked) or both BW_EMAIL and BW_PASSWORD "
                        "in the vaultwarden-bridge-bw secret."
                    ),
                )

            password_env = {"BW_BRIDGE_PASSWORD": self.bw_password}
            try:
                session = self._run_bw_raw(
                    ["login", self.bw_email, "--passwordenv", "BW_BRIDGE_PASSWORD", "--raw"],
                    include_session=False,
                    extra_env=password_env,
                ).strip()
            except BridgeError as exc:
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

    def _lookup_item(self, item_name: str) -> Dict:
        """Fetch a Vaultwarden item by name, syncing once on miss."""
        for attempt in range(2):
            items = self._run_bw_json(["list", "items", "--search", item_name])
            try:
                return self._select_item(items, item_name)
            except SecretLookupError:
                if attempt == 0:
                    self._run_bw_raw(["sync"], tolerate_failure=True)
                    continue
                raise
        raise SecretLookupError(f"Vaultwarden item '{item_name}' not found")

    def _get_item_cached(self, namespace: str, secret: str, item_name: str) -> Dict:
        """Return item, optionally serving from TTL cache with negative caching support."""
        cache_key = (namespace, secret)
        now = time.time()

        if self.cache_ttl_seconds > 0 or self.negative_cache_ttl_seconds > 0:
            with self._cache_lock:
                cached = self._item_cache.get(cache_key)
                if cached and cached[0] > now:
                    _, item, neg_err = cached
                    if neg_err is not None:
                        self.metrics.record_negative_cache_hit()
                        raise neg_err
                    if item is not None:
                        self.metrics.record_cache_hit()
                        return item

        self.metrics.record_cache_miss()
        try:
            selected = self._lookup_item(item_name)
            if self.cache_ttl_seconds > 0:
                with self._cache_lock:
                    self._item_cache[cache_key] = (time.time() + self.cache_ttl_seconds, selected, None)
            return selected
        except SecretLookupError as exc:
            if self.negative_cache_ttl_seconds > 0:
                with self._cache_lock:
                    self._item_cache[cache_key] = (time.time() + self.negative_cache_ttl_seconds, None, exc)
            raise

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        item_name = self.item_template.format(namespace=namespace, secret=secret)
        selected = self._get_item_cached(namespace, secret, item_name)

        value = extract_value_from_bw_item(selected, key)
        if value is None:
            raise SecretLookupError(f"Key '{key}' not found on item '{item_name}'")
        return value

    def get_all_values(self, namespace: str, secret: str) -> Dict[str, str]:
        item_name = self.item_template.format(namespace=namespace, secret=secret)
        selected = self._get_item_cached(namespace, secret, item_name)
        return extract_all_values_from_bw_item(selected)

    def get_attachment(self, namespace: str, secret: str, filename: str) -> Tuple[bytes, str]:
        item_name = self.item_template.format(namespace=namespace, secret=secret)
        selected = self._get_item_cached(namespace, secret, item_name)

        attachments = selected.get("attachments", []) or []
        target = None
        for att in attachments:
            if att.get("fileName") == filename or att.get("id") == filename:
                target = att
                break

        if not target:
            raise SecretLookupError(f"Attachment '{filename}' not found on item '{item_name}'")

        item_id = selected.get("id")
        if not item_id:
            raise SecretLookupError(f"Item ID missing on item '{item_name}'")

        target_name = target.get("fileName") or filename
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, target_name)
            self._run_bw_raw(
                ["get", "attachment", target_name, "--itemid", item_id, "--output", out_file],
                tolerate_failure=False,
            )
            if not os.path.exists(out_file):
                raise SecretLookupError(f"Failed to retrieve attachment '{filename}' from item '{item_name}'")
            with open(out_file, "rb") as f:
                content = f.read()

        return content, "application/octet-stream"

    def ensure_item(
        self, item_name: str, fields: Dict[str, str]
    ) -> Dict[str, Any]:
        """Verify item exists; create if missing; populate absent fields."""
        self._run_bw_raw(["sync"], tolerate_failure=True)
        created = False
        populated: List[str] = []

        # Try to find existing item
        try:
            items = self._run_bw_json(["list", "items", "--search", item_name])
            selected = self._select_item(items, item_name)
        except SecretLookupError:
            # Create new login item
            folder_id = self._resolve_folder_id()
            new_item: Dict[str, Any] = {
                "type": 1,  # Login
                "name": item_name,
                "login": {"username": "", "password": ""},
                "fields": [],
                "notes": None,
            }
            if folder_id:
                new_item["folderId"] = folder_id
            if self.org_id:
                new_item["organizationId"] = self.org_id
            encoded = base64.b64encode(json.dumps(new_item).encode()).decode()
            result = self._run_bw_json(["create", "item", encoded])
            selected = result
            created = True

        # Populate missing fields
        item_fields = selected.get("fields") or []
        existing_names = {f.get("name") for f in item_fields}
        login = selected.get("login") or {}
        login_keys = {"username", "password"}

        changed = False
        for key, default_value in fields.items():
            if key in login_keys:
                current = login.get(key)
                if not current:
                    login[key] = default_value
                    changed = True
                    populated.append(key)
            elif key == "notes":
                if not selected.get("notes"):
                    selected["notes"] = default_value
                    changed = True
                    populated.append(key)
            elif key not in existing_names:
                item_fields.append({"name": key, "value": default_value, "type": 0})
                changed = True
                populated.append(key)

        if changed:
            selected["login"] = login
            selected["fields"] = item_fields
            item_id = selected.get("id", "")
            encoded = base64.b64encode(json.dumps(selected).encode()).decode()
            self._run_bw_json(["edit", "item", item_id, encoded])
            self._run_bw_raw(["sync"], tolerate_failure=True)
            # Invalidate cache
            with self._cache_lock:
                self._item_cache.clear()

        LOGGER.info(
            "admin ensure item=%s created=%s populated=%s",
            item_name, created, populated,
        )
        return {"item": item_name, "created": created, "populated": populated}

    def rotate_item(
        self, item_name: str, field_names: List[str], length: int = 32
    ) -> Dict[str, Any]:
        """Rotate specified fields on an item with new random values."""
        self._run_bw_raw(["sync"], tolerate_failure=True)
        items = self._run_bw_json(["list", "items", "--search", item_name])
        selected = self._select_item(items, item_name)

        item_fields = selected.get("fields") or []
        login = selected.get("login") or {}
        login_keys = {"username", "password"}
        rotated: List[str] = []

        for field in field_names:
            new_value = generate_password(length)
            if field in login_keys:
                login[field] = new_value
                rotated.append(field)
            elif field == "notes":
                selected["notes"] = new_value
                rotated.append(field)
            else:
                found = False
                for f in item_fields:
                    if f.get("name") == field:
                        f["value"] = new_value
                        found = True
                        break
                if not found:
                    item_fields.append({"name": field, "value": new_value, "type": 0})
                rotated.append(field)

        selected["login"] = login
        selected["fields"] = item_fields
        item_id = selected.get("id", "")
        encoded = base64.b64encode(json.dumps(selected).encode()).decode()
        self._run_bw_json(["edit", "item", item_id, encoded])
        self._run_bw_raw(["sync"], tolerate_failure=True)

        # Invalidate cache
        with self._cache_lock:
            self._item_cache.clear()

        LOGGER.info(
            "admin rotate item=%s rotated=%s",
            item_name, rotated,
        )
        return {"item": item_name, "rotated": rotated}


def parse_secret_path(path: str) -> Tuple[str, str, Optional[str]]:
    """Parse /v1/secret/{namespace}/{secret}/{key} or /v1/secret/{namespace}/{secret} path."""
    parsed = urlparse(path)
    prefix = "/v1/secret/"
    if not parsed.path.startswith(prefix):
        raise ValueError("Expected /v1/secret/{namespace}/{secret} or /v1/secret/{namespace}/{secret}/{key}")
    remainder = parsed.path[len(prefix) :].strip("/")
    if not remainder:
        raise ValueError("Expected /v1/secret/{namespace}/{secret} or /v1/secret/{namespace}/{secret}/{key}")

    # Attachment request: /v1/secret/{namespace}/{secret}/attachment/{filename}
    if "/attachment/" in remainder:
        parts = remainder.split("/attachment/", 1)
        secret_path = unquote(parts[0])
        filename = unquote(parts[1])
        if "/" not in secret_path:
            raise ValueError("Expected /v1/secret/{namespace}/{secret}/attachment/{filename}")
        namespace, secret = secret_path.split("/", 1)
        if not namespace or not secret or not filename:
            raise ValueError("Expected /v1/secret/{namespace}/{secret}/attachment/{filename}")
        return namespace, secret, f"attachment/{filename}"

    # Split from right to check for 3-part path or encoded secret_ref
    if "/" in remainder:
        secret_path_enc, last_part_enc = remainder.rsplit("/", 1)
        secret_path = unquote(secret_path_enc)
        last_part = unquote(last_part_enc)

        if "/" in secret_path:
            namespace, secret = secret_path.split("/", 1)
            if namespace and secret and last_part:
                return namespace, secret, last_part

    # 2-part bulk path: /v1/secret/{namespace}/{secret}
    unquoted_remainder = unquote(remainder)
    if "/" in unquoted_remainder:
        namespace, secret = unquoted_remainder.split("/", 1)
        if namespace and secret:
            return namespace, secret, None

    raise ValueError("Expected /v1/secret/{namespace}/{secret} or /v1/secret/{namespace}/{secret}/{key}")


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
    """Return legacy token forms derived from a presented bearer value."""
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
    """Return True when the presented bearer token authorizes the request."""
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
        bw_item_cache_ttl_seconds=parse_non_negative_int_env("BW_ITEM_CACHE_TTL_SECONDS", 0),
        bw_command_timeout_seconds=parse_positive_int_env("BW_COMMAND_TIMEOUT_SECONDS", 120),
        bw_negative_cache_ttl_seconds=parse_non_negative_int_env("BW_NEGATIVE_CACHE_TTL_SECONDS", 15),
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
            negative_cache_ttl_seconds=config.bw_negative_cache_ttl_seconds,
        )
    raise RuntimeError(f"Unsupported BACKEND_MODE: {config.backend_mode}")


class BridgeRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for secret lookups."""

    token: str = ""
    token_legacy_variants: bool = False
    backend: SecretBackend

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _write_json(self, status: int, payload: Dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_bytes(self, status: int, body: bytes, content_type: str = "application/octet-stream") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
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

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        presented = extract_bearer_token(header)
        return token_matches(
            self.token,
            presented,
            legacy_variants=self.token_legacy_variants,
        )

    def do_GET(self) -> None:  # noqa: N802
        start_time = time.time()
        status_code = HTTPStatus.OK
        matched_path = "/v1/secret"

        try:
            if self.path == "/healthz":
                matched_path = "/healthz"
                self._write_json(HTTPStatus.OK, {"ok": True})
                return

            if self.path in ("/readyz", "/ready"):
                matched_path = "/readyz"
                ready = self.backend.is_ready()
                if ready:
                    self._write_json(HTTPStatus.OK, {"ok": True, "ready": True})
                else:
                    status_code = HTTPStatus.SERVICE_UNAVAILABLE
                    self._write_json(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"ok": False, "ready": False, "error": "backend session not ready"},
                    )
                return

            if self.path == "/metrics":
                matched_path = "/metrics"
                self._write_text(
                    HTTPStatus.OK,
                    self.backend.metrics_text(),
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                return

            if not self._authorized():
                status_code = HTTPStatus.UNAUTHORIZED
                self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return

            try:
                namespace, secret, key = parse_secret_path(self.path)

                if key is None:
                    # Multi-key bulk JSON endpoint (Issue #19)
                    values = self.backend.get_all_values(namespace, secret)
                    self._write_json(HTTPStatus.OK, {"data": values, **values})
                elif key.startswith("attachment/"):
                    # Binary attachment endpoint (Issue #23)
                    filename = key[len("attachment/") :]
                    content_bytes, mime = self.backend.get_attachment(namespace, secret, filename)
                    accept_header = self.headers.get("Accept", "").lower()
                    if "application/octet-stream" in accept_header or "application/x-binary" in accept_header:
                        self._write_bytes(HTTPStatus.OK, content_bytes, mime)
                    else:
                        b64_val = base64.b64encode(content_bytes).decode("utf-8")
                        self._write_json(
                            HTTPStatus.OK,
                            {
                                "value": b64_val,
                                "filename": filename,
                                "size": len(content_bytes),
                            },
                        )
                else:
                    # Single key lookup
                    value = self.backend.get_value(namespace, secret, key)
                    self._write_json(HTTPStatus.OK, {"value": value})
            except ValueError as exc:
                status_code = HTTPStatus.BAD_REQUEST
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except AuthError as exc:
                status_code = HTTPStatus.SERVICE_UNAVAILABLE
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
                status_code = HTTPStatus.BAD_GATEWAY
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
                status_code = HTTPStatus.NOT_FOUND
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
                status_code = HTTPStatus.BAD_GATEWAY
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
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
                LOGGER.exception("bridge request failed path=%s", self.path)
                self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
        finally:
            duration = time.time() - start_time
            if hasattr(self.backend, "metrics") and self.backend.metrics is not None:
                self.backend.metrics.record_request(matched_path, int(status_code), duration)

    def do_POST(self) -> None:  # noqa: N802
        start_time = time.time()
        status_code = HTTPStatus.OK
        matched_path = self.path

        try:
            if not self._authorized():
                status_code = HTTPStatus.UNAUTHORIZED
                self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return

            raw = self._read_body()
            if not raw:
                status_code = HTTPStatus.BAD_REQUEST
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "empty request body"})
                return

            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                status_code = HTTPStatus.BAD_REQUEST
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
                return

            if self.path == "/v1/admin/ensure":
                matched_path = "/v1/admin/ensure"
                items = body.get("items")
                if not isinstance(items, list) or not items:
                    status_code = HTTPStatus.BAD_REQUEST
                    self._write_json(HTTPStatus.BAD_REQUEST, {
                        "error": "body must contain 'items' array",
                        "example": {"items": [{"name": "ns/secret", "fields": {"key": "default"}}]},
                    })
                    return
                results = []
                for entry in items:
                    name = entry.get("name", "")
                    fields = entry.get("fields", {})
                    if not name or not isinstance(fields, dict):
                        status_code = HTTPStatus.BAD_REQUEST
                        self._write_json(HTTPStatus.BAD_REQUEST, {
                            "error": f"each item needs 'name' (str) and 'fields' (object), got: {entry}",
                        })
                        return
                    result = self.backend.ensure_item(name, fields)
                    results.append(result)
                LOGGER.info("admin ensure completed items=%d", len(results))
                self._write_json(HTTPStatus.OK, {"ok": True, "results": results})

            elif self.path == "/v1/admin/rotate":
                matched_path = "/v1/admin/rotate"
                items = body.get("items")
                pw_length = int(body.get("length", 32))
                if not isinstance(items, list) or not items:
                    status_code = HTTPStatus.BAD_REQUEST
                    self._write_json(HTTPStatus.BAD_REQUEST, {
                        "error": "body must contain 'items' array",
                        "example": {"items": [{"name": "ns/secret", "fields": ["password"]}], "length": 32},
                    })
                    return
                results = []
                for entry in items:
                    name = entry.get("name", "")
                    field_names = entry.get("fields", [])
                    if not name or not isinstance(field_names, list) or not field_names:
                        status_code = HTTPStatus.BAD_REQUEST
                        self._write_json(HTTPStatus.BAD_REQUEST, {
                            "error": f"each item needs 'name' (str) and 'fields' (list), got: {entry}",
                        })
                        return
                    result = self.backend.rotate_item(name, field_names, pw_length)
                    results.append(result)
                LOGGER.info("admin rotate completed items=%d", len(results))
                self._write_json(HTTPStatus.OK, {"ok": True, "results": results})

            else:
                status_code = HTTPStatus.NOT_FOUND
                self._write_json(HTTPStatus.NOT_FOUND, {"error": f"unknown admin route: {self.path}"})

        except AuthError as exc:
            status_code = HTTPStatus.SERVICE_UNAVAILABLE
            LOGGER.error("admin auth failure path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except SecretLookupError as exc:
            status_code = HTTPStatus.NOT_FOUND
            LOGGER.warning("admin lookup failed path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.NOT_FOUND, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except BridgeError as exc:
            status_code = HTTPStatus.BAD_GATEWAY
            LOGGER.error("admin failure path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.BAD_GATEWAY, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except Exception as exc:  # pragma: no cover
            status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            LOGGER.exception("admin request failed path=%s", self.path)
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
        finally:
            duration = time.time() - start_time
            if hasattr(self.backend, "metrics") and self.backend.metrics is not None:
                self.backend.metrics.record_request(matched_path, int(status_code), duration)


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
        "neg_cache_ttl=%ss cmd_timeout=%ss token_legacy_variants=%s",
        config.backend_mode,
        port,
        config.bw_item_cache_ttl_seconds,
        config.bw_negative_cache_ttl_seconds,
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
