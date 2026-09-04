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
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.error
from urllib.parse import unquote, urlparse
import urllib.request

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


class BwsError(BridgeError):
    """Generic failure executing BWS command or API request."""

    code = "bws_error"


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


class TokenReviewAuthenticator:
    """Authenticates Kubernetes ServiceAccount tokens via the TokenReview API."""

    def __init__(
        self,
        allowed_service_accounts: List[str],
        *,
        audiences: Optional[List[str]] = None,
        cache_ttl_seconds: int = 300,
        negative_cache_ttl_seconds: int = 10,
        api_url: Optional[str] = None,
        ca_path: Optional[str] = None,
        token_path: Optional[str] = None,
    ):
        self.allowed_service_accounts = [sa.strip() for sa in allowed_service_accounts if sa.strip()]
        self.audiences = audiences or []
        self.cache_ttl_seconds = max(cache_ttl_seconds, 0)
        self.negative_cache_ttl_seconds = max(negative_cache_ttl_seconds, 0)
        self.api_url = (api_url or os.getenv("KUBERNETES_API_SERVER", "https://kubernetes.default.svc")).rstrip("/")
        self.ca_path = ca_path or os.getenv("KUBERNETES_CA_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        self.token_path = token_path or os.getenv("KUBERNETES_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, bool, str]] = {}

    def _get_sa_token(self) -> Optional[str]:
        if os.path.exists(self.token_path):
            try:
                with open(self.token_path, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception as exc:
                LOGGER.error("Failed to read in-pod ServiceAccount token at %s: %s", self.token_path, exc)
        return None

    def matches_service_account(self, username: str) -> bool:
        """Check if username matches any allowed service account rule."""
        if not username:
            return False
        for pattern in self.allowed_service_accounts:
            if pattern == "*":
                return True
            if pattern == username:
                return True
            if username.startswith("system:serviceaccount:"):
                sa_suffix = username[len("system:serviceaccount:"):]
                if pattern in (sa_suffix, sa_suffix.replace(":", "/")):
                    return True
                if pattern.endswith(":*"):
                    ns_prefix = pattern[:-2]
                    if sa_suffix.startswith(f"{ns_prefix}:") or username.startswith(f"{ns_prefix}:"):
                        return True
                if pattern.endswith("/*"):
                    ns_prefix = pattern[:-2]
                    if sa_suffix.startswith(f"{ns_prefix}:"):
                        return True
        return False

    def _review_token(self, token: str) -> Tuple[bool, str]:
        url = f"{self.api_url}/apis/authentication.k8s.io/v1/tokenreviews"
        payload: Dict[str, Any] = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {
                "token": token,
            },
        }
        if self.audiences:
            payload["spec"]["audiences"] = self.audiences

        req_data = json.dumps(payload).encode("utf-8")
        sa_token = self._get_sa_token()
        if not sa_token:
            LOGGER.error("TokenReview failed: in-pod ServiceAccount token not found at %s", self.token_path)
            return False, ""

        headers = {
            "Authorization": f"Bearer {sa_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")

        ssl_context = None
        if os.path.exists(self.ca_path):
            ssl_context = ssl.create_default_context(cafile=self.ca_path)
        else:
            ssl_context = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                status = data.get("status", {})
                authenticated = bool(status.get("authenticated"))
                username = status.get("user", {}).get("username", "")
                return authenticated, username
        except Exception as exc:
            LOGGER.error("Kubernetes TokenReview API request failed: %s", exc)
            return False, ""

    def authenticate(self, token: Optional[str]) -> bool:
        if not token:
            return False
        now = time.time()
        if self.cache_ttl_seconds > 0 or self.negative_cache_ttl_seconds > 0:
            with self._lock:
                cached = self._cache.get(token)
                if cached and cached[0] > now:
                    return cached[1]

        authenticated, username = self._review_token(token)
        allowed = authenticated and self.matches_service_account(username)

        ttl = self.cache_ttl_seconds if allowed else self.negative_cache_ttl_seconds
        if ttl > 0:
            with self._lock:
                self._cache[token] = (now + ttl, allowed, username)

        if allowed:
            LOGGER.debug("TokenReview authentication succeeded for user=%s", username)
        else:
            LOGGER.warning("TokenReview authentication rejected for user=%s (authenticated=%s)", username, authenticated)
        return allowed

DEFAULT_AUTO_GENERATE_ANNOTATION = "vaultwarden.bridge/auto-generate"
DEFAULT_PASSWORD_LENGTH_ANNOTATION = "vaultwarden.bridge/password-length"
DEFAULT_GENERATE_KEYS_ANNOTATION = "vaultwarden.bridge/generate-keys"
MIN_GENERATED_PASSWORD_LENGTH = 8
MAX_GENERATED_PASSWORD_LENGTH = 128
DEFAULT_GENERATED_PASSWORD_LENGTH = 32


def annotation_is_true(value: Optional[str]) -> bool:
    """Return True for common truthy annotation strings."""
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def clamp_password_length(
    raw: Any, default: int = DEFAULT_GENERATED_PASSWORD_LENGTH
) -> int:
    """Clamp a generated-password length into the supported range."""
    try:
        length = int(raw)
    except (TypeError, ValueError):
        length = default
    return max(MIN_GENERATED_PASSWORD_LENGTH, min(MAX_GENERATED_PASSWORD_LENGTH, length))


def iter_externalsecret_remote_refs(
    es: Dict[str, Any],
) -> List[Tuple[str, Optional[str]]]:
    """Yield (remoteRef.key, property) pairs from an ExternalSecret object."""
    spec = es.get("spec") or {}
    refs: List[Tuple[str, Optional[str]]] = []
    for item in spec.get("data") or []:
        if not isinstance(item, dict):
            continue
        remote = item.get("remoteRef") or {}
        key = remote.get("key")
        if not key:
            continue
        prop = remote.get("property")
        refs.append((str(key), str(prop) if prop else None))
    for item in spec.get("dataFrom") or []:
        if not isinstance(item, dict):
            continue
        extract = item.get("extract") or {}
        key = extract.get("key")
        if key:
            refs.append((str(key), None))
    return refs


class AutoGenerateDecision:
    """Whether an ExternalSecret requested on-demand secret creation."""

    def __init__(
        self,
        enabled: bool,
        password_length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
        keys: Tuple[str, ...] = (),
    ):
        self.enabled = enabled
        self.password_length = password_length
        self.keys = keys


DISABLED_AUTO_GENERATE = AutoGenerateDecision(False)


class ExternalSecretProvisioner:
    """Resolve ExternalSecret annotations that request auto-generation."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        annotation: str = DEFAULT_AUTO_GENERATE_ANNOTATION,
        password_length_annotation: str = DEFAULT_PASSWORD_LENGTH_ANNOTATION,
        generate_keys_annotation: str = DEFAULT_GENERATE_KEYS_ANNOTATION,
        default_password_length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
        list_cache_ttl_seconds: int = 15,
        list_externalsecrets: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        api_url: Optional[str] = None,
        ca_path: Optional[str] = None,
        token_path: Optional[str] = None,
    ):
        self.enabled = enabled
        self.annotation = annotation
        self.password_length_annotation = password_length_annotation
        self.generate_keys_annotation = generate_keys_annotation
        self.default_password_length = clamp_password_length(default_password_length)
        self.list_cache_ttl_seconds = max(int(list_cache_ttl_seconds), 0)
        self._list_externalsecrets = list_externalsecrets
        self.api_url = (
            api_url or os.getenv("KUBERNETES_API_SERVER", "https://kubernetes.default.svc")
        ).rstrip("/")
        self.ca_path = ca_path or os.getenv(
            "KUBERNETES_CA_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        )
        self.token_path = token_path or os.getenv(
            "KUBERNETES_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"
        )
        self._lock = threading.Lock()
        self._cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])

    def _sa_token(self) -> Optional[str]:
        if not os.path.exists(self.token_path):
            return None
        try:
            with open(self.token_path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            LOGGER.error("Failed to read ServiceAccount token at %s: %s", self.token_path, exc)
            return None

    def _ssl_context(self) -> ssl.SSLContext:
        if os.path.exists(self.ca_path):
            return ssl.create_default_context(cafile=self.ca_path)
        return ssl.create_default_context()

    def _list_from_api(self) -> List[Dict[str, Any]]:
        token = self._sa_token()
        if not token:
            LOGGER.warning("auto-generate skipped: in-cluster token missing")
            return []
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        ssl_context = self._ssl_context()
        last_error: Optional[Exception] = None
        for version in ("v1", "v1beta1"):
            url = f"{self.api_url}/apis/external-secrets.io/{version}/externalsecrets"
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                items = payload.get("items") if isinstance(payload, dict) else None
                if not isinstance(items, list):
                    return []
                return [item for item in items if isinstance(item, dict)]
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code == 404:
                    continue
                LOGGER.error("listing ExternalSecrets failed version=%s error=%s", version, exc)
                return []
            except Exception as exc:
                last_error = exc
                LOGGER.error("listing ExternalSecrets failed version=%s error=%s", version, exc)
                return []
        if last_error:
            LOGGER.warning("ExternalSecret API not available: %s", last_error)
        return []

    def list_externalsecrets(self) -> List[Dict[str, Any]]:
        if self._list_externalsecrets is not None:
            try:
                items = self._list_externalsecrets()
            except Exception as exc:
                LOGGER.error("auto-generate ExternalSecret list callback failed: %s", exc)
                return []
            return [item for item in items if isinstance(item, dict)]
        now = time.time()
        with self._lock:
            expiry, cached = self._cache
            if self.list_cache_ttl_seconds > 0 and expiry > now:
                return cached
        items = self._list_from_api()
        if self.list_cache_ttl_seconds > 0:
            with self._lock:
                self._cache = (time.time() + self.list_cache_ttl_seconds, items)
        return items

    def decision_for(
        self, remote_key: str, requested_key: Optional[str] = None
    ) -> AutoGenerateDecision:
        if not self.enabled or not remote_key:
            return DISABLED_AUTO_GENERATE
        for es in self.list_externalsecrets():
            annotations = (es.get("metadata") or {}).get("annotations") or {}
            if not isinstance(annotations, dict) or not annotation_is_true(
                annotations.get(self.annotation)
            ):
                continue
            refs = iter_externalsecret_remote_refs(es)
            matching_props = [prop for key, prop in refs if key == remote_key]
            if not matching_props:
                continue
            length = clamp_password_length(
                annotations.get(self.password_length_annotation),
                self.default_password_length,
            )
            annotated_keys = [
                part.strip()
                for part in str(annotations.get(self.generate_keys_annotation) or "").split(",")
                if part.strip()
            ]
            declared = annotated_keys or [prop for prop in matching_props if prop]
            if requested_key:
                if declared and requested_key not in declared:
                    continue
                keys = (requested_key,)
            else:
                keys = tuple(declared) if declared else ("password",)
            return AutoGenerateDecision(True, length, keys)
        return DISABLED_AUTO_GENERATE



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
        bws_access_token: str = "",
        bws_server_url: str = "",
        bws_project_id: str = "",
        bws_cli_path: str = "bws",
        bws_item_cache_ttl_seconds: int = 120,
        bws_negative_cache_ttl_seconds: int = 15,
        bws_command_timeout_seconds: int = 60,
        tokenreview_enabled: bool = False,
        allowed_service_accounts: Optional[List[str]] = None,
        tokenreview_cache_ttl_seconds: int = 300,
        tokenreview_audiences: Optional[List[str]] = None,
        tls_enabled: bool = False,
        tls_cert_path: str = "/etc/tls/tls.crt",
        tls_key_path: str = "/etc/tls/tls.key",
        websocket_sync_enabled: bool = False,
        websocket_url: str = "",
        websocket_token: str = "",
        websocket_reconnect_interval_seconds: float = 5.0,
        websocket_ssl_verify: bool = True,
        auto_generate_enabled: bool = False,
        auto_generate_annotation: str = DEFAULT_AUTO_GENERATE_ANNOTATION,
        auto_generate_password_length_annotation: str = DEFAULT_PASSWORD_LENGTH_ANNOTATION,
        auto_generate_keys_annotation: str = DEFAULT_GENERATE_KEYS_ANNOTATION,
        auto_generate_default_password_length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
        auto_generate_list_cache_ttl_seconds: int = 15,
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
        self.bws_access_token = bws_access_token
        self.bws_server_url = bws_server_url
        self.bws_project_id = bws_project_id
        self.bws_cli_path = bws_cli_path
        self.bws_item_cache_ttl_seconds = bws_item_cache_ttl_seconds
        self.bws_negative_cache_ttl_seconds = bws_negative_cache_ttl_seconds
        self.bws_command_timeout_seconds = bws_command_timeout_seconds
        self.tokenreview_enabled = tokenreview_enabled
        self.allowed_service_accounts = allowed_service_accounts or []
        self.tokenreview_cache_ttl_seconds = tokenreview_cache_ttl_seconds
        self.tokenreview_audiences = tokenreview_audiences or []
        self.tls_enabled = tls_enabled
        self.tls_cert_path = tls_cert_path
        self.tls_key_path = tls_key_path
        self.websocket_sync_enabled = websocket_sync_enabled
        self.websocket_url = websocket_url
        self.websocket_token = websocket_token
        self.websocket_reconnect_interval_seconds = websocket_reconnect_interval_seconds
        self.websocket_ssl_verify = websocket_ssl_verify
        self.auto_generate_enabled = auto_generate_enabled
        self.auto_generate_annotation = auto_generate_annotation
        self.auto_generate_password_length_annotation = auto_generate_password_length_annotation
        self.auto_generate_keys_annotation = auto_generate_keys_annotation
        self.auto_generate_default_password_length = clamp_password_length(
            auto_generate_default_password_length
        )
        self.auto_generate_list_cache_ttl_seconds = max(int(auto_generate_list_cache_ttl_seconds), 0)


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
        self.websocket_notifications_total = 0
        self.websocket_connected = False
        self.request_latencies: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def record_websocket_notification(self) -> None:
        with self._lock:
            self.websocket_notifications_total += 1

    def set_websocket_connected(self, connected: bool) -> None:
        with self._lock:
            self.websocket_connected = connected
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
                "websocket_notifications_total": self.websocket_notifications_total,
                "websocket_connected": self.websocket_connected,
            }

    def render_prometheus(self, *, session_ready: Optional[bool] = None) -> str:
        with self._lock:
            auth_success = self.auth_refresh_success_total
            auth_failure = self.auth_refresh_failure_total
            cache_hits = self.cache_hits_total
            cache_misses = self.cache_misses_total
            neg_hits = self.negative_cache_hits_total
            ws_notifications = self.websocket_notifications_total
            ws_connected = self.websocket_connected
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
            "# HELP bridge_websocket_notifications_total Total Vaultwarden WebSocket notifications received",
            "# TYPE bridge_websocket_notifications_total counter",
            f"bridge_websocket_notifications_total {ws_notifications}",
            "# HELP bridge_websocket_connected Whether the Vaultwarden WebSocket listener is connected (1/0)",
            "# TYPE bridge_websocket_connected gauge",
            f"bridge_websocket_connected {1 if ws_connected else 0}",
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
    def render_item_name(self, namespace: str, secret: str) -> str:
        """Render the Vaultwarden item name from namespace and secret."""
        return f"{namespace}/{secret}"


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

    def set_value(self, namespace: str, secret: str, key: str, value: str) -> Dict[str, Any]:
        """Set a single key/value on a secret (PushSecret support)."""
        raise NotImplementedError

    def set_all_values(self, namespace: str, secret: str, values: Dict[str, str]) -> Dict[str, Any]:
        """Set/merge dictionary of values on a secret (PushSecret bulk support)."""
        raise NotImplementedError

    def delete_secret(self, namespace: str, secret: str, key: Optional[str] = None) -> Dict[str, Any]:
        """Delete a key or entire secret."""
        raise NotImplementedError

    def rotate_item(
        self, item_name: str, field_names: List[str], length: int = 32
    ) -> Dict[str, Any]:
        """Rotate specified fields on an item with new random values. Returns action report."""
        raise NotImplementedError
    def is_ready(self) -> bool:
        """Return True when the backend can serve secret lookups."""
        return True


    def invalidate_cache(self) -> None:
        """Clear in-memory cache upon receiving WebSocket change event."""
        pass
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
    def render_item_name(self, namespace: str, secret: str) -> str:
        return f"{namespace}/{secret}"


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

    def set_value(self, namespace: str, secret: str, key: str, value: str) -> Dict[str, Any]:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            self.secrets[secret_path] = {}
        self.secrets[secret_path][key] = value
        return {"item": secret_path, "key": key, "status": "updated"}

    def set_all_values(self, namespace: str, secret: str, values: Dict[str, str]) -> Dict[str, Any]:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            self.secrets[secret_path] = {}
        self.secrets[secret_path].update(values)
        return {"item": secret_path, "keys": list(values.keys()), "status": "updated"}

    def delete_secret(self, namespace: str, secret: str, key: Optional[str] = None) -> Dict[str, Any]:
        secret_path = f"{namespace}/{secret}"
        if secret_path not in self.secrets:
            return {"item": secret_path, "status": "not_found"}
        if key:
            self.secrets[secret_path].pop(key, None)
            return {"item": secret_path, "key": key, "status": "deleted"}
        self.secrets.pop(secret_path, None)
        return {"item": secret_path, "status": "deleted"}

    def invalidate_cache(self) -> None:
        pass


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
        self.item_name_template = item_template
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
        try:
            self._run_bw_raw(
                ["config", "server", self.bw_server],
                include_session=False,
            )
        except BridgeError as exc:
            # If already logged in, bw-cli refuses to update the server URL with
            # "Logout required before server config update." That is safe to ignore
            # because the server was already configured at login.
            if "logout required" in str(exc).lower():
                LOGGER.debug("bw-cli server already configured (%s)", exc)
                return
            raise

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

    def _encode_base64(self, raw_json: str) -> str:
        return base64.b64encode(raw_json.encode("utf-8")).decode("ascii")

    def _get_item_data(self, namespace: str, secret: str) -> Dict:
        item_name = self.render_item_name(namespace, secret)
        return self._get_item_cached(namespace, secret, item_name)

    def render_item_name(self, namespace: str, secret: str) -> str:
        """Render the Vaultwarden item name from namespace and secret."""
        return self.item_name_template.format(namespace=namespace, secret=secret)

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        item_name = self.render_item_name(namespace, secret)
        selected = self._get_item_cached(namespace, secret, item_name)

        value = extract_value_from_bw_item(selected, key)
        if value is None:
            raise SecretLookupError(f"Key '{key}' not found on item '{item_name}'")
        return value

    def get_all_values(self, namespace: str, secret: str) -> Dict[str, str]:
        item_name = self.render_item_name(namespace, secret)
        selected = self._get_item_cached(namespace, secret, item_name)
        return extract_all_values_from_bw_item(selected)

    def get_attachment(self, namespace: str, secret: str, filename: str) -> Tuple[bytes, str]:
        item_name = self.render_item_name(namespace, secret)
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

    def set_value(self, namespace: str, secret: str, key: str, value: str) -> Dict[str, Any]:
        return self.set_all_values(namespace, secret, {key: value})

    def set_all_values(self, namespace: str, secret: str, values: Dict[str, str]) -> Dict[str, Any]:
        item_name = self.render_item_name(namespace, secret)
        try:
            item = self._get_item_data(namespace, secret)
            fields = item.get("fields") or []
            existing_field_names = set()
            for f in fields:
                fname = f.get("name")
                if fname in values:
                    f["value"] = values[fname]
                    existing_field_names.add(fname)
            for k, v in values.items():
                if k not in existing_field_names:
                    if k == "password" and "login" in item:
                        item["login"]["password"] = v
                    elif k == "username" and "login" in item:
                        item["login"]["username"] = v
                    else:
                        fields.append({"name": k, "value": v, "type": 0})
            item["fields"] = fields

            raw_json = json.dumps(item)
            encoded = self._encode_base64(raw_json)
            self._run_bw_raw(["edit", "item", item["id"], encoded])
            self._run_bw_raw(["sync"], tolerate_failure=True)
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("set_all_values item=%s updated keys=%s", item_name, list(values.keys()))
            return {"item": item_name, "status": "updated", "keys": list(values.keys())}
        except SecretLookupError:
            folder_id = self._resolve_folder_id()
            fields_list = [{"name": k, "value": v, "type": 0} for k, v in values.items() if k not in ("username", "password")]
            new_item = {
                "type": 1,
                "name": item_name,
                "notes": f"Managed by vaultwarden-eso-bridge ({namespace})",
                "fields": fields_list,
                "login": {
                    "username": values.get("username", ""),
                    "password": values.get("password", ""),
                },
            }
            if folder_id:
                new_item["folderId"] = folder_id
            if self.org_id:
                new_item["organizationId"] = self.org_id

            raw_json = json.dumps(new_item)
            encoded = self._encode_base64(raw_json)
            self._run_bw_raw(["create", "item", encoded])
            self._run_bw_raw(["sync"], tolerate_failure=True)
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("set_all_values item=%s created keys=%s", item_name, list(values.keys()))
            return {"item": item_name, "status": "created", "keys": list(values.keys())}

    def delete_secret(self, namespace: str, secret: str, key: Optional[str] = None) -> Dict[str, Any]:
        item_name = self.render_item_name(namespace, secret)
        try:
            item = self._get_item_data(namespace, secret)
            if key:
                fields = [f for f in (item.get("fields") or []) if f.get("name") != key]
                item["fields"] = fields
                raw_json = json.dumps(item)
                encoded = self._encode_base64(raw_json)
                self._run_bw_raw(["edit", "item", item["id"], encoded])
            else:
                self._run_bw_raw(["delete", "item", item["id"]])
            self._run_bw_raw(["sync"], tolerate_failure=True)
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("delete_secret item=%s key=%s deleted", item_name, key)
            return {"item": item_name, "status": "deleted"}
        except SecretLookupError:
            return {"item": item_name, "status": "not_found"}

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._item_cache.clear()
        LOGGER.info("BwCliBackend cache invalidated via WebSocket event")
        threading.Thread(target=self._run_bw_raw, args=(["sync"],), kwargs={"tolerate_failure": True}, daemon=True).start()



class BwsBackend(SecretBackend):
    """Bitwarden Secrets Manager (BWS) backend using machine access tokens."""

    def __init__(
        self,
        access_token: str,
        server_url: str = "",
        project_id: str = "",
        bws_path: str = "bws",
        cache_ttl_seconds: int = 120,
        negative_cache_ttl_seconds: int = 15,
        command_timeout_seconds: int = 60,
        metrics: Optional[AuthMetrics] = None,
        http_client: Optional[Any] = None,
    ):
        self.access_token = access_token.strip()
        self.server_url = (server_url.strip() or "https://vault.bitwarden.com/api").rstrip("/")
        self.project_id = project_id.strip()
        self.bws_path = bws_path.strip() or "bws"
        self.cache_ttl_seconds = max(int(cache_ttl_seconds), 0)
        self.negative_cache_ttl_seconds = max(int(negative_cache_ttl_seconds), 0)
        self.command_timeout_seconds = max(command_timeout_seconds, 1)
        self.metrics = metrics or AuthMetrics()
        self._http_client = http_client
        self._cache_lock = threading.RLock()
        self._ready_lock = threading.Lock()
        self._session_ready = bool(self.access_token)
        # Cache entries: (expiry_timestamp, Optional[Dict[str, Any]], Optional[SecretLookupError])
        self._item_cache: Dict[Tuple[str, str], Tuple[float, Optional[Dict[str, Any]], Optional[SecretLookupError]]] = {}

        if not self.access_token:
            LOGGER.warning("BWS_ACCESS_TOKEN is empty; BwsBackend will not be ready until a valid token is provided")

    def is_ready(self) -> bool:
        with self._ready_lock:
            return bool(self.access_token) and self._session_ready

    def metrics_text(self) -> str:
        return self.metrics.render_prometheus(session_ready=self.is_ready())

    def _api_request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Make an authenticated REST API request to Bitwarden Secrets Manager."""
        if self._http_client is not None:
            return self._http_client(method, endpoint, payload)

        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "vaultwarden-eso-bridge/bws",
        }
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

        try:
            with urllib.request.urlopen(req, timeout=self.command_timeout_seconds) as resp:
                resp_bytes = resp.read()
                if not resp_bytes:
                    return None
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in (401, 403):
                with self._ready_lock:
                    self._session_ready = False
                raise AuthError(
                    f"BWS authentication failed (HTTP {exc.code}): {body or exc.reason}",
                    hint="Check BWS_ACCESS_TOKEN machine access token.",
                ) from exc
            if exc.code == 404:
                raise SecretLookupError(
                    f"BWS resource not found: {endpoint}",
                    hint="Check secret name, project ID, and machine account permissions.",
                ) from exc
            raise BwsError(
                f"BWS API error (HTTP {exc.code}): {body or exc.reason}",
                hint="Check BWS API endpoint connectivity and payload.",
            ) from exc
        except urllib.error.URLError as exc:
            raise BwsError(
                f"Failed to connect to BWS server ({self.server_url}): {exc.reason}",
                hint="Check network connectivity, DNS, and BWS_SERVER_URL.",
            ) from exc

    def _get_secret_data(self, namespace: str, secret: str) -> Dict[str, Any]:
        """Fetch and cache secret dictionary for namespace/secret."""
        cache_key = (namespace, secret)
        now = time.monotonic()

        with self._cache_lock:
            if self.cache_ttl_seconds > 0 or self.negative_cache_ttl_seconds > 0:
                entry = self._item_cache.get(cache_key)
                if entry:
                    expires_at, cached_item, cached_exc = entry
                    if now < expires_at:
                        if cached_exc is not None:
                            raise cached_exc
                        if cached_item is not None:
                            return cached_item

        target_names = [
            f"{namespace}/{secret}",
            f"{namespace}_{secret}",
            secret,
        ]

        try:
            endpoint = f"secrets?projectId={self.project_id}" if self.project_id else "secrets"
            resp = self._api_request("GET", endpoint)
            items = resp.get("data", resp) if isinstance(resp, dict) else (resp if isinstance(resp, list) else [])

            matching_secret = None
            for item in items:
                key = item.get("key", "")
                if key in target_names:
                    matching_secret = item
                    break

            if not matching_secret:
                exc = SecretLookupError(
                    f"Secret '{namespace}/{secret}' not found in BWS (searched: {', '.join(target_names)})",
                    hint=f"Create secret in BWS with key '{namespace}/{secret}' or check project assignment.",
                )
                if self.negative_cache_ttl_seconds > 0:
                    with self._cache_lock:
                        self._item_cache[cache_key] = (now + self.negative_cache_ttl_seconds, None, exc)
                raise exc

            secret_id = matching_secret.get("id")
            if "value" not in matching_secret and secret_id:
                secret_detail = self._api_request("GET", f"secrets/{secret_id}")
            else:
                secret_detail = matching_secret

            value_str = secret_detail.get("value", "") or ""
            note_str = secret_detail.get("note", "") or ""

            data: Dict[str, Any] = {}
            if value_str.strip().startswith("{") and value_str.strip().endswith("}"):
                try:
                    parsed = json.loads(value_str)
                    if isinstance(parsed, dict):
                        for k, v in parsed.items():
                            data[k] = str(v) if v is not None else ""
                except Exception:
                    data = {}

            if not data:
                data = {
                    "value": value_str,
                    "password": value_str,
                    "secret": value_str,
                }
                data[secret] = value_str

            if note_str:
                data["note"] = note_str

            data["_id"] = secret_detail.get("id", "")
            data["_key"] = secret_detail.get("key", "")
            data["_projectId"] = secret_detail.get("projectId", "")

            if self.cache_ttl_seconds > 0:
                with self._cache_lock:
                    self._item_cache[cache_key] = (now + self.cache_ttl_seconds, data, None)

            return data

        except (SecretLookupError, AuthError, BwsError):
            raise
        except Exception as exc:
            raise BwsError(f"Unexpected error querying BWS for '{namespace}/{secret}': {exc}") from exc

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        data = self._get_secret_data(namespace, secret)
        if key not in data:
            try:
                sub_data = self._get_secret_data(namespace, f"{secret}/{key}")
                if "value" in sub_data:
                    return sub_data["value"]
            except SecretLookupError:
                pass
            raise SecretLookupError(
                f"Field '{key}' not found in secret '{namespace}/{secret}' (available: {', '.join([k for k in data.keys() if not k.startswith('_')])})",
                hint="Add field to JSON payload in BWS or create individual secret item.",
            )
        return data[key]

    def get_all_values(self, namespace: str, secret: str) -> Dict[str, str]:
        data = self._get_secret_data(namespace, secret)
        return {k: str(v) for k, v in data.items() if not k.startswith("_")}

    def get_attachment(self, namespace: str, secret: str, filename: str) -> Tuple[bytes, str]:
        data = self._get_secret_data(namespace, secret)
        if filename in data:
            val = data[filename]
            try:
                decoded = base64.b64decode(val)
                return decoded, "application/octet-stream"
            except Exception:
                return val.encode("utf-8"), "text/plain"
        raise SecretLookupError(
            f"Attachment '{filename}' not found on secret '{namespace}/{secret}'",
            hint="Store attachment base64 encoded in secret field or note.",
        )

    def ensure_item(self, item_name: str, fields: Dict[str, str]) -> Dict[str, Any]:
        parts = item_name.split("/", 1)
        namespace = parts[0] if len(parts) > 1 else "default"
        secret = parts[1] if len(parts) > 1 else parts[0]

        try:
            existing = self._get_secret_data(namespace, secret)
            secret_id = existing.get("_id")
            updated = False
            current_dict = {k: v for k, v in existing.items() if not k.startswith("_")}
            for k, v in fields.items():
                if k not in current_dict or not current_dict[k]:
                    current_dict[k] = v
                    updated = True

            if updated and secret_id:
                new_value = json.dumps(current_dict)
                self._api_request(
                    "PUT",
                    f"secrets/{secret_id}",
                    {
                        "projectId": existing.get("_projectId") or self.project_id or None,
                        "key": existing.get("_key") or item_name,
                        "value": new_value,
                        "note": existing.get("note", ""),
                    },
                )
                with self._cache_lock:
                    self._item_cache.pop((namespace, secret), None)
                return {"item": item_name, "status": "updated", "fields": list(fields.keys())}
            return {"item": item_name, "status": "unchanged"}
        except SecretLookupError:
            new_value = json.dumps(fields)
            resp = self._api_request(
                "POST",
                "secrets",
                {
                    "projectId": self.project_id or None,
                    "key": item_name,
                    "value": new_value,
                    "note": f"Managed by vaultwarden-eso-bridge ({namespace})",
                },
            )
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            return {"item": item_name, "status": "created", "id": resp.get("id") if isinstance(resp, dict) else None}

    def rotate_item(self, item_name: str, field_names: List[str], length: int = 32) -> Dict[str, Any]:
        parts = item_name.split("/", 1)
        namespace = parts[0] if len(parts) > 1 else "default"
        secret = parts[1] if len(parts) > 1 else parts[0]

        existing = self._get_secret_data(namespace, secret)
        secret_id = existing.get("_id")
        if not secret_id:
            raise SecretLookupError(f"Cannot rotate item '{item_name}': missing secret ID")

        current_dict = {k: v for k, v in existing.items() if not k.startswith("_")}
        rotated = []
        for field in field_names:
            current_dict[field] = generate_password(length)
            rotated.append(field)

        new_value = json.dumps(current_dict)
        self._api_request(
            "PUT",
            f"secrets/{secret_id}",
            {
                "projectId": existing.get("_projectId") or self.project_id or None,
                "key": existing.get("_key") or item_name,
                "value": new_value,
                "note": existing.get("note", ""),
            },
        )
        with self._cache_lock:
            self._item_cache.pop((namespace, secret), None)
        return {"item": item_name, "rotated": rotated}

    def set_value(self, namespace: str, secret: str, key: str, value: str) -> Dict[str, Any]:
        return self.set_all_values(namespace, secret, {key: value})

    def set_all_values(self, namespace: str, secret: str, values: Dict[str, str]) -> Dict[str, Any]:
        item_name = f"{namespace}/{secret}"
        try:
            existing = self._get_secret_data(namespace, secret)
            secret_id = existing.get("_id")
            current_dict = {k: v for k, v in existing.items() if not k.startswith("_")}
            current_dict.update(values)
            new_value = json.dumps(current_dict)
            self._api_request(
                "PUT",
                f"secrets/{secret_id}",
                {
                    "projectId": existing.get("_projectId") or self.project_id or None,
                    "key": existing.get("_key") or item_name,
                    "value": new_value,
                    "note": existing.get("note", ""),
                },
            )
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("bws set_all_values item=%s updated keys=%s", item_name, list(values.keys()))
            return {"item": item_name, "status": "updated", "keys": list(values.keys())}
        except SecretLookupError:
            new_value = json.dumps(values)
            resp = self._api_request(
                "POST",
                "secrets",
                {
                    "projectId": self.project_id or None,
                    "key": item_name,
                    "value": new_value,
                    "note": f"Managed by vaultwarden-eso-bridge ({namespace})",
                },
            )
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("bws set_all_values item=%s created keys=%s", item_name, list(values.keys()))
            return {"item": item_name, "status": "created", "id": resp.get("id") if isinstance(resp, dict) else None, "keys": list(values.keys())}

    def delete_secret(self, namespace: str, secret: str, key: Optional[str] = None) -> Dict[str, Any]:
        item_name = f"{namespace}/{secret}"
        try:
            existing = self._get_secret_data(namespace, secret)
            secret_id = existing.get("_id")
            if not secret_id:
                return {"item": item_name, "status": "not_found"}
            if key:
                current_dict = {k: v for k, v in existing.items() if not k.startswith("_")}
                current_dict.pop(key, None)
                new_value = json.dumps(current_dict)
                self._api_request(
                    "PUT",
                    f"secrets/{secret_id}",
                    {
                        "projectId": existing.get("_projectId") or self.project_id or None,
                        "key": existing.get("_key") or item_name,
                        "value": new_value,
                        "note": existing.get("note", ""),
                    },
                )
            else:
                self._api_request("DELETE", f"secrets/{secret_id}")
            with self._cache_lock:
                self._item_cache.pop((namespace, secret), None)
            LOGGER.info("bws delete_secret item=%s key=%s deleted", item_name, key)
            return {"item": item_name, "status": "deleted"}
        except SecretLookupError:
            return {"item": item_name, "status": "not_found"}

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._item_cache.clear()
        LOGGER.info("BwsBackend cache invalidated via WebSocket event")


class VaultwardenWebSocketClient:
    """Event-driven SignalR WebSocket client for Vaultwarden /notifications/hub."""

    def __init__(
        self,
        server_url: str,
        token: Optional[str] = None,
        on_notification: Optional[Any] = None,
        reconnect_interval_seconds: float = 5.0,
        max_reconnect_interval_seconds: float = 60.0,
        ssl_verify: bool = True,
        metrics: Optional[AuthMetrics] = None,
    ):
        self.server_url = server_url.strip()
        self.token = token.strip() if token else None
        self.on_notification = on_notification
        self.reconnect_interval = max(float(reconnect_interval_seconds), 1.0)
        self.max_reconnect_interval = max(float(max_reconnect_interval_seconds), self.reconnect_interval)
        self.ssl_verify = ssl_verify
        self.metrics = metrics
        self._running = False
        self._connected = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.notification_count = 0

    def is_connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, name="vw-websocket-client", daemon=True)
            self._thread.start()
            LOGGER.info("Vaultwarden WebSocket listener thread started for %s", self.server_url)

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._connected = False
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self.metrics:
            self.metrics.set_websocket_connected(False)
        LOGGER.info("Vaultwarden WebSocket listener stopped")

    def _create_connection(self) -> socket.socket:
        parsed = urlparse(self.server_url)
        scheme = parsed.scheme.lower()
        is_ssl = scheme in ("wss", "https")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if is_ssl else 80)
        path = parsed.path or "/notifications/hub"
        if parsed.query:
            path += f"?{parsed.query}"

        raw_sock = socket.create_connection((host, port), timeout=15)
        if is_ssl:
            context = ssl.create_default_context()
            if not self.ssl_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {sec_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if self.token:
            headers.append(f"Authorization: Bearer {self.token}")
        headers.extend(["", ""])
        handshake_payload = "\r\n".join(headers).encode("ascii")
        sock.sendall(handshake_payload)

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("Server closed connection during WebSocket handshake")
            response += chunk

        first_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if not (" 101 " in first_line or first_line.endswith(" 101")):
            raise ConnectionError(f"WebSocket handshake rejected by server: {first_line}")

        return sock

    def _send_ws_frame(self, sock: socket.socket, payload: bytes, opcode: int = 0x1) -> None:
        """Send a client-to-server masked WebSocket frame."""
        mask_key = os.urandom(4)
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        length = len(payload)

        header = bytearray()
        header.append(0x80 | (opcode & 0x0F))  # FIN + opcode
        if length < 126:
            header.append(0x80 | length)  # MASK = 1 + len
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        sock.sendall(header + masked_payload)

    def _recv_exact(self, sock: socket.socket, num_bytes: int) -> bytes:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed while reading WebSocket frame")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_ws_frame(self, sock: socket.socket) -> Tuple[int, bytes]:
        """Receive a WebSocket frame (opcode, payload)."""
        header = self._recv_exact(sock, 2)
        opcode = header[0] & 0x0F
        has_mask = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        if length == 126:
            length = struct.unpack("!H", self._recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(sock, 8))[0]

        if has_mask:
            mask_key = self._recv_exact(sock, 4)
            raw_payload = self._recv_exact(sock, length)
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))
        else:
            payload = self._recv_exact(sock, length)

        return opcode, payload

    def _run_loop(self) -> None:
        backoff = self.reconnect_interval
        while self._running:
            sock = None
            try:
                LOGGER.info("Connecting to Vaultwarden WebSocket at %s...", self.server_url)
                sock = self._create_connection()
                with self._lock:
                    self._sock = sock
                    self._connected = True
                if self.metrics:
                    self.metrics.set_websocket_connected(True)
                LOGGER.info("Vaultwarden WebSocket connected successfully")
                backoff = self.reconnect_interval

                # SignalR Handshake
                signalr_handshake = json.dumps({"protocol": "json", "version": 1}) + "\x1e"
                self._send_ws_frame(sock, signalr_handshake.encode("utf-8"), opcode=0x1)

                buffer = ""
                while self._running:
                    opcode, frame_data = self._recv_ws_frame(sock)
                    if opcode == 0x8:  # CLOSE
                        break
                    elif opcode == 0x9:  # PING
                        self._send_ws_frame(sock, frame_data, opcode=0xA)  # PONG
                    elif opcode == 0x1:  # TEXT
                        buffer += frame_data.decode("utf-8", errors="replace")
                        while "\x1e" in buffer:
                            msg_str, buffer = buffer.split("\x1e", 1)
                            msg_str = msg_str.strip()
                            if not msg_str:
                                continue
                            try:
                                msg = json.loads(msg_str)
                                msg_type = msg.get("type")
                                if msg_type == 6:  # SignalR Ping
                                    self._send_ws_frame(sock, b'{"type":6}\x1e', opcode=0x1)
                                elif msg_type == 1:  # Invocation
                                    target = msg.get("target", "")
                                    args = msg.get("arguments", [])
                                    LOGGER.info("Vaultwarden WebSocket event received: target=%s args=%s", target, args)
                                    self.notification_count += 1
                                    if self.metrics:
                                        self.metrics.record_websocket_notification()
                                    if self.on_notification:
                                        try:
                                            self.on_notification(target, args)
                                        except Exception as exc:
                                            LOGGER.error("Error in on_notification callback: %s", exc)
                            except json.JSONDecodeError:
                                pass
            except Exception as exc:
                if self._running:
                    LOGGER.warning("Vaultwarden WebSocket connection lost: %s (reconnecting in %.1fs)", exc, backoff)
            finally:
                with self._lock:
                    self._connected = False
                    if self._sock:
                        try:
                            self._sock.close()
                        except Exception:
                            pass
                        self._sock = None
                if self.metrics:
                    self.metrics.set_websocket_connected(False)

            if self._running:
                time.sleep(backoff)
                backoff = min(backoff * 1.5, self.max_reconnect_interval)

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
    auth_mode = os.getenv("AUTH_MODE", "").strip().lower()
    tokenreview_enabled = parse_bool_env("TOKENREVIEW_ENABLED", False) or auth_mode in ("tokenreview", "dual")

    if not token and not tokenreview_enabled:
        raise RuntimeError("Either BRIDGE_TOKEN or TOKENREVIEW_ENABLED must be configured for authentication")

    allowed_sa_raw = os.getenv("ALLOWED_SERVICE_ACCOUNTS", "").strip()
    allowed_service_accounts = (
        [s.strip() for s in allowed_sa_raw.split(",") if s.strip()]
        if allowed_sa_raw
        else ["system:serviceaccount:external-secrets:external-secrets"]
    )
    audiences_raw = os.getenv("TOKENREVIEW_AUDIENCES", "").strip()
    tokenreview_audiences = [a.strip() for a in audiences_raw.split(",") if a.strip()]

    ws_url = os.getenv("VAULTWARDEN_WS_URL", "").strip()
    if not ws_url:
        srv = os.getenv("VAULTWARDEN_SERVER", os.getenv("BW_SERVER", "")).strip()
        if srv:
            if srv.startswith("https://"):
                ws_url = "wss://" + srv[8:].rstrip("/") + "/notifications/hub"
            elif srv.startswith("http://"):
                ws_url = "ws://" + srv[7:].rstrip("/") + "/notifications/hub"
            else:
                ws_url = "wss://" + srv.rstrip("/") + "/notifications/hub"

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
        bws_access_token=os.getenv("BWS_ACCESS_TOKEN", "").strip(),
        bws_server_url=os.getenv("BWS_SERVER_URL", "").strip(),
        bws_project_id=os.getenv("BWS_PROJECT_ID", "").strip(),
        bws_cli_path=os.getenv("BWS_CLI_PATH", "bws").strip(),
        bws_item_cache_ttl_seconds=parse_non_negative_int_env("BWS_ITEM_CACHE_TTL_SECONDS", 120),
        bws_negative_cache_ttl_seconds=parse_non_negative_int_env("BWS_NEGATIVE_CACHE_TTL_SECONDS", 15),
        bws_command_timeout_seconds=parse_positive_int_env("BWS_COMMAND_TIMEOUT_SECONDS", 60),
        tokenreview_enabled=tokenreview_enabled,
        allowed_service_accounts=allowed_service_accounts,
        tokenreview_cache_ttl_seconds=parse_non_negative_int_env("TOKENREVIEW_CACHE_TTL_SECONDS", 300),
        tokenreview_audiences=tokenreview_audiences,
        tls_enabled=parse_bool_env("TLS_ENABLED", False),
        tls_cert_path=os.getenv("TLS_CERT_PATH", "/etc/tls/tls.crt").strip(),
        tls_key_path=os.getenv("TLS_KEY_PATH", "/etc/tls/tls.key").strip(),
        websocket_sync_enabled=parse_bool_env("WEBSOCKET_SYNC_ENABLED", False),
        websocket_url=ws_url,
        websocket_token=os.getenv("WEBSOCKET_TOKEN", "").strip(),
        websocket_reconnect_interval_seconds=float(os.getenv("WEBSOCKET_RECONNECT_INTERVAL_SECONDS", "5.0")),
        websocket_ssl_verify=parse_bool_env("WEBSOCKET_SSL_VERIFY", True),
        auto_generate_enabled=parse_bool_env("AUTO_GENERATE_ENABLED", False),
        auto_generate_annotation=os.getenv(
            "AUTO_GENERATE_ANNOTATION", DEFAULT_AUTO_GENERATE_ANNOTATION
        ).strip()
        or DEFAULT_AUTO_GENERATE_ANNOTATION,
        auto_generate_password_length_annotation=os.getenv(
            "AUTO_GENERATE_PASSWORD_LENGTH_ANNOTATION", DEFAULT_PASSWORD_LENGTH_ANNOTATION
        ).strip()
        or DEFAULT_PASSWORD_LENGTH_ANNOTATION,
        auto_generate_keys_annotation=os.getenv(
            "AUTO_GENERATE_KEYS_ANNOTATION", DEFAULT_GENERATE_KEYS_ANNOTATION
        ).strip()
        or DEFAULT_GENERATE_KEYS_ANNOTATION,
        auto_generate_default_password_length=parse_positive_int_env(
            "AUTO_GENERATE_DEFAULT_PASSWORD_LENGTH", DEFAULT_GENERATED_PASSWORD_LENGTH
        ),
        auto_generate_list_cache_ttl_seconds=parse_non_negative_int_env(
            "AUTO_GENERATE_LIST_CACHE_TTL_SECONDS", 15
        ),
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
    if config.backend_mode == "bws":
        return BwsBackend(
            access_token=config.bws_access_token,
            server_url=config.bws_server_url,
            project_id=config.bws_project_id,
            bws_path=config.bws_cli_path,
            cache_ttl_seconds=config.bws_item_cache_ttl_seconds,
            negative_cache_ttl_seconds=config.bws_negative_cache_ttl_seconds,
            command_timeout_seconds=config.bws_command_timeout_seconds,
        )
    raise RuntimeError(f"Unsupported BACKEND_MODE: {config.backend_mode}")


class BridgeRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for secret lookups."""

    token: str = ""
    token_legacy_variants: bool = False
    token_review_authenticator: Optional[TokenReviewAuthenticator] = None
    backend: SecretBackend
    provisioner: Optional[ExternalSecretProvisioner] = None
    _autogen_lock = threading.Lock()

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
        if not presented:
            return False
        if self.token and token_matches(self.token, presented, legacy_variants=self.token_legacy_variants):
            return True
        if self.token_review_authenticator and self.token_review_authenticator.authenticate(presented):
            return True
        return False

    def _get_with_autogen(self, namespace: str, secret: str, key: Optional[str]):
        try:
            if key is None:
                return self.backend.get_all_values(namespace, secret)
            return self.backend.get_value(namespace, secret, key)
        except SecretLookupError as exc:
            self._try_autogenerate(namespace, secret, key, exc)
            if key is None:
                return self.backend.get_all_values(namespace, secret)
            return self.backend.get_value(namespace, secret, key)

    def _try_autogenerate(
        self,
        namespace: str,
        secret: str,
        key: Optional[str],
        exc: SecretLookupError,
    ) -> None:
        provisioner = self.provisioner
        if provisioner is None or not provisioner.enabled:
            raise exc
        remote_key = f"{namespace}/{secret}"
        decision = provisioner.decision_for(remote_key, key)
        if not decision.enabled:
            raise exc
        keys = list(decision.keys)
        if not keys:
            keys = [key] if key else ["password"]
        item_name = self.backend.render_item_name(namespace, secret)
        fields = {field: generate_password(decision.password_length) for field in keys}
        LOGGER.info(
            "auto-generate creating missing Vaultwarden item=%s keys=%s",
            item_name,
            list(fields.keys()),
        )
        with self._autogen_lock:
            try:
                if key is None:
                    self.backend.get_all_values(namespace, secret)
                    return
                self.backend.get_value(namespace, secret, key)
                return
            except SecretLookupError:
                self.backend.ensure_item(item_name, fields)

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

                if key is not None and key.startswith("attachment/"):
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
                elif key is None:
                    values = self._get_with_autogen(namespace, secret, None)
                    self._write_json(HTTPStatus.OK, {"data": values, **values})
                else:
                    value = self._get_with_autogen(namespace, secret, key)
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
            if self.path.startswith("/v1/secret/"):
                matched_path = "/v1/secret"
                namespace, secret, key = parse_secret_path(self.path)
                if key:
                    val_str = ""
                    if isinstance(body, dict):
                        val_str = str(body.get("value", body.get(key, body.get("data", ""))))
                    elif isinstance(body, str):
                        val_str = body
                    else:
                        val_str = str(body)
                    result = self.backend.set_value(namespace, secret, key, val_str)
                    LOGGER.info("push secret set_value item=%s/%s key=%s status=%s", namespace, secret, key, result.get("status"))
                    self._write_json(HTTPStatus.OK, {"ok": True, "result": result})
                else:
                    if not isinstance(body, dict):
                        status_code = HTTPStatus.BAD_REQUEST
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": "bulk secret push body must be a JSON object"})
                        return
                    values_dict = {str(k): str(v) if v is not None else "" for k, v in body.items()}
                    result = self.backend.set_all_values(namespace, secret, values_dict)
                    LOGGER.info("push secret set_all_values item=%s/%s keys=%s status=%s", namespace, secret, list(values_dict.keys()), result.get("status"))
                    self._write_json(HTTPStatus.OK, {"ok": True, "result": result})
                return

            elif self.path == "/v1/admin/ensure":
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
                self._write_json(HTTPStatus.NOT_FOUND, {"error": f"unknown route: {self.path}"})
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


    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()

    def do_DELETE(self) -> None:  # noqa: N802
        start_time = time.time()
        status_code = HTTPStatus.OK
        matched_path = self.path

        try:
            if not self._authorized():
                status_code = HTTPStatus.UNAUTHORIZED
                self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return

            if self.path.startswith("/v1/secret/"):
                matched_path = "/v1/secret"
                namespace, secret, key = parse_secret_path(self.path)
                result = self.backend.delete_secret(namespace, secret, key)
                LOGGER.info("push secret delete item=%s/%s key=%s status=%s", namespace, secret, key, result.get("status"))
                self._write_json(HTTPStatus.OK, {"ok": True, "result": result})
            else:
                status_code = HTTPStatus.NOT_FOUND
                self._write_json(HTTPStatus.NOT_FOUND, {"error": f"unknown delete route: {self.path}"})
        except AuthError as exc:
            status_code = HTTPStatus.SERVICE_UNAVAILABLE
            LOGGER.error("delete auth failure path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except SecretLookupError as exc:
            status_code = HTTPStatus.NOT_FOUND
            LOGGER.warning("delete lookup failed path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.NOT_FOUND, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except BridgeError as exc:
            status_code = HTTPStatus.BAD_GATEWAY
            LOGGER.error("delete failure path=%s error=%s", self.path, exc.log_message())
            self._write_json(HTTPStatus.BAD_GATEWAY, {
                "error": str(exc), "code": exc.code, "hint": exc.hint,
            })
        except Exception as exc:  # pragma: no cover
            status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            LOGGER.exception("delete request failed path=%s", self.path)
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

    tokenreview_auth = None
    if config.tokenreview_enabled:
        tokenreview_auth = TokenReviewAuthenticator(
            allowed_service_accounts=config.allowed_service_accounts,
            audiences=config.tokenreview_audiences,
            cache_ttl_seconds=config.tokenreview_cache_ttl_seconds,
        )
        LOGGER.info(
            "TokenReview authenticator enabled for service accounts: %s (cache_ttl=%ss)",
            config.allowed_service_accounts,
            config.tokenreview_cache_ttl_seconds,
        )

    provisioner = None
    if config.auto_generate_enabled:
        provisioner = ExternalSecretProvisioner(
            enabled=True,
            annotation=config.auto_generate_annotation,
            password_length_annotation=config.auto_generate_password_length_annotation,
            generate_keys_annotation=config.auto_generate_keys_annotation,
            default_password_length=config.auto_generate_default_password_length,
            list_cache_ttl_seconds=config.auto_generate_list_cache_ttl_seconds,
        )
        LOGGER.info(
            "ExternalSecret auto-generate enabled annotation=%s password_length_annotation=%s",
            config.auto_generate_annotation,
            config.auto_generate_password_length_annotation,
        )

    LOGGER.info(
        "starting vaultwarden bridge backend_mode=%s port=%s cache_ttl=%ss "
        "neg_cache_ttl=%ss cmd_timeout=%ss token_auth=%s tokenreview_auth=%s tls=%s",
        config.backend_mode,
        port,
        config.bw_item_cache_ttl_seconds,
        config.bw_negative_cache_ttl_seconds,
        config.bw_command_timeout_seconds,
        bool(config.token),
        config.tokenreview_enabled,
        config.tls_enabled,
    )
    if config.token_legacy_variants:
        LOGGER.warning(
            "BRIDGE_TOKEN_LEGACY_VARIANTS enabled: quoted/base64 bearer forms "
            "are accepted and may mask misconfigured secrets; prefer strict matching"
        )

    BridgeRequestHandler.token = config.token
    BridgeRequestHandler.token_legacy_variants = config.token_legacy_variants
    BridgeRequestHandler.token_review_authenticator = tokenreview_auth
    BridgeRequestHandler.backend = backend
    BridgeRequestHandler.provisioner = provisioner
    ws_client = None
    if config.websocket_sync_enabled and config.websocket_url:
        ws_token = config.websocket_token or config.bw_session or config.bws_access_token
        if not ws_token:
            LOGGER.info(
                "WebSocket sync is enabled but no token (WEBSOCKET_TOKEN, BW_SESSION, or BWS_ACCESS_TOKEN) "
                "is available; skipping WebSocket listener"
            )
        else:
            def _on_ws_notification(target: str, args: List[Any]) -> None:
                backend.invalidate_cache()

            ws_client = VaultwardenWebSocketClient(
                server_url=config.websocket_url,
                token=ws_token,
                on_notification=_on_ws_notification,
                reconnect_interval_seconds=config.websocket_reconnect_interval_seconds,
                ssl_verify=config.websocket_ssl_verify,
                metrics=backend.metrics if hasattr(backend, "metrics") else None,
            )
            ws_client.start()
    server = ThreadingHTTPServer(("0.0.0.0", port), BridgeRequestHandler)

    if config.tls_enabled:
        if not os.path.exists(config.tls_cert_path) or not os.path.exists(config.tls_key_path):
            raise RuntimeError(
                f"TLS enabled but certificate files not found: cert={config.tls_cert_path}, key={config.tls_key_path}"
            )
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=config.tls_cert_path, keyfile=config.tls_key_path)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        LOGGER.info("TLS server wrapper active (cert=%s)", config.tls_cert_path)

    server.serve_forever()


if __name__ == "__main__":
    run()
