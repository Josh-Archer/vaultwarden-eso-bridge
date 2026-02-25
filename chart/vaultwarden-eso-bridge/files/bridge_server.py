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


class SecretLookupError(RuntimeError):
    """Raised when a secret/key cannot be resolved."""


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


@dataclass
class BridgeConfig:
    """Runtime config for bridge server."""

    token: str
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


class SecretBackend:
    """Secret backend interface."""

    def get_value(self, namespace: str, secret: str, key: str) -> str:
        raise NotImplementedError


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
        self._folder_id: Optional[str] = None
        self._cache_lock = threading.RLock()
        self._bw_lock = threading.Lock()
        self._item_cache: Dict[str, Tuple[float, Dict]] = {}

        self._bootstrap_auth()

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
            raise SecretLookupError(
                f"bw CLI timed out after {self.command_timeout_seconds}s"
            ) from exc
        if proc.returncode != 0 and not tolerate_failure:
            detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
            raise SecretLookupError(f"bw CLI failed: {detail}")
        return proc.stdout.strip()

    def _run_bw_json(self, args: List[str]) -> Dict:
        for attempt in range(2):
            try:
                stdout = self._run_bw_raw(args)
            except SecretLookupError as exc:
                # bw CLI can lose auth state at runtime; re-bootstrap and retry once.
                if attempt == 0 and "You are not logged in." in str(exc):
                    self._bootstrap_auth()
                    continue
                raise

            try:
                return json.loads(stdout)
            except json.JSONDecodeError as exc:
                # Some bw-cli auth failures can surface as non-JSON stdout.
                if attempt == 0:
                    self._bootstrap_auth()
                    continue
                raise SecretLookupError(f"bw CLI returned invalid JSON: {exc}") from exc

        raise SecretLookupError("bw CLI JSON lookup exhausted retries")

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
        except (SecretLookupError, json.JSONDecodeError):
            return False
        return isinstance(parsed, list)

    def _bootstrap_auth(self) -> None:
        if self.session and self._validate_session(self.session):
            try:
                self._run_bw_raw(["sync"])
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
    """Return plausible token forms from a bearer value."""
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


def build_config_from_env() -> BridgeConfig:
    """Build BridgeConfig from environment."""
    token = os.getenv("BRIDGE_TOKEN", "").strip()
    if not token:
        raise RuntimeError("BRIDGE_TOKEN is required")
    return BridgeConfig(
        token=token,
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

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        token = extract_bearer_token(header)
        return token is not None and self.token in expand_token_variants(token)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"ok": True})
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
        except SecretLookupError as exc:
            LOGGER.warning("secret lookup failed path=%s error=%s", self.path, exc)
            self._write_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
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
        "starting vaultwarden bridge backend_mode=%s port=%s cache_ttl=%ss cmd_timeout=%ss",
        config.backend_mode,
        port,
        config.bw_item_cache_ttl_seconds,
        config.bw_command_timeout_seconds,
    )

    BridgeRequestHandler.token = config.token
    BridgeRequestHandler.backend = backend
    server = ThreadingHTTPServer(("0.0.0.0", port), BridgeRequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()
