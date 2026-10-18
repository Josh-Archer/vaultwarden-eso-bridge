import importlib.util
import json
import os
import pathlib
import socket
import struct
import subprocess
import threading
import time
import traceback
import unittest
from unittest.mock import patch


BRIDGE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "chart"
    / "vaultwarden-eso-bridge"
    / "files"
    / "bridge_server.py"
)


def _load_module():
    import sys
    spec = importlib.util.spec_from_file_location("bridge_server", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bridge_server"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


bridge = _load_module()


def _read_http_request(conn):
    conn.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip() or b"0")
    while len(rest) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head, rest[:length]


def _recv_exact(conn, size):
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def _read_client_ws_frame(conn):
    header = _recv_exact(conn, 2)
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(conn, 8))[0]
    mask = _recv_exact(conn, 4) if masked else b""
    payload = _recv_exact(conn, length)
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header[0] & 0x0F, payload


def _ws_server_frame(opcode, payload):
    frame = bytearray()
    frame.append(0x80 | (opcode & 0x0F))
    length = len(payload)
    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(payload)
    return bytes(frame)


def _start_hub_server(negotiate_handler, ws_handler=None, upgrade_extra=b"", rounds=1):
    """Serve SignalR negotiate responses and optional WebSocket upgrades.

    ``upgrade_extra`` is written in the same send as the 101 response so tests
    can cover hub frames that share a packet with the handshake. ``rounds``
    accepts that many negotiate-plus-websocket cycles.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(5)
    port = srv.getsockname()[1]
    captured = {"negotiate": [], "websocket": [], "handshake": b"", "error": "", "client_frames": []}

    def _serve():
        try:
            for _ in range(rounds):
                try:
                    conn, _ = srv.accept()
                except (TimeoutError, socket.timeout):
                    return
                try:
                    head, body = _read_http_request(conn)
                    captured["negotiate"].append(head + b"\r\n\r\n" + body)
                    status, resp_body = negotiate_handler(head, body)
                    payload = resp_body if isinstance(resp_body, bytes) else json.dumps(resp_body).encode()
                    response = (
                        b"HTTP/1.1 " + status + b"\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + payload
                    )
                    conn.sendall(response)
                finally:
                    conn.close()
                if ws_handler is None:
                    continue
                try:
                    conn, _ = srv.accept()
                except (TimeoutError, socket.timeout):
                    return
                try:
                    head, _body = _read_http_request(conn)
                    captured["websocket"].append(head)
                    conn.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Upgrade: websocket\r\n"
                        b"Connection: Upgrade\r\n"
                        b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                        + upgrade_extra
                    )
                    ws_handler(conn, captured)
                finally:
                    conn.close()
        except Exception:
            captured["error"] = traceback.format_exc()
        finally:
            srv.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port, thread, captured


def _mp_str(text):
    raw = text.encode("utf-8")
    length = len(raw)
    if length <= 31:
        return bytes((0xA0 | length,)) + raw
    if length <= 255:
        return bytes((0xD9, length)) + raw
    return bytes((0xDA,)) + struct.pack("!H", length) + raw


def _mp_map(items):
    count = len(items)
    if count <= 15:
        head = bytes((0x80 | count,))
    else:
        head = bytes((0xDE,)) + struct.pack("!H", count)
    return head + b"".join(_mp_str(key) + value for key, value in items)


def _signalr_binary_frame(*bodies):
    """Prefix each MessagePack body with a SignalR BinaryMessageFormat length."""
    frame = bytearray()
    for body in bodies:
        size = len(body)
        prefix = bytearray()
        while True:
            part = size & 0x7F
            size >>= 7
            if size:
                prefix.append(part | 0x80)
            else:
                prefix.append(part)
                break
        frame.extend(prefix)
        frame.extend(body)
    return bytes(frame)


def _invocation_body(target, argument):
    """SignalR MessagePack invocation: [1, {}, null, target, [argument]]."""
    return bytes((0x95, 0x01, 0x80, 0xC0)) + _mp_str(target) + bytes((0x91,)) + argument


def _vaultwarden_notification_body():
    """Match vaultwarden ``create_update``: ReceiveMessage with a timestamp 64 payload."""
    uuid = "11111111-1111-1111-1111-111111111111"
    seconds = 1_700_000_000
    timestamp = (123 << 34) | seconds
    payload = _mp_map(
        [
            ("Id", _mp_str(uuid)),
            ("UserId", _mp_str(uuid)),
            ("RevisionDate", bytes((0xD7, 0xFF)) + timestamp.to_bytes(8, "big")),
        ]
    )
    argument = _mp_map(
        [
            ("ContextId", _mp_str("device-1")),
            ("Type", bytes((0,))),
            ("Payload", payload),
        ]
    )
    return _invocation_body("ReceiveMessage", argument)


def _wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class BridgeUnitTests(unittest.TestCase):
    def test_classify_bw_cli_failure_auth_not_logged_in(self):
        err = bridge.classify_bw_cli_failure("You are not logged in.")
        self.assertIsInstance(err, bridge.AuthError)
        self.assertEqual(err.code, "auth_error")
        self.assertIn("Re-authenticate", err.hint)
        self.assertIn("BW_SESSION", err.hint)
        self.assertIn("next_steps:", err.log_message())

    def test_classify_bw_cli_failure_auth_vault_locked(self):
        err = bridge.classify_bw_cli_failure("Vault is locked.")
        self.assertIsInstance(err, bridge.AuthError)
        self.assertIn("Unlock", err.hint)
        self.assertIn("BW_PASSWORD", err.hint)

    def test_classify_bw_cli_failure_auth_server_url(self):
        err = bridge.classify_bw_cli_failure("connect ECONNREFUSED 10.0.0.1:443")
        self.assertIsInstance(err, bridge.AuthError)
        self.assertIn("VAULTWARDEN_SERVER", err.hint)
        self.assertIn("BW_SERVER", err.hint)

    def test_classify_bw_cli_failure_invalid_password(self):
        err = bridge.classify_bw_cli_failure("Invalid master password.")
        self.assertIsInstance(err, bridge.AuthError)
        self.assertIn("BW_PASSWORD", err.hint)

    def test_classify_bw_cli_failure_generic_cli(self):
        err = bridge.classify_bw_cli_failure("something unexpected exploded")
        self.assertIsInstance(err, bridge.BwCliError)
        self.assertNotIsInstance(err, bridge.AuthError)
        self.assertEqual(err.code, "bw_cli_error")
        self.assertTrue(err.hint)

    def test_error_classes_are_distinct(self):
        auth = bridge.AuthError("auth", hint="re-auth")
        missing = bridge.SecretLookupError("missing", hint="create item")
        invalid = bridge.InvalidJsonError("bad json", hint="check session")
        self.assertNotEqual(auth.code, missing.code)
        self.assertNotEqual(missing.code, invalid.code)
        self.assertNotEqual(auth.code, invalid.code)
        self.assertIsInstance(auth, bridge.BridgeError)
        self.assertIsInstance(missing, bridge.BridgeError)
        self.assertIsInstance(invalid, bridge.BridgeError)

    def test_load_mock_secrets(self):
        parsed = bridge.load_mock_secrets('{"default/demo":{"password":"x"}}')
        self.assertEqual(parsed["default/demo"]["password"], "x")

    def test_extract_value_from_bw_item_fields(self):
        item = {"fields": [{"name": "api-key", "value": "abc123"}]}
        self.assertEqual(bridge.extract_value_from_bw_item(item, "api-key"), "abc123")

    def test_extract_value_from_bw_item_login(self):
        item = {"login": {"username": "user", "password": "pass"}}
        self.assertEqual(bridge.extract_value_from_bw_item(item, "login.username"), "user")
        self.assertEqual(bridge.extract_value_from_bw_item(item, "password"), "pass")

    def test_parse_secret_path(self):
        ns, secret, key = bridge.parse_secret_path("/v1/secret/media/plex/token")
        self.assertEqual((ns, secret, key), ("media", "plex", "token"))

    def test_parse_secret_path_encoded_secret_ref(self):
        ns, secret, key = bridge.parse_secret_path(
            "/v1/secret/external-secrets%2Fdemo-shared/password"
        )
        self.assertEqual((ns, secret, key), ("external-secrets", "demo-shared", "password"))

    def test_parse_secret_path_invalid(self):
        with self.assertRaises(ValueError):
            bridge.parse_secret_path("/v1/wrong/path")

    def test_extract_bearer_token(self):
        self.assertEqual(bridge.extract_bearer_token("Bearer abc123"), "abc123")
        self.assertEqual(bridge.extract_bearer_token("bearer abc123"), "abc123")
        self.assertEqual(bridge.extract_bearer_token("Bearer   abc123  "), "abc123")
        self.assertIsNone(bridge.extract_bearer_token("Token abc123"))
        self.assertIsNone(bridge.extract_bearer_token("Bearer"))
        self.assertIsNone(bridge.extract_bearer_token(""))

    def test_expand_token_variants(self):
        self.assertEqual(
            bridge.expand_token_variants("abc123"),
            ("abc123",),
        )
        self.assertEqual(
            bridge.expand_token_variants('"abc123"'),
            ('"abc123"', "abc123"),
        )
        self.assertIn(
            "abc123",
            bridge.expand_token_variants("YWJjMTIz"),
        )

    def test_token_matches_strict_accepts_exact_only(self):
        configured = "abc123"
        self.assertTrue(bridge.token_matches(configured, "abc123", legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, '"abc123"', legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, "'abc123'", legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, "YWJjMTIz", legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, "wrong", legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, None, legacy_variants=False))
        self.assertFalse(bridge.token_matches(configured, "", legacy_variants=False))

    def test_token_matches_legacy_accepts_quote_and_base64(self):
        configured = "abc123"
        self.assertTrue(bridge.token_matches(configured, "abc123", legacy_variants=True))
        self.assertTrue(bridge.token_matches(configured, '"abc123"', legacy_variants=True))
        self.assertTrue(bridge.token_matches(configured, "'abc123'", legacy_variants=True))
        self.assertTrue(bridge.token_matches(configured, "YWJjMTIz", legacy_variants=True))
        self.assertFalse(bridge.token_matches(configured, "wrong", legacy_variants=True))

    def test_token_matches_legacy_warns_on_variant_not_exact(self):
        configured = "abc123"
        with self.assertLogs(bridge.LOGGER, level="WARNING") as captured:
            matched = bridge.token_matches(configured, '"abc123"', legacy_variants=True)
        self.assertTrue(matched)
        self.assertTrue(
            any("legacy variant expansion" in line for line in captured.output),
            captured.output,
        )

        # Exact match must not warn.
        with patch.object(bridge.LOGGER, "warning") as warn_mock:
            self.assertTrue(
                bridge.token_matches(configured, "abc123", legacy_variants=True)
            )
        warn_mock.assert_not_called()

    def test_build_config_defaults_legacy_variants_off(self):
        with patch.dict(
            os.environ,
            {"BRIDGE_TOKEN": "bridge-token"},
            clear=True,
        ):
            config = bridge.build_config_from_env()
        self.assertFalse(config.token_legacy_variants)

    def test_build_config_reads_legacy_variants_flag(self):
        with patch.dict(
            os.environ,
            {
                "BRIDGE_TOKEN": "bridge-token",
                "BRIDGE_TOKEN_LEGACY_VARIANTS": "true",
            },
            clear=True,
        ):
            config = bridge.build_config_from_env()
        self.assertTrue(config.token_legacy_variants)

    def test_mock_backend_lookup(self):
        backend = bridge.MockBackend({"media/servarr": {"api-key": "xyz"}})
        self.assertEqual(backend.get_value("media", "servarr", "api-key"), "xyz")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("media", "servarr", "missing")
        self.assertTrue(backend.is_ready())
        self.assertIn("bridge_auth_refresh_success_total 0", backend.metrics_text())

    def test_bw_cli_backend_requires_auth_material(self):
        with patch.dict(
            os.environ,
            {
                "BRIDGE_TOKEN": "bridge-token",
                "BACKEND_MODE": "bw-cli",
            },
            clear=True,
        ):
            config = bridge.build_config_from_env()
            with self.assertRaises(bridge.AuthError) as ctx:
                bridge.build_backend(config)
            self.assertIn("BW_SESSION", ctx.exception.hint)
            self.assertIn("BW_EMAIL", ctx.exception.hint)

    def test_bw_cli_backend_accepts_preseeded_session(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                with patch.dict(
                    os.environ,
                    {
                        "BRIDGE_TOKEN": "bridge-token",
                        "BACKEND_MODE": "bw-cli",
                        "BW_SESSION": "preseeded-session",
                    },
                    clear=True,
                ):
                    config = bridge.build_config_from_env()
                    backend = bridge.build_backend(config)
                    self.assertIsInstance(backend, bridge.BwCliBackend)
                    self.assertEqual(backend.session, "preseeded-session")

    def test_bw_cli_backend_configures_server_before_login(self):
        calls = []

        def _fake_run_bw_raw(args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ["config", "server"]:
                return ""
            if args[:2] == ["login", "user@example.com"]:
                return "fresh-session"
            if args == ["sync"]:
                return ""
            raise AssertionError(f"unexpected bw args: {args}")

        with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
            with patch.object(bridge.BwCliBackend, "_run_bw_raw", side_effect=_fake_run_bw_raw):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="https://vault.example.internal",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        self.assertEqual(backend.session, "fresh-session")
        self.assertEqual(calls[0][0], ["config", "server", "https://vault.example.internal"])
        self.assertFalse(calls[0][1]["include_session"])


    def test_bw_cli_backend_ignores_logout_required_during_server_config(self):
        calls = []

        def _fake_run_bw_raw(args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ["config", "server"]:
                raise bridge.BwCliError("bw CLI failed: Logout required before server config update.")
            if args[:2] == ["login", "user@example.com"]:
                raise bridge.BwCliError("bw CLI failed: Already logged in.")
            if args[0] == "unlock":
                return "unlocked-session"
            if args == ["sync"]:
                return ""
            raise AssertionError(f"unexpected bw args: {args}")

        with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
            with patch.object(bridge.BwCliBackend, "_run_bw_raw", side_effect=_fake_run_bw_raw):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="https://vault.example.internal",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        self.assertEqual(backend.session, "unlocked-session")
        self.assertEqual(calls[0][0], ["config", "server", "https://vault.example.internal"])
    def _make_bw_backend(
        self,
        *,
        cache_ttl_seconds: int = 120,
        negative_cache_ttl_seconds: int = 15,
        item_template: str = "{namespace}/{secret}",
    ) -> "bridge.BwCliBackend":
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                return bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template=item_template,
                    bw_server="",
                    bw_email="",
                    bw_password="",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=cache_ttl_seconds,
                    command_timeout_seconds=20,
                    negative_cache_ttl_seconds=negative_cache_ttl_seconds,
                )

    def test_parse_non_negative_int_env_allows_zero(self):
        with patch.dict(os.environ, {"BW_ITEM_CACHE_TTL_SECONDS": "0"}, clear=False):
            self.assertEqual(bridge.parse_non_negative_int_env("BW_ITEM_CACHE_TTL_SECONDS", 5), 0)
        with patch.dict(os.environ, {"BW_ITEM_CACHE_TTL_SECONDS": "30"}, clear=False):
            self.assertEqual(bridge.parse_non_negative_int_env("BW_ITEM_CACHE_TTL_SECONDS", 5), 30)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(bridge.parse_non_negative_int_env("BW_ITEM_CACHE_TTL_SECONDS", 0), 0)

    def test_build_config_defaults_cache_ttl_off(self):
        with patch.dict(os.environ, {"BRIDGE_TOKEN": "t"}, clear=True):
            config = bridge.build_config_from_env()
        self.assertEqual(config.bw_item_cache_ttl_seconds, 0)

    def test_bw_cli_backend_caches_item_lookups(self):
        backend = self._make_bw_backend(cache_ttl_seconds=120)
        calls = {"count": 0}

        def _fake_run_bw_json(args):
            if args == ["list", "items", "--search", "infra/consolidated-postgres-secret"]:
                calls["count"] += 1
                return [
                    {
                        "name": "infra/consolidated-postgres-secret",
                        "fields": [
                            {"name": "POSTGRES_DB", "value": "postgres"},
                            {"name": "MAILU_DB", "value": "mailu"},
                        ],
                    }
                ]
            raise AssertionError(f"unexpected bw args: {args}")

        with patch.object(backend, "_run_bw_json", side_effect=_fake_run_bw_json):
            self.assertEqual(
                backend.get_value("infra", "consolidated-postgres-secret", "POSTGRES_DB"),
                "postgres",
            )
            self.assertEqual(
                backend.get_value("infra", "consolidated-postgres-secret", "MAILU_DB"),
                "mailu",
            )

        self.assertEqual(calls["count"], 1)

    def test_bw_cli_backend_cache_miss_for_different_secrets(self):
        backend = self._make_bw_backend(cache_ttl_seconds=120)
        calls = []

        def _fake_run_bw_json(args):
            calls.append(args)
            name = args[-1]
            # Example-only fixture values (not real credentials).
            return [{"name": name, "fields": [{"name": "api-key", "value": f"<example-only-{name}>"}]}]

        with patch.object(backend, "_run_bw_json", side_effect=_fake_run_bw_json):
            self.assertEqual(
                backend.get_value("ns-a", "secret-a", "api-key"),
                "<example-only-ns-a/secret-a>",
            )
            self.assertEqual(
                backend.get_value("ns-b", "secret-a", "api-key"),
                "<example-only-ns-b/secret-a>",
            )

        self.assertEqual(len(calls), 2)
        self.assertIn(("ns-a", "secret-a"), backend._item_cache)
        self.assertIn(("ns-b", "secret-a"), backend._item_cache)

    def test_bw_cli_backend_cache_disabled_when_ttl_zero(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)
        calls = {"count": 0}

        def _fake_run_bw_json(args):
            calls["count"] += 1
            return [
                {
                    "name": "media/plex",
                    "fields": [{"name": "token", "value": "t1"}],
                }
            ]

        with patch.object(backend, "_run_bw_json", side_effect=_fake_run_bw_json):
            self.assertEqual(backend.get_value("media", "plex", "token"), "t1")
            self.assertEqual(backend.get_value("media", "plex", "token"), "t1")

        self.assertEqual(calls["count"], 2)
        self.assertEqual(backend._item_cache, {})

    def test_bw_cli_backend_cache_expiry(self):
        backend = self._make_bw_backend(cache_ttl_seconds=10)
        calls = {"count": 0}
        clock = {"now": 1_000.0}

        def _fake_run_bw_json(args):
            calls["count"] += 1
            return [
                {
                    "name": "media/plex",
                    "fields": [{"name": "token", "value": f"v{calls['count']}"}],
                }
            ]

        with patch.object(backend, "_run_bw_json", side_effect=_fake_run_bw_json):
            with patch.object(bridge.time, "time", side_effect=lambda: clock["now"]):
                self.assertEqual(backend.get_value("media", "plex", "token"), "v1")
                clock["now"] = 1_005.0  # still within TTL
                self.assertEqual(backend.get_value("media", "plex", "token"), "v1")
                clock["now"] = 1_011.0  # expired
                self.assertEqual(backend.get_value("media", "plex", "token"), "v2")

        self.assertEqual(calls["count"], 2)

    def test_bw_cli_backend_reauths_when_session_is_lost(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        self.assertTrue(backend.is_ready())
        self.assertEqual(backend.metrics.snapshot()["auth_refresh_success_total"], 0)

        with patch.object(backend, "_bootstrap_auth") as bootstrap_mock:
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=[
                    bridge.classify_bw_cli_failure("You are not logged in."),
                    "[]",
                ],
            ) as run_mock:
                items = backend._run_bw_json(["list", "items", "--search", "demo"])

        self.assertEqual(items, [])
        bootstrap_mock.assert_called_once()
        self.assertEqual(run_mock.call_count, 2)
        self.assertTrue(backend.is_ready())
        self.assertEqual(backend.metrics.snapshot()["auth_refresh_success_total"], 1)
        self.assertEqual(backend.metrics.snapshot()["auth_refresh_failure_total"], 0)

    def test_bw_cli_backend_marks_not_ready_when_refresh_fails(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        with patch.object(
            backend,
            "_bootstrap_auth",
            side_effect=RuntimeError("login failed"),
        ):
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=bridge.classify_bw_cli_failure("You are not logged in."),
            ):
                with self.assertRaises(RuntimeError):
                    backend._run_bw_json(["list", "items", "--search", "demo"])

        self.assertFalse(backend.is_ready())
        self.assertEqual(backend.metrics.snapshot()["auth_refresh_failure_total"], 1)
        self.assertEqual(backend.metrics.snapshot()["auth_refresh_success_total"], 0)
        metrics = backend.metrics_text()
        self.assertIn("bridge_auth_refresh_failure_total 1", metrics)
        self.assertIn("bridge_bw_session_ready 0", metrics)

    def test_readyz_and_healthz_handlers(self):
        backend = bridge.MockBackend({})
        handler = bridge.BridgeRequestHandler
        handler.token = "token"
        handler.backend = backend

        class _FakeHandler(bridge.BridgeRequestHandler):
            def __init__(self):
                self.path = "/healthz"
                self.headers = {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                import json as _json

                body = _json.dumps(payload).encode("utf-8")
                self.responses.append(
                    {"status": status, "body": body, "headers": {"Content-Type": "application/json"}}
                )

            def _write_text(self, status, body, content_type):
                self.responses.append(
                    {
                        "status": status,
                        "body": body.encode("utf-8"),
                        "headers": {"Content-Type": content_type},
                    }
                )

        fake = _FakeHandler()
        fake.path = "/healthz"
        fake.do_GET()
        self.assertEqual(fake.responses[-1]["status"], 200)

        fake.path = "/readyz"
        fake.do_GET()
        self.assertEqual(fake.responses[-1]["status"], 200)

        class _NotReady:
            def is_ready(self):
                return False

            def metrics_text(self):
                return "bridge_bw_session_ready 0\n"

        fake.backend = _NotReady()
        fake.path = "/readyz"
        fake.do_GET()
        self.assertEqual(fake.responses[-1]["status"], 503)

        fake.path = "/metrics"
        fake.do_GET()
        self.assertEqual(fake.responses[-1]["status"], 200)
        self.assertIn(b"bridge_bw_session_ready", fake.responses[-1]["body"])

    def test_bw_cli_backend_surfaces_auth_error_after_reauth_failure(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        with patch.object(backend, "_bootstrap_auth") as bootstrap_mock:
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=[
                    bridge.classify_bw_cli_failure("You are not logged in."),
                    bridge.classify_bw_cli_failure("You are not logged in."),
                ],
            ):
                with self.assertRaises(bridge.AuthError) as ctx:
                    backend._run_bw_json(["list", "items", "--search", "demo"])

        bootstrap_mock.assert_called_once()
        self.assertIn("Re-authenticate", ctx.exception.hint)

    def test_bw_cli_backend_surfaces_invalid_json_after_retry(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        with patch.object(backend, "_bootstrap_auth") as bootstrap_mock:
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=["not-json", "still-not-json"],
            ):
                with self.assertRaises(bridge.InvalidJsonError) as ctx:
                    backend._run_bw_json(["list", "items", "--search", "demo"])

        bootstrap_mock.assert_called_once()
        self.assertEqual(ctx.exception.code, "invalid_json")
        self.assertIn("BW_SESSION", ctx.exception.hint)

    def test_bw_cli_backend_syncs_on_item_miss_before_failing(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        with patch.object(
            backend,
            "_run_bw_json",
            side_effect=[
                [],
                [
                    {
                        "name": "nextcloud/nextcloud-admin-secret",
                        "fields": [
                            {"name": "NEXTCLOUD_ADMIN_USER", "value": "admin"},
                        ],
                    }
                ],
            ],
        ):
            with patch.object(backend, "_run_bw_raw", return_value="") as run_raw_mock:
                value = backend.get_value(
                    "nextcloud",
                    "nextcloud-admin-secret",
                    "NEXTCLOUD_ADMIN_USER",
                )

        self.assertEqual(value, "admin")
        run_raw_mock.assert_called_once_with(["sync"], tolerate_failure=True)

    def test_bw_cli_select_item_requires_exact_name_match(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)
        items = [
            {"id": "fuzzy-1", "name": "media/plex-old"},
            {"id": "exact", "name": "media/plex"},
            {"id": "fuzzy-2", "name": "media/plex-backup"},
        ]
        selected = backend._select_item(items, "media/plex")
        self.assertEqual(selected["id"], "exact")

    def test_bw_cli_select_item_raises_on_search_miss(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)
        items = [
            {"id": "fuzzy-1", "name": "media/plex-old", "login": {"password": "wrong"}},
            {"id": "fuzzy-2", "name": "media/plex-backup"},
        ]
        with self.assertRaises(bridge.SecretLookupError) as ctx:
            backend._select_item(items, "media/plex")
        self.assertIn("media/plex", str(ctx.exception))

    def test_bw_cli_select_item_requires_org_and_folder_match(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)
        backend.org_id = "org-1"
        items = [
            {"id": "wrong-org", "name": "media/plex", "organizationId": "org-other", "folderId": "folder-1"},
            {"id": "wrong-folder", "name": "media/plex", "organizationId": "org-1", "folderId": "folder-other"},
            {"id": "match", "name": "media/plex", "organizationId": "org-1", "folderId": "folder-1"},
        ]
        with patch.object(backend, "_resolve_folder_id", return_value="folder-1"):
            selected = backend._select_item(items, "media/plex")
        self.assertEqual(selected["id"], "match")

        with patch.object(backend, "_resolve_folder_id", return_value="folder-1"):
            with self.assertRaises(bridge.SecretLookupError):
                backend._select_item(items[:2], "media/plex")

    def test_bw_cli_lookup_does_not_return_fuzzy_search_hit(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)
        with patch.object(
            backend,
            "_run_bw_json",
            return_value=[{"name": "media/plex-old", "login": {"password": "wrong-secret"}}],
        ):
            with patch.object(backend, "_run_bw_raw", return_value=""):
                with self.assertRaises(bridge.SecretLookupError):
                    backend.get_value("media", "plex", "password")


    def test_bw_cli_backend_reauths_on_invalid_json_stdout(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        with patch.object(backend, "_bootstrap_auth") as bootstrap_mock:
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=[
                    "not-json",
                    "[]",
                ],
            ) as run_mock:
                items = backend._run_bw_json(["list", "items", "--search", "demo"])

        self.assertEqual(items, [])
        bootstrap_mock.assert_called_once()
        self.assertEqual(run_mock.call_count, 2)

    def test_bw_cli_backend_uses_explicit_session_flag(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        completed = subprocess.CompletedProcess(
            args=["bw", "list", "items"],
            returncode=0,
            stdout="[]",
            stderr="",
        )

        with patch("subprocess.run", return_value=completed) as run_mock:
            backend._run_bw_raw(["list", "items"])

        command = run_mock.call_args.args[0]
        self.assertEqual(command[-2:], ["--session", "preseeded-session"])

    def test_bw_cli_backend_unlocks_when_already_logged_in(self):
        with patch.object(
            bridge.BwCliBackend,
            "_run_bw_raw",
            side_effect=[
                bridge.classify_bw_cli_failure(
                    "You are already logged in as test@example.com."
                ),
                "unlocked-session",
                "",
            ],
        ):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="user@example.com",
                    bw_password="password",
                    bw_session="",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )
                self.assertEqual(backend.session, "unlocked-session")

    def test_run_bw_raw_classifies_auth_failures(self):
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                backend = bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="",
                    bw_password="",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=120,
                    command_timeout_seconds=20,
                )

        completed = subprocess.CompletedProcess(
            args=["bw", "list", "items"],
            returncode=1,
            stdout="",
            stderr="You are not logged in.",
        )
        with patch("subprocess.run", return_value=completed):
            with self.assertRaises(bridge.AuthError) as ctx:
                # Call unbound implementation to exercise real classification path.
                bridge.BwCliBackend._run_bw_raw(backend, ["list", "items"])

        self.assertIn("Re-authenticate", ctx.exception.hint)



    def test_extract_all_values_from_bw_item(self):
        item = {
            "notes": "some notes",
            "login": {
                "username": "user",
                "password": "pass",
                "totp": "123456",
                "uris": [{"uri": "https://vault.example.com"}],
            },
            "fields": [
                {"name": "API_KEY", "value": "secret-api-key"},
                {"name": "EMPTY_FIELD", "value": None},
                {"name": "PORT", "value": 8080},
            ],
        }
        extracted = bridge.extract_all_values_from_bw_item(item)
        self.assertEqual(extracted["username"], "user")
        self.assertEqual(extracted["login.username"], "user")
        self.assertEqual(extracted["password"], "pass")
        self.assertEqual(extracted["totp"], "123456")
        self.assertEqual(extracted["uri"], "https://vault.example.com")
        self.assertEqual(extracted["notes"], "some notes")
        self.assertEqual(extracted["API_KEY"], "secret-api-key")
        self.assertEqual(extracted["PORT"], "8080")
        self.assertNotIn("EMPTY_FIELD", extracted)

    def test_parse_secret_path_bulk_and_attachment(self):
        # Bulk lookup
        ns, secret, key = bridge.parse_secret_path("/v1/secret/media/plex")
        self.assertEqual((ns, secret, key), ("media", "plex", None))

        # Attachment lookup
        ns, secret, key = bridge.parse_secret_path("/v1/secret/media/plex/attachment/cert.pem")
        self.assertEqual((ns, secret, key), ("media", "plex", "attachment/cert.pem"))

    def test_mock_backend_bulk_and_attachment(self):
        secrets = {
            "media/plex": {
                "username": "plexuser",
                "token": "plextoken",
            }
        }
        attachments = {
            "media/plex": {
                "cert.pem": b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            }
        }
        backend = bridge.MockBackend(secrets, attachments=attachments)

        # Bulk
        all_vals = backend.get_all_values("media", "plex")
        self.assertEqual(all_vals, {"username": "plexuser", "token": "plextoken"})

        with self.assertRaises(bridge.SecretLookupError):
            backend.get_all_values("media", "missing")

        # Attachment
        raw_bytes, mime = backend.get_attachment("media", "plex", "cert.pem")
        self.assertIn(b"BEGIN CERTIFICATE", raw_bytes)
        self.assertEqual(mime, "application/octet-stream")

        with self.assertRaises(bridge.SecretLookupError):
            backend.get_attachment("media", "plex", "missing.pem")

    def test_bw_cli_backend_negative_caching(self):
        backend = self._make_bw_backend(cache_ttl_seconds=60, negative_cache_ttl_seconds=60)

        with patch.object(backend, "_run_bw_json", side_effect=bridge.SecretLookupError("not found")):
            # First lookup: misses cache, fails and stores negative cache
            with self.assertRaises(bridge.SecretLookupError):
                backend.get_value("media", "missing-secret", "token")
            self.assertEqual(backend.metrics.cache_misses_total, 1)
            self.assertEqual(backend.metrics.negative_cache_hits_total, 0)

            # Second lookup within TTL: hits negative cache immediately without calling _run_bw_json again
            with self.assertRaises(bridge.SecretLookupError):
                backend.get_value("media", "missing-secret", "token")
            self.assertEqual(backend.metrics.cache_misses_total, 1)
            self.assertEqual(backend.metrics.negative_cache_hits_total, 1)

    def test_bw_cli_backend_get_all_values(self):
        backend = self._make_bw_backend(cache_ttl_seconds=60)
        item_payload = {
            "name": "media/plex",
            "login": {"username": "plexuser", "password": "plexpassword"},
            "fields": [{"name": "TOKEN", "value": "plextoken123"}],
        }
        with patch.object(backend, "_lookup_item", return_value=item_payload):
            values = backend.get_all_values("media", "plex")
            self.assertEqual(values["username"], "plexuser")
            self.assertEqual(values["password"], "plexpassword")
            self.assertEqual(values["TOKEN"], "plextoken123")

    def test_bw_cli_backend_get_attachment(self):
        backend = self._make_bw_backend(cache_ttl_seconds=60)
        item_payload = {
            "id": "item-12345",
            "name": "media/plex",
            "attachments": [{"id": "att-1", "fileName": "tls.crt", "size": 1024}],
        }
        with patch.object(backend, "_lookup_item", return_value=item_payload):
            def mock_run_bw_raw(args, **kwargs):
                if "attachment" in args:
                    out_idx = args.index("--output") + 1
                    with open(args[out_idx], "wb") as f:
                        f.write(b"MOCK_TLS_CERT_DATA")
                    return ""
                return ""

            with patch.object(backend, "_run_bw_raw", side_effect=mock_run_bw_raw):
                content, mime = backend.get_attachment("media", "plex", "tls.crt")
                self.assertEqual(content, b"MOCK_TLS_CERT_DATA")
                self.assertEqual(mime, "application/octet-stream")

            # Missing attachment error
            with self.assertRaises(bridge.SecretLookupError):
                backend.get_attachment("media", "plex", "missing.key")

    def test_auth_metrics_histogram_and_counters(self):
        metrics = bridge.AuthMetrics()
        metrics.record_cache_hit()
        metrics.record_cache_miss()
        metrics.record_negative_cache_hit()
        metrics.record_request("/v1/secret", 200, 0.015)
        metrics.record_request("/v1/secret", 404, 0.002)

        prom_text = metrics.render_prometheus(session_ready=True)
        self.assertIn("bridge_cache_hits_total 1", prom_text)
        self.assertIn("bridge_cache_misses_total 1", prom_text)
        self.assertIn("bridge_negative_cache_hits_total 1", prom_text)
        self.assertIn("bridge_bw_session_ready 1", prom_text)
        self.assertIn("bridge_request_duration_seconds_bucket", prom_text)
        self.assertIn('path="/v1/secret",status="200"', prom_text)
        self.assertIn('path="/v1/secret",status="404"', prom_text)


    def test_handler_bulk_json_and_attachment_endpoints(self):
        backend = bridge.MockBackend(
            secrets={
                "default/app-secrets": {
                    "username": "admin",
                    "password": "secretpassword",
                    "api_key": "key123",
                }
            },
            attachments={
                "default/app-secrets": {
                    "ca.crt": b"MOCK_CERT_BYTES",
                }
            },
        )
        handler = bridge.BridgeRequestHandler
        handler.token = "valid-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _TestHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                import json as _json
                body = _json.dumps(payload).encode("utf-8")
                self.responses.append(
                    {"status": status, "body": body, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

            def _write_bytes(self, status, body, content_type="application/octet-stream"):
                self.responses.append(
                    {"status": status, "body": body, "headers": {"Content-Type": content_type}}
                )

            def _write_text(self, status, body, content_type):
                self.responses.append(
                    {"status": status, "body": body.encode("utf-8"), "headers": {"Content-Type": content_type}}
                )

        # 1. Bulk multi-key JSON request
        h_bulk = _TestHandler("/v1/secret/default/app-secrets", {"Authorization": "Bearer valid-token"})
        h_bulk.do_GET()
        self.assertEqual(len(h_bulk.responses), 1)
        self.assertEqual(h_bulk.responses[0]["status"], 200)
        payload = h_bulk.responses[0]["payload"]
        self.assertIn("data", payload)
        self.assertEqual(payload["data"]["username"], "admin")
        self.assertEqual(payload["data"]["password"], "secretpassword")
        self.assertEqual(payload["data"]["api_key"], "key123")
        self.assertEqual(payload["username"], "admin")

        # 2. Attachment request with default JSON response (base64)
        h_att_json = _TestHandler("/v1/secret/default/app-secrets/attachment/ca.crt", {"Authorization": "Bearer valid-token"})
        h_att_json.do_GET()
        self.assertEqual(len(h_att_json.responses), 1)
        self.assertEqual(h_att_json.responses[0]["status"], 200)
        att_payload = h_att_json.responses[0]["payload"]
        self.assertEqual(att_payload["filename"], "ca.crt")
        self.assertEqual(att_payload["size"], len(b"MOCK_CERT_BYTES"))
        import base64 as _base64
        self.assertEqual(_base64.b64decode(att_payload["value"]), b"MOCK_CERT_BYTES")

        # 3. Attachment request with binary Accept header
        h_att_bin = _TestHandler(
            "/v1/secret/default/app-secrets/attachment/ca.crt",
            {"Authorization": "Bearer valid-token", "Accept": "application/octet-stream"},
        )
        h_att_bin.do_GET()
        self.assertEqual(len(h_att_bin.responses), 1)
        self.assertEqual(h_att_bin.responses[0]["status"], 200)
        self.assertEqual(h_att_bin.responses[0]["body"], b"MOCK_CERT_BYTES")
        self.assertEqual(h_att_bin.responses[0]["headers"]["Content-Type"], "application/octet-stream")

    def test_render_item_name(self):
        backend = self._make_bw_backend()
        self.assertEqual(backend.render_item_name("auth", "example"), "auth/example")

        custom_backend = self._make_bw_backend(item_template="k8s-{namespace}-{secret}")
        self.assertEqual(
            custom_backend.render_item_name("auth", "example"),
            "k8s-auth-example",
        )

        mock = bridge.MockBackend({"auth/example": {"KEY": "VAL"}})
        self.assertEqual(mock.render_item_name("auth", "example"), "auth/example")


    def test_admin_ensure_creates_and_populates(self):
        """Test POST /v1/admin/ensure creates items and populates missing fields."""
        backend = bridge.MockBackend(secrets={})
        handler = bridge.BridgeRequestHandler
        handler.token = "admin-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _AdminHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []
                self._body = body

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _read_body(self):
                return self._body

            def _write_json(self, status, payload):
                import json as _json
                self.responses.append(
                    {"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

        # Ensure: create new item with fields
        import json as _json
        body = _json.dumps({
            "items": [
                {"name": "media/plex", "fields": {"username": "admin", "api_key": "default-key"}}
            ]
        }).encode()
        h = _AdminHandler("/v1/admin/ensure", body, {"Authorization": "Bearer admin-token"})
        h.do_POST()
        self.assertEqual(h.responses[-1]["status"], 200)
        result = h.responses[-1]["payload"]
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["results"]), 1)
        self.assertTrue(result["results"][0]["created"])
        self.assertIn("username", result["results"][0]["populated"])
        self.assertIn("api_key", result["results"][0]["populated"])

        # Verify item was created in mock
        self.assertEqual(backend.secrets["media/plex"]["username"], "admin")
        self.assertEqual(backend.secrets["media/plex"]["api_key"], "default-key")

        # Ensure again: fields already exist, nothing populated
        h2 = _AdminHandler("/v1/admin/ensure", body, {"Authorization": "Bearer admin-token"})
        h2.do_POST()
        self.assertEqual(h2.responses[-1]["status"], 200)
        r2 = h2.responses[-1]["payload"]
        self.assertFalse(r2["results"][0]["created"])
        self.assertEqual(r2["results"][0]["populated"], [])

    def test_admin_rotate_updates_fields(self):
        """Test POST /v1/admin/rotate rotates specified fields."""
        backend = bridge.MockBackend(secrets={
            "media/plex": {"username": "admin", "password": "old-pass", "api_key": "old-key"}
        })
        handler = bridge.BridgeRequestHandler
        handler.token = "admin-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _AdminHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []
                self._body = body

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _read_body(self):
                return self._body

            def _write_json(self, status, payload):
                import json as _json
                self.responses.append(
                    {"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

        import json as _json
        body = _json.dumps({
            "items": [{"name": "media/plex", "fields": ["password", "api_key"]}],
            "length": 16,
        }).encode()
        h = _AdminHandler("/v1/admin/rotate", body, {"Authorization": "Bearer admin-token"})
        h.do_POST()
        self.assertEqual(h.responses[-1]["status"], 200)
        result = h.responses[-1]["payload"]
        self.assertTrue(result["ok"])
        self.assertIn("password", result["results"][0]["rotated"])
        self.assertIn("api_key", result["results"][0]["rotated"])

        # Values should have changed
        self.assertNotEqual(backend.secrets["media/plex"]["password"], "old-pass")
        self.assertNotEqual(backend.secrets["media/plex"]["api_key"], "old-key")
        # New values should be 16 chars
        self.assertEqual(len(backend.secrets["media/plex"]["password"]), 16)
        self.assertEqual(len(backend.secrets["media/plex"]["api_key"]), 16)
        # Username unchanged
        self.assertEqual(backend.secrets["media/plex"]["username"], "admin")

    def test_admin_rotate_not_found(self):
        """Test POST /v1/admin/rotate returns 404 for missing item."""
        backend = bridge.MockBackend(secrets={})
        handler = bridge.BridgeRequestHandler
        handler.token = "admin-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _AdminHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []
                self._body = body

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _read_body(self):
                return self._body

            def _write_json(self, status, payload):
                import json as _json
                self.responses.append(
                    {"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

        import json as _json
        body = _json.dumps({
            "items": [{"name": "nonexistent/item", "fields": ["password"]}],
        }).encode()
        h = _AdminHandler("/v1/admin/rotate", body, {"Authorization": "Bearer admin-token"})
        h.do_POST()
        self.assertEqual(h.responses[-1]["status"], 404)

    def test_admin_unauthorized(self):
        """Test POST /v1/admin/* returns 401 without valid token."""
        backend = bridge.MockBackend(secrets={})
        handler = bridge.BridgeRequestHandler
        handler.token = "admin-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _AdminHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []
                self._body = body

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _read_body(self):
                return self._body

            def _write_json(self, status, payload):
                import json as _json
                self.responses.append(
                    {"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

        import json as _json
        body = _json.dumps({"items": [{"name": "a/b", "fields": {"x": "y"}}]}).encode()
        h = _AdminHandler("/v1/admin/ensure", body, {"Authorization": "Bearer wrong-token"})
        h.do_POST()
        self.assertEqual(h.responses[-1]["status"], 401)

    def test_admin_invalid_body(self):
        """Test POST /v1/admin/ensure with invalid body returns 400."""
        backend = bridge.MockBackend(secrets={})
        handler = bridge.BridgeRequestHandler
        handler.token = "admin-token"
        handler.backend = backend
        handler.token_legacy_variants = False

        class _AdminHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []
                self._body = body

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _read_body(self):
                return self._body

            def _write_json(self, status, payload):
                import json as _json
                self.responses.append(
                    {"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}}
                )

        # Empty body
        h1 = _AdminHandler("/v1/admin/ensure", b"", {"Authorization": "Bearer admin-token"})
        h1.do_POST()
        self.assertEqual(h1.responses[-1]["status"], 400)

        # Invalid JSON
        h2 = _AdminHandler("/v1/admin/ensure", b"not json", {"Authorization": "Bearer admin-token"})
        h2.do_POST()
        self.assertEqual(h2.responses[-1]["status"], 400)

        # Missing items array
        import json as _json
        h3 = _AdminHandler("/v1/admin/ensure", _json.dumps({"foo": "bar"}).encode(), {"Authorization": "Bearer admin-token"})
        h3.do_POST()
        self.assertEqual(h3.responses[-1]["status"], 400)

    def test_generate_password(self):
        """Test generate_password produces expected-length passwords."""
        pw16 = bridge.generate_password(16)
        self.assertEqual(len(pw16), 16)
        pw64 = bridge.generate_password(64)
        self.assertEqual(len(pw64), 64)
        # Two generated passwords should be different (with overwhelming probability)
        self.assertNotEqual(pw16, bridge.generate_password(16))


    def test_tokenreview_matches_service_account(self):
        """Test TokenReview SA rule matching against various patterns."""
        auth = bridge.TokenReviewAuthenticator([
            "system:serviceaccount:external-secrets:external-secrets",
            "media:*",
            "custom-ns:my-app",
            "slash-ns/slash-app",
        ])

        # Exact match
        self.assertTrue(auth.matches_service_account("system:serviceaccount:external-secrets:external-secrets"))
        # Namespace wildcard
        self.assertTrue(auth.matches_service_account("system:serviceaccount:media:plex"))
        self.assertTrue(auth.matches_service_account("system:serviceaccount:media:radarr"))
        # Short forms
        self.assertTrue(auth.matches_service_account("system:serviceaccount:custom-ns:my-app"))
        self.assertTrue(auth.matches_service_account("system:serviceaccount:slash-ns:slash-app"))

        # Non-matching
        self.assertFalse(auth.matches_service_account("system:serviceaccount:default:attacker"))
        self.assertFalse(auth.matches_service_account("system:serviceaccount:media2:plex"))
        self.assertFalse(auth.matches_service_account(""))

    def test_tokenreview_global_wildcard(self):
        """Test TokenReview SA matching with global wildcard."""
        auth = bridge.TokenReviewAuthenticator(["*"])
        self.assertTrue(auth.matches_service_account("system:serviceaccount:any:sa"))
        self.assertFalse(auth.matches_service_account(""))

    def test_tokenreview_authenticator_cache_and_validation(self):
        """Test TokenReviewAuthenticator caching, hits, and rejection."""
        auth = bridge.TokenReviewAuthenticator(
            ["system:serviceaccount:external-secrets:external-secrets"],
            cache_ttl_seconds=60,
            negative_cache_ttl_seconds=10,
        )

        reviews = []
        def _mock_review(token):
            reviews.append(token)
            if token == "valid-sa-jwt":
                return True, "system:serviceaccount:external-secrets:external-secrets"
            if token == "unauthorized-sa-jwt":
                return True, "system:serviceaccount:default:intruder"
            return False, ""

        with patch.object(auth, "_review_token", side_effect=_mock_review):
            # 1. Valid token
            self.assertTrue(auth.authenticate("valid-sa-jwt"))
            self.assertEqual(len(reviews), 1)

            # 2. Cache hit on valid token
            self.assertTrue(auth.authenticate("valid-sa-jwt"))
            self.assertEqual(len(reviews), 1)  # No new review call

            # 3. Unauthorized user
            self.assertFalse(auth.authenticate("unauthorized-sa-jwt"))
            self.assertEqual(len(reviews), 2)

            # 4. Negative cache hit
            self.assertFalse(auth.authenticate("unauthorized-sa-jwt"))
            self.assertEqual(len(reviews), 2)  # No new review call

            # 5. Invalid / empty token
            self.assertFalse(auth.authenticate(""))
            self.assertFalse(auth.authenticate(None))

    def test_handler_tokenreview_authentication(self):
        """Test BridgeRequestHandler authenticating via TokenReview."""
        backend = bridge.MockBackend(secrets={"media/plex": {"token": "plex-pass"}})
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:external-secrets:external-secrets=media"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:external-secrets:external-secrets")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""  # No static token
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    import json as _json
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

            # Valid TokenReview SA bearer token for permitted namespace
            h_valid = _TestHandler("/v1/secret/media/plex/token", {"Authorization": "Bearer sa-jwt-123"})
            h_valid.do_GET()
            self.assertEqual(h_valid.responses[-1]["status"], 200)
            self.assertEqual(h_valid.responses[-1]["payload"]["value"], "plex-pass")

            # Valid TokenReview SA bearer token for forbidden namespace
            h_forbidden = _TestHandler("/v1/secret/forbidden-ns/plex/token", {"Authorization": "Bearer sa-jwt-123"})
            h_forbidden.do_GET()
            self.assertEqual(h_forbidden.responses[-1]["status"], 403)
            self.assertEqual(h_forbidden.responses[-1]["payload"]["error"], "forbidden")

            # Missing authorization header
            h_no_auth = _TestHandler("/v1/secret/media/plex/token", {})
            h_no_auth.do_GET()
            self.assertEqual(h_no_auth.responses[-1]["status"], 401)

    def test_handler_tokenreview_identity_is_request_scoped_and_fails_closed(self):
        """A failed identity lookup cannot reuse identity state from another request."""
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:media:plex"])
        self.assertFalse(hasattr(auth, "_last_user"))

        class _TestHandler(bridge.BridgeRequestHandler):
            def __init__(self):
                self.path = "/v1/secret/media/plex/token"
                self.headers = {"Authorization": "Bearer sa-jwt"}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload})

        handler = bridge.BridgeRequestHandler
        handler.token = ""
        handler.token_review_authenticator = auth
        handler.token_legacy_variants = False
        request = _TestHandler()
        with patch.object(auth, "get_authenticated_user", return_value=None), patch.object(
            auth, "authenticate", return_value=True
        ):
            self.assertFalse(request._authorized())
        self.assertIsNone(request.caller_sa)
        self.assertEqual(request.auth_type, "")

    def test_tokenreview_least_privilege_namespace_matching(self):
        """Test least-privilege namespace matching rules."""
        # 1. Bare rules restrict to caller's own namespace
        auth = bridge.TokenReviewAuthenticator([
            "system:serviceaccount:media:plex",
            "frontend:*",
            "backend:api",
        ])
        # Same-namespace access allowed
        self.assertTrue(auth.is_namespace_allowed("system:serviceaccount:media:plex", "media"))
        self.assertTrue(auth.is_namespace_allowed("system:serviceaccount:frontend:web", "frontend"))
        self.assertTrue(auth.is_namespace_allowed("system:serviceaccount:backend:api", "backend"))
        # Cross-namespace access denied
        self.assertFalse(auth.is_namespace_allowed("system:serviceaccount:media:plex", "frontend"))
        self.assertFalse(auth.is_namespace_allowed("system:serviceaccount:frontend:web", "backend"))
        self.assertFalse(auth.is_namespace_allowed("system:serviceaccount:backend:api", "media"))

        # 2. Explicit allowed namespaces with '='
        auth_explicit = bridge.TokenReviewAuthenticator([
            "system:serviceaccount:external-secrets:external-secrets=*",
            "system:serviceaccount:monitoring:prometheus=monitoring;infra;cluster",
            "system:serviceaccount:dev:runner=dev-*",
        ])
        # Wildcard namespace allows any
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:external-secrets:external-secrets", "media"))
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:external-secrets:external-secrets", "prod"))
        # Multiple delimited namespaces
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:monitoring:prometheus", "monitoring"))
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:monitoring:prometheus", "infra"))
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:monitoring:prometheus", "cluster"))
        self.assertFalse(auth_explicit.is_namespace_allowed("system:serviceaccount:monitoring:prometheus", "billing"))
        # Glob pattern namespaces
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:dev:runner", "dev-staging"))
        self.assertTrue(auth_explicit.is_namespace_allowed("system:serviceaccount:dev:runner", "dev-test"))
        self.assertFalse(auth_explicit.is_namespace_allowed("system:serviceaccount:dev:runner", "prod"))

        # Commas cannot safely delimit grants because the chart joins entries with commas.
        auth_comma = bridge.TokenReviewAuthenticator(["system:serviceaccount:ops:runner=infra,billing"])
        self.assertFalse(auth_comma.is_namespace_allowed("system:serviceaccount:ops:runner", "infra"))
        self.assertFalse(auth_comma.is_namespace_allowed("system:serviceaccount:ops:runner", "billing"))

        # 3. Global wildcard SA allows any namespace
        auth_wildcard = bridge.TokenReviewAuthenticator(["*"])
        self.assertTrue(auth_wildcard.is_namespace_allowed("system:serviceaccount:any:sa", "any-ns"))

        # 4. Unknown/empty user or namespace
        self.assertFalse(auth.is_namespace_allowed("", "media"))
        self.assertFalse(auth.is_namespace_allowed("system:serviceaccount:unknown:sa", "unknown"))
        self.assertFalse(auth.is_namespace_allowed("system:serviceaccount:media:plex", ""))

    def test_tokenreview_authenticate_with_namespace(self):
        """Test TokenReviewAuthenticator.authenticate with optional namespace parameter."""
        auth = bridge.TokenReviewAuthenticator([
            "system:serviceaccount:media:plex",
            "system:serviceaccount:ops:runner=*",
        ])
        with patch.object(
            auth,
            "_review_token",
            side_effect=lambda t: (True, "system:serviceaccount:media:plex")
            if t == "media-token"
            else (True, "system:serviceaccount:ops:runner")
            if t == "ops-token"
            else (False, ""),
        ):
            # Checking token validity only (namespace=None)
            self.assertTrue(auth.authenticate("media-token"))
            self.assertTrue(auth.authenticate("ops-token"))
            self.assertFalse(auth.authenticate("invalid-token"))

            # Checking token validity + allowed namespace
            self.assertTrue(auth.authenticate("media-token", namespace="media"))
            self.assertFalse(auth.authenticate("media-token", namespace="finance"))
            self.assertTrue(auth.authenticate("ops-token", namespace="media"))
            self.assertTrue(auth.authenticate("ops-token", namespace="finance"))

    def test_handler_tokenreview_least_privilege_endpoints(self):
        """Test BridgeRequestHandler endpoints enforce least-privilege on single, bulk, attachment, and push."""
        backend = bridge.MockBackend(
            secrets={
                "media/plex": {"token": "plex-token"},
                "finance/payroll": {"salary": "secret-salary"},
            },
            attachments={
                "media/plex": {"cert.pem": b"CERT-DATA"},
                "finance/payroll": {"report.pdf": b"PDF-DATA"},
            },
        )
        auth = bridge.TokenReviewAuthenticator([
            "system:serviceaccount:media:plex",
        ])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:media:plex")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None, body=b""):
                    self.path = path
                    self.headers = headers or {}
                    self._test_body = body
                    self.responses = []

                def _read_body(self):
                    return self._test_body

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

                def _write_bytes(self, status, body, content_type="application/octet-stream"):
                    self.responses.append({"status": status, "bytes": body, "headers": {"Content-Type": content_type}})

            auth_header = {"Authorization": "Bearer sa-media-jwt"}

            # 1. Single-key lookup: allowed vs forbidden
            h_single_ok = _TestHandler("/v1/secret/media/plex/token", auth_header)
            h_single_ok.do_GET()
            self.assertEqual(h_single_ok.responses[-1]["status"], 200)
            self.assertEqual(h_single_ok.responses[-1]["payload"]["value"], "plex-token")

            h_single_forbidden = _TestHandler("/v1/secret/finance/payroll/salary", auth_header)
            h_single_forbidden.do_GET()
            self.assertEqual(h_single_forbidden.responses[-1]["status"], 403)
            self.assertEqual(h_single_forbidden.responses[-1]["payload"]["code"], "forbidden")

            # 2. Bulk multi-key lookup: allowed vs forbidden
            h_bulk_ok = _TestHandler("/v1/secret/media/plex", auth_header)
            h_bulk_ok.do_GET()
            self.assertEqual(h_bulk_ok.responses[-1]["status"], 200)

            h_bulk_forbidden = _TestHandler("/v1/secret/finance/payroll", auth_header)
            h_bulk_forbidden.do_GET()
            self.assertEqual(h_bulk_forbidden.responses[-1]["status"], 403)

            # 3. Attachment lookup: allowed vs forbidden
            h_att_ok = _TestHandler("/v1/secret/media/plex/attachment/cert.pem", auth_header)
            h_att_ok.do_GET()
            self.assertEqual(h_att_ok.responses[-1]["status"], 200)

            h_att_forbidden = _TestHandler("/v1/secret/finance/payroll/attachment/report.pdf", auth_header)
            h_att_forbidden.do_GET()
            self.assertEqual(h_att_forbidden.responses[-1]["status"], 403)

            # 4. PushSecret single/bulk: allowed vs forbidden
            import json as _json
            push_body = _json.dumps({"value": "new-val"}).encode()
            h_push_ok = _TestHandler("/v1/secret/media/plex/token", auth_header, push_body)
            h_push_ok.do_POST()
            self.assertEqual(h_push_ok.responses[-1]["status"], 200)

            h_push_forbidden = _TestHandler("/v1/secret/finance/payroll/salary", auth_header, push_body)
            h_push_forbidden.do_POST()
            self.assertEqual(h_push_forbidden.responses[-1]["status"], 403)

            # 5. PUT and DELETE must enforce the same namespace grant as GET/POST.
            h_put_forbidden = _TestHandler("/v1/secret/finance/payroll/salary", auth_header, push_body)
            h_put_forbidden.do_PUT()
            self.assertEqual(h_put_forbidden.responses[-1]["status"], 403)

            h_delete_forbidden = _TestHandler("/v1/secret/finance/payroll/salary", auth_header)
            h_delete_forbidden.do_DELETE()
            self.assertEqual(h_delete_forbidden.responses[-1]["status"], 403)

            # 6. Admin operations blocked for restricted SA
            ensure_body = _json.dumps({"items": [{"name": "media/new", "fields": {"k": "v"}}]}).encode()
            h_admin = _TestHandler("/v1/admin/ensure", auth_header, ensure_body)
            h_admin.do_POST()
            self.assertEqual(h_admin.responses[-1]["status"], 403)

            # 7. Cached token preserves caller identity and still enforces least privilege
            h_cached_ok = _TestHandler("/v1/secret/media/plex/token", auth_header)
            h_cached_ok.do_GET()
            self.assertEqual(h_cached_ok.responses[-1]["status"], 200)

            h_cached_forbidden = _TestHandler("/v1/secret/finance/payroll/salary", auth_header)
            h_cached_forbidden.do_GET()
            self.assertEqual(h_cached_forbidden.responses[-1]["status"], 403)

    def test_build_config_tokenreview_and_tls(self):
        """Test build_config_from_env parsing TokenReview and TLS flags."""
        env_vars = {
            "BRIDGE_TOKEN": "static-token",
            "TOKENREVIEW_ENABLED": "true",
            "ALLOWED_SERVICE_ACCOUNTS": "system:serviceaccount:ns1:sa1, ns2:*",
            "TOKENREVIEW_CACHE_TTL_SECONDS": "180",
            "TOKENREVIEW_AUDIENCES": "https://vaultwarden-eso-bridge, api",
            "TLS_ENABLED": "true",
            "TLS_CERT_PATH": "/custom/tls.crt",
            "TLS_KEY_PATH": "/custom/tls.key",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertEqual(config.token, "static-token")
            self.assertTrue(config.tokenreview_enabled)
            self.assertEqual(config.allowed_service_accounts, ["system:serviceaccount:ns1:sa1", "ns2:*"])
            self.assertEqual(config.tokenreview_cache_ttl_seconds, 180)
            self.assertEqual(config.tokenreview_audiences, ["https://vaultwarden-eso-bridge", "api"])
            self.assertTrue(config.tls_enabled)
            self.assertEqual(config.tls_cert_path, "/custom/tls.crt")
            self.assertEqual(config.tls_key_path, "/custom/tls.key")

    def test_build_config_pure_tokenreview_mode(self):
        """Test build_config_from_env allows pure TokenReview mode with no BRIDGE_TOKEN."""
        env_vars = {
            "BRIDGE_TOKEN": "",
            "AUTH_MODE": "tokenreview",
            "ALLOWED_SERVICE_ACCOUNTS": "system:serviceaccount:external-secrets:external-secrets",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertEqual(config.token, "")
            self.assertTrue(config.tokenreview_enabled)


    def test_bws_backend_init_and_readiness(self):
        """Test BwsBackend readiness with and without access token."""
        backend_ready = bridge.BwsBackend(access_token="mock-bws-access-token-ready")
        self.assertTrue(backend_ready.is_ready())
        self.assertIn("bridge_bw_session_ready 1", backend_ready.metrics_text())

        backend_unready = bridge.BwsBackend(access_token="")
        self.assertFalse(backend_unready.is_ready())
        self.assertIn("bridge_bw_session_ready 0", backend_unready.metrics_text())

    def test_bws_backend_get_value_and_bulk_json(self):
        """Test BwsBackend secret lookup from JSON-encoded secret payload."""
        fake_secrets = [
            {
                "id": "sec-1",
                "key": "media/plex",
                "value": '{"token": "my-plex-token", "claim": "claim-xyz"}',
                "note": "sample note",
            }
        ]

        calls = []
        def _fake_http(method, endpoint, payload):
            calls.append((method, endpoint))
            if endpoint == "secrets":
                return {"data": fake_secrets}
            if endpoint == "secrets/sec-1":
                return fake_secrets[0]
            raise bridge.SecretLookupError(f"not found: {endpoint}")

        backend = bridge.BwsBackend(
            access_token="bws-token",
            cache_ttl_seconds=60,
            http_client=_fake_http,
        )

        # Single value lookup
        val = backend.get_value("media", "plex", "token")
        self.assertEqual(val, "my-plex-token")
        self.assertEqual(backend.get_value("media", "plex", "claim"), "claim-xyz")
        self.assertEqual(backend.get_value("media", "plex", "note"), "sample note")

        # Bulk lookup
        all_vals = backend.get_all_values("media", "plex")
        self.assertEqual(all_vals["token"], "my-plex-token")
        self.assertEqual(all_vals["claim"], "claim-xyz")
        self.assertEqual(all_vals["note"], "sample note")

        # Cache hit — no second API request
        self.assertEqual(len(calls), 1)

    def test_bws_backend_get_value_raw_string(self):
        """Test BwsBackend lookup when secret value is a plain string."""
        fake_secrets = [
            {
                "id": "sec-2",
                "key": "default/db-pass",
                "value": "super-secret-password",
            }
        ]

        def _fake_http(method, endpoint, payload):
            return fake_secrets

        backend = bridge.BwsBackend(
            access_token="bws-token",
            http_client=_fake_http,
        )

        self.assertEqual(backend.get_value("default", "db-pass", "password"), "super-secret-password")
        self.assertEqual(backend.get_value("default", "db-pass", "value"), "super-secret-password")
        self.assertEqual(backend.get_value("default", "db-pass", "db-pass"), "super-secret-password")

    def test_decode_bws_attachment_value_keeps_plaintext(self):
        content, mime = bridge.decode_bws_attachment_value("password")
        self.assertEqual(content, b"password")
        self.assertEqual(mime, "text/plain")

        content, mime = bridge.decode_bws_attachment_value("hello world")
        self.assertEqual(content, b"hello world")
        self.assertEqual(mime, "text/plain")

        pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
        content, mime = bridge.decode_bws_attachment_value(pem)
        self.assertEqual(content, pem.encode("utf-8"))
        self.assertEqual(mime, "text/plain")

        encoded = bridge.base64.b64encode(b"\x00\x01\xffbinary").decode("ascii")
        content, mime = bridge.decode_bws_attachment_value(encoded)
        self.assertEqual(content, b"\x00\x01\xffbinary")
        self.assertEqual(mime, "application/octet-stream")

        content, mime = bridge.decode_bws_attachment_value("dGVz\ndA==")
        self.assertEqual(content, b"test")
        self.assertEqual(mime, "application/octet-stream")

    def test_bws_backend_get_attachment_plaintext_not_decoded(self):
        import json

        fake_secrets = [
            {
                "id": "sec-att",
                "key": "media/plex",
                "value": json.dumps(
                    {
                        "password.txt": "password",
                        "token.bin": bridge.base64.b64encode(b"\x00\x01\xff").decode("ascii"),
                    }
                ),
            }
        ]

        def _fake_http(method, endpoint, payload):
            return fake_secrets

        backend = bridge.BwsBackend(
            access_token="bws-token",
            cache_ttl_seconds=0,
            http_client=_fake_http,
        )
        content, mime = backend.get_attachment("media", "plex", "password.txt")
        self.assertEqual(content, b"password")
        self.assertEqual(mime, "text/plain")

        content, mime = backend.get_attachment("media", "plex", "token.bin")
        self.assertEqual(content, b"\x00\x01\xff")
        self.assertEqual(mime, "application/octet-stream")

    def test_bws_backend_not_found_and_negative_cache(self):
        """Test BwsBackend raises SecretLookupError for missing secrets and caches negative results."""
        calls = []
        def _fake_http(method, endpoint, payload):
            calls.append(endpoint)
            return []

        backend = bridge.BwsBackend(
            access_token="bws-token",
            cache_ttl_seconds=60,
            negative_cache_ttl_seconds=60,
            http_client=_fake_http,
        )

        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("missing-ns", "missing-sec", "key")

        # Second call should raise from negative cache without calling API again
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("missing-ns", "missing-sec", "key")

        self.assertEqual(len(calls), 1)

    def test_bws_backend_ensure_and_rotate_item(self):
        """Test BwsBackend ensure_item (create/update) and rotate_item."""
        store = {}

        def _fake_http(method, endpoint, payload):
            if method == "GET" and endpoint == "secrets":
                return list(store.values())
            if method == "POST" and endpoint == "secrets":
                sec_id = f"id-{len(store)+1}"
                item = {"id": sec_id, **payload}
                store[sec_id] = item
                return item
            if method == "PUT" and endpoint.startswith("secrets/"):
                sec_id = endpoint.split("/")[1]
                store[sec_id].update(payload)
                return store[sec_id]
            raise bridge.SecretLookupError(f"not found: {endpoint}")

        backend = bridge.BwsBackend(
            access_token="bws-token",
            cache_ttl_seconds=0,
            http_client=_fake_http,
        )

        # 1. Ensure new secret
        res1 = backend.ensure_item("media/radarr", {"api_key": "initial-key", "url": "http://radarr:7878"})
        self.assertEqual(res1["status"], "created")
        self.assertEqual(backend.get_value("media", "radarr", "api_key"), "initial-key")

        # 2. Rotate secret field
        res2 = backend.rotate_item("media/radarr", ["api_key"], length=24)
        self.assertEqual(res2["rotated"], ["api_key"])
        new_key = backend.get_value("media", "radarr", "api_key")
        self.assertNotEqual(new_key, "initial-key")
        self.assertEqual(len(new_key), 24)

    def test_build_config_and_backend_bws_mode(self):
        """Test build_config_from_env and build_backend for BWS mode."""
        env_vars = {
            "BRIDGE_TOKEN": "test-token",
            "BACKEND_MODE": "bws",
            "BWS_ACCESS_TOKEN": "mock-bws-test-token-123",
            "BWS_SERVER_URL": "https://vault.bitwarden.eu/api",
            "BWS_PROJECT_ID": "proj-uuid-123",
            "BWS_ITEM_CACHE_TTL_SECONDS": "90",
            "BWS_NEGATIVE_CACHE_TTL_SECONDS": "20",
            "BWS_COMMAND_TIMEOUT_SECONDS": "45",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertEqual(config.backend_mode, "bws")
            self.assertEqual(config.bws_access_token, "mock-bws-test-token-123")
            self.assertEqual(config.bws_server_url, "https://vault.bitwarden.eu/api")
            self.assertEqual(config.bws_project_id, "proj-uuid-123")
            self.assertEqual(config.bws_item_cache_ttl_seconds, 90)
            self.assertEqual(config.bws_negative_cache_ttl_seconds, 20)
            self.assertEqual(config.bws_command_timeout_seconds, 45)

            backend = bridge.build_backend(config)
            self.assertIsInstance(backend, bridge.BwsBackend)
            self.assertTrue(backend.is_ready())

    def test_mock_backend_push_and_delete_operations(self):
        """Test MockBackend set_value, set_all_values, and delete_secret."""
        backend = bridge.MockBackend(secrets={})

        # 1. Set single key
        res1 = backend.set_value("media", "plex", "token", "val-123")
        self.assertEqual(res1["status"], "updated")
        self.assertEqual(backend.get_value("media", "plex", "token"), "val-123")

        # 2. Set multiple keys
        res2 = backend.set_all_values("media", "plex", {"client_id": "cid-456", "extra": "extra-val"})
        self.assertEqual(res2["status"], "updated")
        self.assertEqual(backend.get_value("media", "plex", "token"), "val-123")
        self.assertEqual(backend.get_value("media", "plex", "client_id"), "cid-456")

        # 3. Delete single key
        del1 = backend.delete_secret("media", "plex", key="extra")
        self.assertEqual(del1["status"], "deleted")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("media", "plex", "extra")

        # 4. Delete entire secret
        del2 = backend.delete_secret("media", "plex")
        self.assertEqual(del2["status"], "deleted")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_all_values("media", "plex")

    def test_bws_backend_push_and_delete_operations(self):
        """Test BwsBackend set_value, set_all_values, and delete_secret."""
        store = {}

        def _fake_http(method, endpoint, payload):
            if method == "GET" and endpoint == "secrets":
                return list(store.values())
            if method == "POST" and endpoint == "secrets":
                sec_id = f"id-{len(store)+1}"
                item = {"id": sec_id, **payload}
                store[sec_id] = item
                return item
            if method == "PUT" and endpoint.startswith("secrets/"):
                sec_id = endpoint.split("/")[1]
                store[sec_id].update(payload)
                return store[sec_id]
            if method == "DELETE" and endpoint.startswith("secrets/"):
                sec_id = endpoint.split("/")[1]
                store.pop(sec_id, None)
                return {}
            raise bridge.SecretLookupError(f"not found: {endpoint}")

        backend = bridge.BwsBackend(access_token="bws-token", cache_ttl_seconds=0, http_client=_fake_http)

        # Set single key (creates item)
        res1 = backend.set_value("infra", "db", "db_password_field", "sample-placeholder-value")
        self.assertEqual(res1["status"], "created")
        self.assertEqual(backend.get_value("infra", "db", "db_password_field"), "sample-placeholder-value")

        # Set multiple keys (updates existing item)
        res2 = backend.set_all_values("infra", "db", {"user": "postgres", "port": "5432"})
        self.assertEqual(res2["status"], "updated")
        self.assertEqual(backend.get_value("infra", "db", "db_password_field"), "sample-placeholder-value")
        self.assertEqual(backend.get_value("infra", "db", "user"), "postgres")
        # Delete single key
        del1 = backend.delete_secret("infra", "db", key="port")
        self.assertEqual(del1["status"], "deleted")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("infra", "db", "port")

        # Delete entire secret
        del2 = backend.delete_secret("infra", "db")
        self.assertEqual(del2["status"], "deleted")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_all_values("infra", "db")

    def test_handler_pushsecret_post_put_delete(self):
        """Test HTTP handler do_POST, do_PUT, and do_DELETE for PushSecret endpoints."""
        backend = bridge.MockBackend(secrets={})

        class _PushTestHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, method="POST", body=b"", headers=None):
                self.path = path
                self.headers = headers or {"Authorization": "Bearer test-token"}
                self._test_body = body
                self.responses = []

            def _read_body(self):
                return self._test_body.decode("utf-8")

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

        bridge.BridgeRequestHandler.token = "test-token"
        bridge.BridgeRequestHandler.token_review_authenticator = None
        bridge.BridgeRequestHandler.token_legacy_variants = False
        bridge.BridgeRequestHandler.backend = backend

        import json as _json

        # 1. POST single key push: /v1/secret/media/plex/token
        h1 = _PushTestHandler("/v1/secret/media/plex/token", body=_json.dumps({"value": "p-token-1"}).encode())
        h1.do_POST()
        self.assertEqual(h1.responses[-1]["status"], 200)
        self.assertEqual(backend.get_value("media", "plex", "token"), "p-token-1")

        # 2. PUT bulk secret push: /v1/secret/media/plex
        h2 = _PushTestHandler("/v1/secret/media/plex", method="PUT", body=_json.dumps({"client_id": "c-123", "pin": "9999"}).encode())
        h2.do_PUT()
        self.assertEqual(h2.responses[-1]["status"], 200)
        self.assertEqual(backend.get_value("media", "plex", "token"), "p-token-1")
        self.assertEqual(backend.get_value("media", "plex", "client_id"), "c-123")

        # 3. DELETE property: /v1/secret/media/plex/pin
        h3 = _PushTestHandler("/v1/secret/media/plex/pin", method="DELETE")
        h3.do_DELETE()
        self.assertEqual(h3.responses[-1]["status"], 200)
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("media", "plex", "pin")

        # 4. DELETE entire secret: /v1/secret/media/plex
        h4 = _PushTestHandler("/v1/secret/media/plex", method="DELETE")
        h4.do_DELETE()
        self.assertEqual(h4.responses[-1]["status"], 200)
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_all_values("media", "plex")

    def _run_ws_client(
        self,
        port,
        on_notification,
        reconnect_interval_seconds=1.0,
        keepalive_interval_seconds=15.0,
    ):
        metrics = bridge.AuthMetrics()
        client = bridge.VaultwardenWebSocketClient(
            server_url=f"ws://127.0.0.1:{port}/notifications/hub",
            token="test-token",
            on_notification=on_notification,
            reconnect_interval_seconds=reconnect_interval_seconds,
            keepalive_interval_seconds=keepalive_interval_seconds,
            metrics=metrics,
        )
        return client, metrics

    def test_websocket_client_negotiates_connection_id(self):
        """Negotiate, then join the hub with id and dispatch a JSON invocation."""
        events_received = []

        def _negotiate(_head, _body):
            return (
                b"200 OK",
                {
                    "negotiateVersion": 1,
                    "connectionId": "public-id",
                    "connectionToken": "private-token",
                    "availableTransports": [
                        {"transport": "WebSockets", "transferFormats": ["Text", "Binary"]}
                    ],
                },
            )

        def _websocket(conn, captured):
            _opcode, payload = _read_client_ws_frame(conn)
            captured["handshake"] = payload
            event = b'{"type":1,"target":"SyncVault","arguments":["user-42"]}\x1e'
            conn.sendall(_ws_server_frame(0x1, event))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        negotiate = captured["negotiate"][0].decode()
        self.assertTrue(negotiate.startswith("POST /notifications/hub/negotiate?negotiateVersion=1 "))
        self.assertIn("Authorization: Bearer test-token", negotiate)
        websocket = captured["websocket"][0].decode()
        self.assertIn("GET /notifications/hub?id=private-token&access_token=test-token ", websocket)
        self.assertNotIn("id=public-id", websocket)
        self.assertIn(f"Host: 127.0.0.1:{port}", websocket)
        self.assertIn("Authorization: Bearer test-token", websocket)
        self.assertEqual(captured["handshake"], b'{"protocol":"messagepack","version":1}\x1e')
        self.assertTrue(received)
        self.assertEqual(events_received[0], ("SyncVault", ["user-42"]))
        self.assertEqual(metrics.websocket_notifications_total, 1)

    def test_websocket_client_uses_connection_id_for_negotiate_v0(self):
        """Older negotiate payloads identify the socket with connectionId."""

        def _negotiate(_head, _body):
            return (
                b"200 OK",
                {
                    "connectionId": "conn-v0",
                    "connectionToken": "should-not-use",
                    "availableTransports": [
                        {"transport": "WebSockets", "transferFormats": ["Text", "Binary"]}
                    ],
                },
            )

        def _websocket(conn, captured):
            _opcode, payload = _read_client_ws_frame(conn)
            captured["handshake"] = payload
            time.sleep(0.05)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, _metrics = self._run_ws_client(port, lambda _target, _args: None)
        client.start()
        try:
            opened = _wait_until(lambda: captured["websocket"])
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertTrue(opened)
        websocket = captured["websocket"][0].decode()
        self.assertIn("id=conn-v0", websocket)
        self.assertNotIn("should-not-use", websocket)

    def test_websocket_client_joins_directly_when_negotiate_is_missing(self):
        """Current Vaultwarden has no negotiate route and joins on the upgrade."""
        events_received = []

        def _negotiate(_head, _body):
            return b"404 Not Found", b"no negotiate"

        def _websocket(conn, captured):
            _opcode, payload = _read_client_ws_frame(conn)
            captured["handshake"] = payload
            event = b'{"type":1,"target":"SyncCipherUpdate","arguments":[{"Id":"item-1"}]}\x1e'
            conn.sendall(_ws_server_frame(0x1, event))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        websocket = captured["websocket"][0].decode()
        request_line = websocket.split("\r\n", 1)[0]
        self.assertTrue(request_line.startswith("GET /notifications/hub?"))
        self.assertNotIn("id=", request_line)
        self.assertIn("access_token=test-token", request_line)
        self.assertTrue(received)
        self.assertEqual(events_received[0][0], "SyncCipherUpdate")
        self.assertEqual(metrics.websocket_notifications_total, 1)

    def test_websocket_client_joins_directly_when_negotiate_is_method_not_allowed(self):
        """405 from negotiate is the other signal that the hub has no negotiate route."""

        def _negotiate(_head, _body):
            return b"405 Method Not Allowed", b"no"

        def _websocket(conn, captured):
            _opcode, payload = _read_client_ws_frame(conn)
            captured["handshake"] = payload
            time.sleep(0.05)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, _metrics = self._run_ws_client(port, lambda _target, _args: None)
        client.start()
        try:
            opened = _wait_until(lambda: captured["websocket"])
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertTrue(opened)
        request_line = captured["websocket"][0].decode().split("\r\n", 1)[0]
        self.assertTrue(request_line.startswith("GET /notifications/hub?"))
        self.assertNotIn("id=", request_line)
        self.assertIn("access_token=test-token", request_line)
        self.assertEqual(captured["handshake"], b'{"protocol":"messagepack","version":1}\x1e')

    def test_websocket_invalid_negotiate_json_does_not_open_hub(self):
        def _negotiate(_head, _body):
            return b"200 OK", b"not-json"

        port, thread, captured = _start_hub_server(_negotiate, None)
        client, _metrics = self._run_ws_client(port, lambda _target, _args: None)
        client.start()
        try:
            saw_negotiate = _wait_until(lambda: captured["negotiate"])
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertTrue(saw_negotiate)
        self.assertEqual(captured["websocket"], [])
        self.assertEqual(captured["error"], "")

    def test_websocket_negotiate_auth_failure_does_not_open_hub(self):
        def _negotiate(_head, _body):
            return b"401 Unauthorized", b"denied"

        port, thread, captured = _start_hub_server(_negotiate, None)
        client, _metrics = self._run_ws_client(port, lambda _target, _args: None)
        client.start()
        try:
            saw_negotiate = _wait_until(lambda: captured["negotiate"])
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertTrue(saw_negotiate)
        self.assertEqual(captured["websocket"], [])
        self.assertEqual(len(captured["negotiate"]), 1)
        self.assertIn(b"POST /notifications/hub/negotiate?negotiateVersion=1 ", captured["negotiate"][0])

    def test_websocket_client_messagepack_notification(self):
        """Vaultwarden pushes ReceiveMessage as a length-prefixed MessagePack frame."""
        events_received = []
        # [1, {}, null, "ReceiveMessage", [{"Type": 5}]]
        body = bytes(
            [
                0x95,
                0x01,
                0x80,
                0xC0,
                0xAE,
                0x52,
                0x65,
                0x63,
                0x65,
                0x69,
                0x76,
                0x65,
                0x4D,
                0x65,
                0x73,
                0x73,
                0x61,
                0x67,
                0x65,
                0x91,
                0x81,
                0xA4,
                0x54,
                0x79,
                0x70,
                0x65,
                0x05,
            ]
        )
        frame = bytes([len(body)]) + body

        def _negotiate(_head, _body):
            return b"200 OK", {"negotiateVersion": 1, "connectionToken": "pack-token", "connectionId": "public"}

        def _websocket(conn, _captured):
            _read_client_ws_frame(conn)
            conn.sendall(_ws_server_frame(0x2, b"{}\x1e"))
            conn.sendall(_ws_server_frame(0x2, frame))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertIn("id=pack-token", captured["websocket"][0].decode())
        self.assertTrue(received)
        self.assertEqual(events_received[0][0], "ReceiveMessage")
        self.assertEqual(events_received[0][1], [{"Type": 5}])
        self.assertEqual(metrics.websocket_notifications_total, 1)

    def test_websocket_client_reads_frame_coalesced_with_upgrade(self):
        """A hub frame that shares the 101 packet is still delivered."""
        events_received = []
        event = b'{"type":1,"target":"SyncVault","arguments":["coalesced"]}\x1e'
        extra = _ws_server_frame(0x1, event)

        def _negotiate(_head, _body):
            return b"200 OK", {"negotiateVersion": 1, "connectionToken": "coalesced-id"}

        def _websocket(conn, captured):
            _opcode, payload = _read_client_ws_frame(conn)
            captured["handshake"] = payload
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket, upgrade_extra=extra)
        client, metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertIn("id=coalesced-id", captured["websocket"][0].decode())
        self.assertEqual(captured["handshake"], b'{"protocol":"messagepack","version":1}\x1e')
        self.assertTrue(received)
        self.assertEqual(events_received[0], ("SyncVault", ["coalesced"]))
        self.assertEqual(metrics.websocket_notifications_total, 1)

    def test_websocket_recv_uses_bytes_buffered_after_upgrade(self):
        client = bridge.VaultwardenWebSocketClient(server_url="ws://vault.example/notifications/hub")
        payload = b'{"type":1,"target":"SyncVault","arguments":["buffered"]}\x1e'
        client._recv_buf = _ws_server_frame(0x1, payload)

        class _ClosedSocket:
            def recv(self, _size):
                raise AssertionError("frame should come from the upgrade buffer")

            def settimeout(self, _timeout):
                return None

        opcode, data = client._recv_ws_frame(_ClosedSocket())
        self.assertEqual(opcode, 0x1)
        self.assertEqual(data, payload)
        self.assertEqual(client._recv_buf, b"")

    def test_websocket_recv_continues_buffered_prefix_from_the_socket(self):
        client = bridge.VaultwardenWebSocketClient(server_url="ws://vault.example/notifications/hub")
        frame = _ws_server_frame(0x2, b"\x01\x02")
        client._recv_buf = frame[:1]
        left, right = socket.socketpair()
        try:
            right.sendall(frame[1:])
            opcode, data = client._recv_ws_frame(left)
        finally:
            left.close()
            right.close()
        self.assertEqual(opcode, 0x2)
        self.assertEqual(data, b"\x01\x02")
        self.assertEqual(client._recv_buf, b"")

    def test_websocket_client_pongs_vaultwarden_control_ping(self):
        """Vaultwarden keepalives are WebSocket pings; the hub drops a client that never pongs."""
        events_received = []

        def _negotiate(_head, _body):
            return b"404 Not Found", b"no negotiate"

        def _websocket(conn, captured):
            _read_client_ws_frame(conn)
            conn.sendall(_ws_server_frame(0x9, b"vw-ping"))
            conn.settimeout(1)
            captured["pong"] = _read_client_ws_frame(conn)
            event = b'{"type":1,"target":"SyncVault","arguments":[1]}\x1e'
            conn.sendall(_ws_server_frame(0x1, event))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, _metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertEqual(captured.get("pong"), (0xA, b"vw-ping"))
        self.assertTrue(received)
        self.assertEqual(events_received[0][0], "SyncVault")

    def test_websocket_client_ignores_signalr_protocol_ping(self):
        """A type-6 ping must not be echoed, or Vaultwarden's frame echo loops."""
        events_received = []

        def _negotiate(_head, _body):
            return b"200 OK", {"negotiateVersion": 1, "connectionToken": "ping-id"}

        def _websocket(conn, captured):
            _read_client_ws_frame(conn)
            conn.sendall(_ws_server_frame(0x2, bridge._signalr_msgpack_ping_frame()))
            conn.settimeout(0.3)
            try:
                captured["reply"] = _read_client_ws_frame(conn)
            except (TimeoutError, socket.timeout):
                captured["reply"] = None
            body = _invocation_body("SyncCiphers", _mp_str("folder"))
            conn.sendall(_ws_server_frame(0x2, _signalr_binary_frame(body)))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, _metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: events_received)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertIsNone(captured.get("reply"))
        self.assertTrue(received)
        self.assertEqual(events_received[0], ("SyncCiphers", ["folder"]))

    def test_websocket_client_sends_keepalive_when_idle(self):
        def _negotiate(_head, _body):
            return b"200 OK", {"connectionId": "idle-id"}

        def _websocket(conn, captured):
            conn.settimeout(2)
            frames = []
            try:
                while len(frames) < 2:
                    frames.append(_read_client_ws_frame(conn))
            except (TimeoutError, socket.timeout):
                pass
            captured["client_frames"] = frames

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, _metrics = self._run_ws_client(
            port,
            lambda _target, _args: None,
            keepalive_interval_seconds=0.3,
        )
        client.start()
        try:
            saw_ping = _wait_until(lambda: len(captured["client_frames"]) >= 2, timeout=2)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertTrue(saw_ping)
        handshake_opcode, handshake = captured["client_frames"][0]
        ping_opcode, ping = captured["client_frames"][1]
        self.assertEqual(handshake_opcode, 0x1)
        self.assertEqual(handshake, b'{"protocol":"messagepack","version":1}\x1e')
        self.assertEqual(ping_opcode, 0x2)
        self.assertEqual(ping, bridge._signalr_msgpack_ping_frame())

    def test_websocket_handshake_error_reconnects(self):
        def _negotiate(_head, _body):
            return b"200 OK", {"negotiateVersion": 1, "connectionToken": "again"}

        def _websocket(conn, _captured):
            _read_client_ws_frame(conn)
            conn.sendall(_ws_server_frame(0x2, b'{"error":"unknown protocol"}\x1e'))
            time.sleep(0.1)

        port, thread, captured = _start_hub_server(_negotiate, _websocket, rounds=2)
        client, _metrics = self._run_ws_client(port, lambda _target, _args: None)
        client.start()
        try:
            retried = _wait_until(lambda: len(captured["negotiate"]) >= 2, timeout=3)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertTrue(retried)
        self.assertGreaterEqual(len(captured["websocket"]), 1)
        self.assertIn("id=again", captured["websocket"][0].decode())

    def test_websocket_client_decodes_vaultwarden_notification(self):
        """A length-prefixed ReceiveMessage matches the vaultwarden notifications hub."""
        events_received = []
        body = _vaultwarden_notification_body()
        self.assertGreater(len(body), 127)
        frame = _signalr_binary_frame(body, _invocation_body("SyncVault", bytes((0x05,))))

        def _negotiate(_head, _body):
            return b"404 Not Found", b"no negotiate"

        def _websocket(conn, _captured):
            _read_client_ws_frame(conn)
            conn.sendall(_ws_server_frame(0x2, b"{}\x1e"))
            conn.sendall(_ws_server_frame(0x2, frame))
            time.sleep(0.2)

        port, thread, captured = _start_hub_server(_negotiate, _websocket)
        client, metrics = self._run_ws_client(port, lambda target, args: events_received.append((target, args)))
        client.start()
        try:
            received = _wait_until(lambda: len(events_received) >= 2)
        finally:
            client.stop()
            thread.join(timeout=2)

        self.assertEqual(captured["error"], "")
        self.assertNotIn("id=", captured["websocket"][0].decode().split("\r\n", 1)[0])
        self.assertTrue(received)
        target, args = events_received[0]
        self.assertEqual(target, "ReceiveMessage")
        self.assertEqual(args[0]["ContextId"], "device-1")
        self.assertEqual(args[0]["Type"], 0)
        self.assertEqual(args[0]["Payload"]["Id"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(args[0]["Payload"]["RevisionDate"], 1_700_000_000)
        self.assertEqual(events_received[1], ("SyncVault", [5]))
        self.assertEqual(metrics.websocket_notifications_total, 2)

    def test_signalr_negotiate_url_and_connection_id(self):
        client = bridge.VaultwardenWebSocketClient(
            server_url="wss://vault.example:8443/notifications/hub?foo=1",
            token="tok en",
        )
        self.assertEqual(
            client._build_negotiate_url(),
            "https://vault.example:8443/notifications/hub/negotiate?foo=1&negotiateVersion=1",
        )
        self.assertEqual(
            client._websocket_request_path("a+b/c="),
            "/notifications/hub?foo=1&id=a%2Bb%2Fc%3D&access_token=tok%20en",
        )

        preset = bridge.VaultwardenWebSocketClient(
            server_url="ws://vault.example/notifications/hub?negotiateVersion=0&access_token=already",
            token="other",
        )
        self.assertEqual(
            preset._build_negotiate_url(),
            "http://vault.example/notifications/hub/negotiate?negotiateVersion=0&access_token=already",
        )
        self.assertEqual(
            preset._websocket_request_path("abc"),
            "/notifications/hub?negotiateVersion=0&access_token=already&id=abc",
        )
        self.assertEqual(bridge._format_host_header("vault.example", 443, True), "vault.example")
        self.assertEqual(bridge._format_host_header("vault.example", 8443, True), "vault.example:8443")
        self.assertEqual(bridge._format_host_header("::1", 80, False), "[::1]")
        self.assertEqual(bridge._format_host_header("127.0.0.1", 9, False), "127.0.0.1:9")

        self.assertEqual(
            bridge._connection_id_from_negotiate_payload(
                {"connectionId": "public", "connectionToken": "private"}
            ),
            "public",
        )
        self.assertEqual(
            bridge._connection_id_from_negotiate_payload(
                {"negotiateVersion": 1, "connectionId": "public", "connectionToken": "private"}
            ),
            "private",
        )
        with self.assertRaises(ConnectionError):
            bridge._connection_id_from_negotiate_payload(
                {
                    "negotiateVersion": 1,
                    "connectionToken": "token",
                    "availableTransports": [{"transport": "LongPolling", "transferFormats": ["Text"]}],
                }
            )
        with self.assertRaises(ConnectionError):
            bridge._connection_id_from_negotiate_payload({"negotiateVersion": 1})

    def test_signalr_msgpack_frames_decode_invocation_ping_and_timestamp(self):
        body = bytes(
            [
                0x95,
                0x01,
                0x80,
                0xC0,
                0xAE,
                0x52,
                0x65,
                0x63,
                0x65,
                0x69,
                0x76,
                0x65,
                0x4D,
                0x65,
                0x73,
                0x73,
                0x61,
                0x67,
                0x65,
                0x91,
                0x81,
                0xA4,
                0x54,
                0x79,
                0x70,
                0x65,
                0x05,
            ]
        )
        messages = bridge._iter_signalr_msgpack_messages(bytes([len(body)]) + body)
        self.assertEqual(messages, [[1, {}, None, "ReceiveMessage", [{"Type": 5}]]])
        self.assertEqual(bridge._iter_signalr_msgpack_messages(bridge._signalr_msgpack_ping_frame()), [[6]])
        stamped, consumed = bridge._decode_msgpack_at(bytes([0xD6, 0xFF, 0x00, 0x00, 0x00, 0x02]), 0)
        self.assertEqual((stamped, consumed), (2, 6))
        wide = _vaultwarden_notification_body()
        self.assertGreater(len(wide), 127)
        decoded = bridge._iter_signalr_msgpack_messages(_signalr_binary_frame(wide))
        self.assertEqual(decoded[0][3], "ReceiveMessage")
        self.assertEqual(decoded[0][4][0]["Payload"]["RevisionDate"], 1_700_000_000)
        uint8, offset = bridge._decode_msgpack_at(bytes([0xCC, 0x10]), 0)
        self.assertEqual((uint8, offset), (16, 2))

    def test_build_config_websocket_sync_enabled(self):
        """Test build_config_from_env parses WebSocket sync parameters."""
        env_vars = {
            "BRIDGE_TOKEN": "test-token",
            "WEBSOCKET_SYNC_ENABLED": "true",
            "VAULTWARDEN_WS_URL": "wss://vault.archer.casa/notifications/hub",
            "WEBSOCKET_TOKEN": "ws-bearer-token",
            "WEBSOCKET_RECONNECT_INTERVAL_SECONDS": "8.5",
            "WEBSOCKET_SSL_VERIFY": "false",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertTrue(config.websocket_sync_enabled)
            self.assertEqual(config.websocket_url, "wss://vault.archer.casa/notifications/hub")
            self.assertEqual(config.websocket_token, "ws-bearer-token")
            self.assertEqual(config.websocket_reconnect_interval_seconds, 8.5)
            self.assertFalse(config.websocket_ssl_verify)

    def test_build_config_websocket_url_auto_derived(self):
        """Test VAULTWARDEN_WS_URL is auto-derived from VAULTWARDEN_SERVER when not set."""
        env_vars = {
            "BRIDGE_TOKEN": "test-token",
            "WEBSOCKET_SYNC_ENABLED": "true",
            "VAULTWARDEN_WS_URL": "",
            "VAULTWARDEN_SERVER": "https://vault.example.com",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertTrue(config.websocket_sync_enabled)
            self.assertEqual(config.websocket_url, "wss://vault.example.com/notifications/hub")

    def test_annotation_is_true_and_password_length_clamp(self):
        self.assertTrue(bridge.annotation_is_true("true"))
        self.assertTrue(bridge.annotation_is_true("YES"))
        self.assertTrue(bridge.annotation_is_true("1"))
        self.assertFalse(bridge.annotation_is_true("false"))
        self.assertFalse(bridge.annotation_is_true(None))
        self.assertEqual(bridge.clamp_password_length("32"), 32)
        self.assertEqual(bridge.clamp_password_length("2"), 8)
        self.assertEqual(bridge.clamp_password_length("999"), 128)
        self.assertEqual(bridge.clamp_password_length("nope"), 32)

    def test_iter_externalsecret_remote_refs(self):
        es = {
            "spec": {
                "data": [
                    {"secretKey": "password", "remoteRef": {"key": "default/app", "property": "password"}},
                    {"secretKey": "user", "remoteRef": {"key": "default/app", "property": "username"}},
                ],
                "dataFrom": [{"extract": {"key": "media/plex"}}],
            }
        }
        refs = bridge.iter_externalsecret_remote_refs(es)
        self.assertEqual(
            refs,
            [
                ("default/app", "password"),
                ("default/app", "username"),
                ("media/plex", None),
            ],
        )

    def test_autogenerate_decision_from_externalsecret_annotations(self):
        es = {
            "metadata": {
                "annotations": {
                    "vaultwarden.bridge/auto-generate": "true",
                    "vaultwarden.bridge/password-length": "24",
                }
            },
            "spec": {
                "data": [
                    {
                        "secretKey": "password",
                        "remoteRef": {"key": "default/demo", "property": "password"},
                    }
                ]
            },
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        hit = provisioner.decision_for("default/demo", "password")
        self.assertTrue(hit.enabled)
        self.assertEqual(hit.password_length, 24)
        self.assertEqual(hit.keys, ("password",))

        miss_key = provisioner.decision_for("default/demo", "username")
        self.assertFalse(miss_key.enabled)

        miss_path = provisioner.decision_for("other/demo", "password")
        self.assertFalse(miss_path.enabled)

        disabled = bridge.ExternalSecretProvisioner(
            enabled=False, list_externalsecrets=lambda: [es]
        )
        self.assertFalse(disabled.decision_for("default/demo", "password").enabled)

    def test_autogenerate_decision_bulk_and_fail_closed_list(self):
        es = {
            "metadata": {
                "annotations": {
                    "vaultwarden.bridge/auto-generate": "true",
                    "vaultwarden.bridge/generate-keys": "password,api_key",
                }
            },
            "spec": {"dataFrom": [{"extract": {"key": "media/radarr"}}]},
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        bulk = provisioner.decision_for("media/radarr", None)
        self.assertTrue(bulk.enabled)
        self.assertEqual(bulk.keys, ("password", "api_key"))

        broken = bridge.ExternalSecretProvisioner(
            enabled=True,
            list_externalsecrets=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        self.assertFalse(broken.decision_for("media/radarr", "password").enabled)

    def _autogen_get_handler(self, backend, provisioner):
        bridge.BridgeRequestHandler.token = "valid-token"
        bridge.BridgeRequestHandler.backend = backend
        bridge.BridgeRequestHandler.token_legacy_variants = False
        bridge.BridgeRequestHandler.token_review_authenticator = None
        bridge.BridgeRequestHandler.provisioner = provisioner
        self.addCleanup(setattr, bridge.BridgeRequestHandler, "provisioner", None)

        class _GetHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                pass

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload})

        return _GetHandler

    def test_handler_autogenerate_creates_missing_secret_once(self):
        backend = bridge.MockBackend(secrets={})
        es = {
            "metadata": {"annotations": {"vaultwarden.bridge/auto-generate": "true"}},
            "spec": {
                "data": [
                    {
                        "secretKey": "password",
                        "remoteRef": {"key": "default/generated", "property": "password"},
                    }
                ]
            },
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        handler_cls = self._autogen_get_handler(backend, provisioner)
        first = handler_cls(
            "/v1/secret/default/generated/password",
            {"Authorization": "Bearer valid-token"},
        )
        first.do_GET()
        self.assertEqual(first.responses[-1]["status"], 200)
        created = first.responses[-1]["payload"]["value"]
        self.assertEqual(len(created), 32)
        self.assertEqual(backend.secrets["default/generated"]["password"], created)

        second = handler_cls(
            "/v1/secret/default/generated/password",
            {"Authorization": "Bearer valid-token"},
        )
        second.do_GET()
        self.assertEqual(second.responses[-1]["status"], 200)
        self.assertEqual(second.responses[-1]["payload"]["value"], created)

    def test_handler_autogenerate_does_not_overwrite_existing(self):
        backend = bridge.MockBackend(secrets={"default/keep": {"password": "already-set"}})
        es = {
            "metadata": {"annotations": {"vaultwarden.bridge/auto-generate": "true"}},
            "spec": {
                "data": [
                    {
                        "secretKey": "password",
                        "remoteRef": {"key": "default/keep", "property": "password"},
                    }
                ]
            },
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        handler_cls = self._autogen_get_handler(backend, provisioner)
        req = handler_cls(
            "/v1/secret/default/keep/password",
            {"Authorization": "Bearer valid-token"},
        )
        req.do_GET()
        self.assertEqual(req.responses[-1]["status"], 200)
        self.assertEqual(req.responses[-1]["payload"]["value"], "already-set")

    def test_handler_autogenerate_absent_annotation_stays_404(self):
        backend = bridge.MockBackend(secrets={})
        es = {
            "metadata": {"annotations": {}},
            "spec": {
                "data": [
                    {
                        "secretKey": "password",
                        "remoteRef": {"key": "default/missing", "property": "password"},
                    }
                ]
            },
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        handler_cls = self._autogen_get_handler(backend, provisioner)
        req = handler_cls(
            "/v1/secret/default/missing/password",
            {"Authorization": "Bearer valid-token"},
        )
        req.do_GET()
        self.assertEqual(req.responses[-1]["status"], 404)
        self.assertNotIn("default/missing", backend.secrets)

    def test_handler_autogenerate_respects_password_length(self):
        backend = bridge.MockBackend(secrets={})
        es = {
            "metadata": {
                "annotations": {
                    "vaultwarden.bridge/auto-generate": "true",
                    "vaultwarden.bridge/password-length": "48",
                }
            },
            "spec": {
                "data": [
                    {
                        "secretKey": "password",
                        "remoteRef": {"key": "default/long", "property": "password"},
                    }
                ]
            },
        }
        provisioner = bridge.ExternalSecretProvisioner(
            enabled=True, list_externalsecrets=lambda: [es]
        )
        handler_cls = self._autogen_get_handler(backend, provisioner)
        req = handler_cls(
            "/v1/secret/default/long/password",
            {"Authorization": "Bearer valid-token"},
        )
        req.do_GET()
        self.assertEqual(req.responses[-1]["status"], 200)
        self.assertEqual(len(req.responses[-1]["payload"]["value"]), 48)

    def test_build_config_auto_generate_from_env(self):
        env_vars = {
            "BRIDGE_TOKEN": "test-token",
            "AUTO_GENERATE_ENABLED": "true",
            "AUTO_GENERATE_ANNOTATION": "custom.bridge/auto",
            "AUTO_GENERATE_DEFAULT_PASSWORD_LENGTH": "40",
            "AUTO_GENERATE_LIST_CACHE_TTL_SECONDS": "9",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertTrue(config.auto_generate_enabled)
            self.assertEqual(config.auto_generate_annotation, "custom.bridge/auto")
            self.assertEqual(config.auto_generate_default_password_length, 40)
            self.assertEqual(config.auto_generate_list_cache_ttl_seconds, 9)

    def test_bw_cli_encode_base64_and_get_item_data(self):
        backend = self._make_bw_backend()
        encoded = backend._encode_base64('{"name":"x"}')
        self.assertEqual(encoded, bridge.base64.b64encode(b'{"name":"x"}').decode("ascii"))
        with patch.object(backend, "_get_item_cached", return_value={"id": "abc"}) as cached:
            self.assertEqual(backend._get_item_data("ns", "sec"), {"id": "abc"})
            cached.assert_called_once_with("ns", "sec", "ns/sec")

    def test_bw_cli_delete_secret_clears_login_password_and_username(self):
        backend = self._make_bw_backend(cache_ttl_seconds=0)

        def _edited_item(item, key):
            captured = []

            def _fake_raw(args, **kwargs):
                captured.append(list(args))
                return ""

            with patch.object(backend, "_get_item_data", return_value=item):
                with patch.object(backend, "_run_bw_raw", side_effect=_fake_raw):
                    result = backend.delete_secret("media", "plex", key=key)
            self.assertEqual(result["status"], "deleted")
            edit = next(args for args in captured if args[:2] == ["edit", "item"])
            import json
            return json.loads(bridge.base64.b64decode(edit[3]))

        password_payload = _edited_item(
            {
                "id": "item-1",
                "name": "media/plex",
                "login": {"username": "plexuser", "password": "sample-placeholder-value"},
                "fields": [
                    {"name": "password", "value": "field-placeholder-value"},
                    {"name": "TOKEN", "value": "tok"},
                ],
            },
            "password",
        )
        self.assertNotIn("password", password_payload.get("login") or {})
        self.assertEqual(password_payload["login"]["username"], "plexuser")
        self.assertEqual([field["name"] for field in password_payload["fields"]], ["TOKEN"])

        username_payload = _edited_item(
            {
                "id": "item-1",
                "name": "media/plex",
                "login": {"username": "plexuser", "password": "sample-placeholder-value"},
                "fields": [{"name": "TOKEN", "value": "tok"}],
            },
            "username",
        )
        self.assertNotIn("username", username_payload.get("login") or {})
        self.assertEqual(username_payload["login"]["password"], "sample-placeholder-value")

        alias_payload = _edited_item(
            {
                "id": "item-1",
                "name": "media/plex",
                "login": {"username": "plexuser", "password": "sample-placeholder-value"},
                "fields": [],
            },
            "login.password",
        )
        self.assertNotIn("password", alias_payload.get("login") or {})
        self.assertEqual(alias_payload["login"]["username"], "plexuser")

        token_payload = _edited_item(
            {
                "id": "item-1",
                "name": "media/plex",
                "login": {"username": "plexuser", "password": "sample-placeholder-value"},
                "fields": [{"name": "TOKEN", "value": "tok"}],
            },
            "TOKEN",
        )
        self.assertEqual(token_payload["login"]["username"], "plexuser")
        self.assertEqual(token_payload["login"]["password"], "sample-placeholder-value")
        self.assertEqual(token_payload["fields"], [])

    def test_audit_log_single_secret_read_with_caller_identity(self):
        """Test logging successful single-key secret read with caller identity."""
        backend = bridge.MockBackend(secrets={"media/plex": {"token": "plex-secret-token-value"}})
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:media:plex"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:media:plex")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

            h = _TestHandler("/v1/secret/media/plex/token", {"Authorization": "Bearer sa-jwt-token"})
            with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
                h.do_GET()

            self.assertEqual(h.responses[-1]["status"], 200)
            self.assertEqual(h.responses[-1]["payload"]["value"], "plex-secret-token-value")

            success_logs = [line for line in captured.output if "secret read succeeded" in line]
            self.assertEqual(len(success_logs), 1)
            log_entry = success_logs[0]

            self.assertIn("caller=system:serviceaccount:media:plex", log_entry)
            self.assertIn("service_account=plex", log_entry)
            self.assertIn("caller_namespace=media", log_entry)
            self.assertEqual(log_entry.count("namespace="), 1)
            self.assertIn("item=media/plex", log_entry)
            self.assertIn("key=token", log_entry)

            self.assertNotIn("plex-secret-token-value", log_entry)

    def test_audit_log_bulk_secret_read_with_caller_identity(self):
        """Test logging successful bulk secret read with caller identity."""
        backend = bridge.MockBackend(
            secrets={"billing/invoice": {"api_key": "secret-api-key-999", "webhook": "secret-hook-888"}}
        )
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:billing:invoice-bot"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:billing:invoice-bot")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

            h = _TestHandler("/v1/secret/billing/invoice", {"Authorization": "Bearer sa-billing-jwt"})
            with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
                h.do_GET()

            self.assertEqual(h.responses[-1]["status"], 200)
            success_logs = [line for line in captured.output if "secret read succeeded" in line]
            self.assertEqual(len(success_logs), 1)
            log_entry = success_logs[0]

            self.assertIn("caller=system:serviceaccount:billing:invoice-bot", log_entry)
            self.assertIn("service_account=invoice-bot", log_entry)
            self.assertIn("caller_namespace=billing", log_entry)
            self.assertEqual(log_entry.count("namespace="), 1)
            self.assertIn("item=billing/invoice", log_entry)
            self.assertIn("keys=", log_entry)

            self.assertNotIn("secret-api-key-999", log_entry)
            self.assertNotIn("secret-hook-888", log_entry)

    def test_audit_log_attachment_read_with_caller_identity(self):
        """Test logging successful attachment secret read with caller identity."""
        secret_bytes = b"SUPER-SECRET-PRIVATE-KEY-PEM"
        backend = bridge.MockBackend(
            secrets={},
            attachments={"infra/tls": {"cert.key": secret_bytes}},
        )
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:infra:cert-manager"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:infra:cert-manager")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

                def _write_bytes(self, status, body, content_type="application/octet-stream"):
                    self.responses.append({"status": status, "bytes": body, "headers": {"Content-Type": content_type}})

            # 1. JSON attachment response
            h_json = _TestHandler("/v1/secret/infra/tls/attachment/cert.key", {"Authorization": "Bearer sa-cert-jwt"})
            with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
                h_json.do_GET()
            self.assertEqual(h_json.responses[-1]["status"], 200)

            success_logs = [line for line in captured.output if "secret read succeeded" in line]
            self.assertEqual(len(success_logs), 1)
            log_entry = success_logs[0]

            self.assertIn("caller=system:serviceaccount:infra:cert-manager", log_entry)
            self.assertIn("service_account=cert-manager", log_entry)
            self.assertIn("caller_namespace=infra", log_entry)
            self.assertEqual(log_entry.count("namespace="), 1)
            self.assertIn("item=infra/tls", log_entry)
            self.assertIn("filename=cert.key", log_entry)
            self.assertNotIn("SUPER-SECRET-PRIVATE-KEY-PEM", log_entry)

            # 2. Raw binary octet-stream attachment response
            h_raw = _TestHandler(
                "/v1/secret/infra/tls/attachment/cert.key",
                {"Authorization": "Bearer sa-cert-jwt", "Accept": "application/octet-stream"},
            )
            with self.assertLogs(bridge.LOGGER, level="INFO") as captured_raw:
                h_raw.do_GET()
            self.assertEqual(h_raw.responses[-1]["status"], 200)
            raw_log = [line for line in captured_raw.output if "secret read succeeded" in line][0]
            self.assertIn("filename=cert.key", raw_log)
            self.assertNotIn("SUPER-SECRET-PRIVATE-KEY-PEM", raw_log)

    def test_audit_log_token_authenticated_caller(self):
        """Test logging successful secret read when caller authenticates via static token."""
        fake_secret_val = "fake-test-value-not-a-secret"
        backend = bridge.MockBackend(secrets={"monitoring/grafana": {"admin_password": fake_secret_val}})

        handler = bridge.BridgeRequestHandler
        handler.token = "my-static-bridge-token"
        handler.token_review_authenticator = None
        handler.backend = backend
        handler.token_legacy_variants = False

        class _TestHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

        h = _TestHandler("/v1/secret/monitoring/grafana/admin_password", {"Authorization": "Bearer my-static-bridge-token"})
        with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
            h.do_GET()

        self.assertEqual(h.responses[-1]["status"], 200)
        success_logs = [line for line in captured.output if "secret read succeeded" in line]
        self.assertEqual(len(success_logs), 1)
        log_entry = success_logs[0]

        self.assertIn("caller=token", log_entry)
        self.assertIn("service_account=token", log_entry)
        self.assertIn("caller_namespace=-", log_entry)
        self.assertEqual(log_entry.count("namespace="), 1)
        self.assertIn("item=monitoring/grafana", log_entry)
        self.assertIn("key=admin_password", log_entry)
        self.assertNotIn(fake_secret_val, log_entry)

    def test_secret_value_never_appears_in_logs(self):
        """Test that secret values under all read operations never appear in log records."""
        sensitive_single_value = "fake-test-value-not-a-secret-single-key"
        sensitive_bulk_val1 = "fake-test-value-not-a-secret-bulk-val1"
        sensitive_bulk_val2 = "fake-test-value-not-a-secret-bulk-val2"
        sensitive_att_content = b"fake-test-value-not-a-secret-attachment-content"
        sensitive_att_b64 = bridge.base64.b64encode(sensitive_att_content).decode("utf-8")

        backend = bridge.MockBackend(
            secrets={
                "prod/app": {"api_key": sensitive_single_value},
                "prod/database": {
                    "username": "fake-test-user-not-a-secret",
                    "password": sensitive_bulk_val1,
                    "conn_string": sensitive_bulk_val2,
                },
            },
            attachments={
                "prod/app": {"private.key": sensitive_att_content},
            },
        )
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:prod:app-sa"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:prod:app-sa")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

                def _write_bytes(self, status, body, content_type="application/octet-stream"):
                    self.responses.append({"status": status, "bytes": body, "headers": {"Content-Type": content_type}})

            auth_headers = {"Authorization": "Bearer sa-token"}

            with self.assertLogs(bridge.LOGGER, level="DEBUG") as captured:
                # 1. Single secret read
                h1 = _TestHandler("/v1/secret/prod/app/api_key", auth_headers)
                h1.do_GET()
                self.assertEqual(h1.responses[-1]["status"], 200)

                # 2. Bulk secret read
                h2 = _TestHandler("/v1/secret/prod/database", auth_headers)
                h2.do_GET()
                self.assertEqual(h2.responses[-1]["status"], 200)

                # 3. Attachment secret read (json)
                h3 = _TestHandler("/v1/secret/prod/app/attachment/private.key", auth_headers)
                h3.do_GET()
                self.assertEqual(h3.responses[-1]["status"], 200)

                # 4. Attachment secret read (octet-stream)
                h4 = _TestHandler(
                    "/v1/secret/prod/app/attachment/private.key",
                    {"Authorization": "Bearer sa-token", "Accept": "application/octet-stream"},
                )
                h4.do_GET()
                self.assertEqual(h4.responses[-1]["status"], 200)

            all_logs = "\n".join(captured.output)

            # Assert that NONE of the secret values or secret content ever appear anywhere in the logs
            self.assertNotIn(sensitive_single_value, all_logs)
            self.assertNotIn(sensitive_bulk_val1, all_logs)
            self.assertNotIn(sensitive_bulk_val2, all_logs)
            self.assertNotIn(sensitive_att_content.decode("utf-8"), all_logs)
            self.assertNotIn(sensitive_att_b64, all_logs)

            # Assert caller identity and namespace were properly logged
            self.assertIn("system:serviceaccount:prod:app-sa", all_logs)
            self.assertIn("caller_namespace=prod", all_logs)
            self.assertIn("service_account=app-sa", all_logs)

    def test_audit_log_failed_reads_do_not_log_success(self):
        """Test that failed reads (401, 404, 400) do not emit secret read succeeded logs."""
        backend = bridge.MockBackend(secrets={"media/plex": {"token": "secret"}})

        handler = bridge.BridgeRequestHandler
        handler.token = "expected-token"
        handler.token_review_authenticator = None
        handler.backend = backend
        handler.token_legacy_variants = False

        class _TestHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

        with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
            # 1. 401 Unauthorized
            h_unauth = _TestHandler("/v1/secret/media/plex/token", {"Authorization": "Bearer wrong-token"})
            h_unauth.do_GET()
            self.assertEqual(h_unauth.responses[-1]["status"], 401)

            # 2. 404 Not Found
            h_notfound = _TestHandler("/v1/secret/media/missing/token", {"Authorization": "Bearer expected-token"})
            h_notfound.do_GET()
            self.assertEqual(h_notfound.responses[-1]["status"], 404)

            # 3. 400 Bad Request
            h_bad = _TestHandler("/v1/invalid", {"Authorization": "Bearer expected-token"})
            h_bad.do_GET()
            self.assertEqual(h_bad.responses[-1]["status"], 400)

        # Confirm no "secret read succeeded" is ever logged for failed requests
        for log_line in captured.output:
            self.assertNotIn("secret read succeeded", log_line)

    def test_audit_log_authenticated_sa_fallback_resolves_real_caller(self):
        """Test that audit log resolves the real service account even if caller_sa is preset to literal 'authenticated_sa'."""
        backend = bridge.MockBackend(secrets={"monitoring/grafana": {"token": "fake-test-value-not-a-secret"}})
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:monitoring:prometheus"])

        with patch.object(auth, "_review_token", return_value=(True, "system:serviceaccount:monitoring:prometheus")):
            handler = bridge.BridgeRequestHandler
            handler.token = ""
            handler.token_review_authenticator = auth
            handler.backend = backend
            handler.token_legacy_variants = False

            class _TestHandler(bridge.BridgeRequestHandler):
                def __init__(self, path, headers=None):
                    self.path = path
                    self.headers = headers or {}
                    self.caller_sa = "authenticated_sa"
                    self.responses = []

                def send_response(self, status):
                    self.responses.append({"status": status, "headers": {}})

                def send_header(self, key, value):
                    self.responses[-1]["headers"][key] = value

                def end_headers(self):
                    self.responses[-1]["body"] = b""

                def _write_json(self, status, payload):
                    self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

            h = _TestHandler("/v1/secret/monitoring/grafana/token", {"Authorization": "Bearer sa-prom-token"})
            with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
                h.do_GET()

            self.assertEqual(h.responses[-1]["status"], 200)
            success_logs = [line for line in captured.output if "secret read succeeded" in line]
            self.assertEqual(len(success_logs), 1)
            log_entry = success_logs[0]

            self.assertIn("caller=system:serviceaccount:monitoring:prometheus", log_entry)
            self.assertIn("service_account=prometheus", log_entry)
            self.assertIn("caller_namespace=monitoring", log_entry)
            self.assertNotIn("authenticated_sa", log_entry)
            self.assertEqual(log_entry.count("namespace="), 1)

    def test_audit_log_namespace_logged_only_once_per_entry(self):
        """Test that namespace is logged only once in item=ns/secret and never duplicated as namespace=ns."""
        backend = bridge.MockBackend(secrets={"ns1/mysec": {"mykey": "fake-test-value-not-a-secret"}})

        handler = bridge.BridgeRequestHandler
        handler.token = "my-token"
        handler.token_review_authenticator = None
        handler.backend = backend
        handler.token_legacy_variants = False

        class _TestHandler(bridge.BridgeRequestHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.headers = headers or {}
                self.responses = []

            def send_response(self, status):
                self.responses.append({"status": status, "headers": {}})

            def send_header(self, key, value):
                self.responses[-1]["headers"][key] = value

            def end_headers(self):
                self.responses[-1]["body"] = b""

            def _write_json(self, status, payload):
                self.responses.append({"status": status, "payload": payload, "headers": {"Content-Type": "application/json"}})

        h = _TestHandler("/v1/secret/ns1/mysec/mykey", {"Authorization": "Bearer my-token"})
        with self.assertLogs(bridge.LOGGER, level="INFO") as captured:
            h.do_GET()

        self.assertEqual(h.responses[-1]["status"], 200)
        success_logs = [line for line in captured.output if "secret read succeeded" in line]
        self.assertEqual(len(success_logs), 1)
        log_entry = success_logs[0]

        # The item path contains ns1, but there is no separate namespace=ns1 entry
        self.assertIn("item=ns1/mysec", log_entry)
        self.assertNotIn("namespace=ns1", log_entry)
        self.assertEqual(log_entry.count("namespace="), 1)  # only caller_namespace=-

if __name__ == "__main__":
    unittest.main()
