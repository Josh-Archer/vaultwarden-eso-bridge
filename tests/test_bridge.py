import importlib.util
import os
import pathlib
import subprocess
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
    spec = importlib.util.spec_from_file_location("bridge_server", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


bridge = _load_module()


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

    def _make_bw_backend(self, *, cache_ttl_seconds: int = 120) -> "bridge.BwCliBackend":
        with patch.object(bridge.BwCliBackend, "_run_bw_raw", return_value=""):
            with patch.object(bridge.BwCliBackend, "_validate_session", return_value=True):
                return bridge.BwCliBackend(
                    bw_path="bw",
                    folder_name="",
                    org_id="",
                    item_template="{namespace}/{secret}",
                    bw_server="",
                    bw_email="",
                    bw_password="",
                    bw_session="preseeded-session",
                    cache_ttl_seconds=cache_ttl_seconds,
                    command_timeout_seconds=20,
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


if __name__ == "__main__":
    unittest.main()
