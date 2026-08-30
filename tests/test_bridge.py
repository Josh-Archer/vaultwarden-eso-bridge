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
    import sys
    spec = importlib.util.spec_from_file_location("bridge_server", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bridge_server"] = module
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

    def _make_bw_backend(self, *, cache_ttl_seconds: int = 120, negative_cache_ttl_seconds: int = 15) -> "bridge.BwCliBackend":
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
        auth = bridge.TokenReviewAuthenticator(["system:serviceaccount:external-secrets:external-secrets"])

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

            # Valid TokenReview SA bearer token
            h_valid = _TestHandler("/v1/secret/media/plex/token", {"Authorization": "Bearer sa-jwt-123"})
            h_valid.do_GET()
            self.assertEqual(h_valid.responses[-1]["status"], 200)
            self.assertEqual(h_valid.responses[-1]["payload"]["value"], "plex-pass")

            # Missing authorization header
            h_no_auth = _TestHandler("/v1/secret/media/plex/token", {})
            h_no_auth.do_GET()
            self.assertEqual(h_no_auth.responses[-1]["status"], 401)

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
        backend_ready = bridge.BwsBackend(access_token="0.valid-token:secret")
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
            "BWS_ACCESS_TOKEN": "0.test-token:secret",
            "BWS_SERVER_URL": "https://vault.bitwarden.eu/api",
            "BWS_PROJECT_ID": "proj-uuid-123",
            "BWS_ITEM_CACHE_TTL_SECONDS": "90",
            "BWS_NEGATIVE_CACHE_TTL_SECONDS": "20",
            "BWS_COMMAND_TIMEOUT_SECONDS": "45",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = bridge.build_config_from_env()
            self.assertEqual(config.backend_mode, "bws")
            self.assertEqual(config.bws_access_token, "0.test-token:secret")
            self.assertEqual(config.bws_server_url, "https://vault.bitwarden.eu/api")
            self.assertEqual(config.bws_project_id, "proj-uuid-123")
            self.assertEqual(config.bws_item_cache_ttl_seconds, 90)
            self.assertEqual(config.bws_negative_cache_ttl_seconds, 20)
            self.assertEqual(config.bws_command_timeout_seconds, 45)

            backend = bridge.build_backend(config)
            self.assertIsInstance(backend, bridge.BwsBackend)
            self.assertTrue(backend.is_ready())
if __name__ == "__main__":
    unittest.main()
