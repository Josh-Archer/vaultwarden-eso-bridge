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

    def test_mock_backend_lookup(self):
        backend = bridge.MockBackend({"media/servarr": {"api-key": "xyz"}})
        self.assertEqual(backend.get_value("media", "servarr", "api-key"), "xyz")
        with self.assertRaises(bridge.SecretLookupError):
            backend.get_value("media", "servarr", "missing")

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
            with self.assertRaises(RuntimeError):
                bridge.build_backend(config)

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

    def test_bw_cli_backend_caches_item_lookups(self):
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

        with patch.object(backend, "_bootstrap_auth") as bootstrap_mock:
            with patch.object(
                backend,
                "_run_bw_raw",
                side_effect=[
                    bridge.SecretLookupError("bw CLI failed: You are not logged in."),
                    "[]",
                ],
            ) as run_mock:
                items = backend._run_bw_json(["list", "items", "--search", "demo"])

        self.assertEqual(items, [])
        bootstrap_mock.assert_called_once()
        self.assertEqual(run_mock.call_count, 2)

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
                bridge.SecretLookupError("bw CLI failed: You are already logged in as test@example.com."),
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


if __name__ == "__main__":
    unittest.main()
