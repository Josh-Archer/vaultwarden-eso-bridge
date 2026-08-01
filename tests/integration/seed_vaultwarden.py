#!/usr/bin/env python3
"""Register an ephemeral Vaultwarden user and seed a bridge-readable item.

This avoids depending on a host-installed Bitwarden CLI for account creation.
Crypto matches the Bitwarden client protocol (PBKDF2 + AES-CBC-HMAC).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def _pbkdf2(password: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
        backend=default_backend(),
    ).derive(prk)


def _stretch_master_key(master_key: bytes) -> bytes:
    return _hkdf_expand(master_key, b"enc", 32) + _hkdf_expand(master_key, b"mac", 32)


def _encrypt(data: bytes, key: bytes) -> str:
    enc_key, mac_key = key[:32], key[32:]
    iv = os.urandom(16)
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return (
        "2."
        + base64.b64encode(iv).decode("ascii")
        + "|"
        + base64.b64encode(ciphertext).decode("ascii")
        + "|"
        + base64.b64encode(mac).decode("ascii")
    )


def _encrypt_str(value: str, key: bytes) -> str:
    return _encrypt(value.encode("utf-8"), key)


def _decrypt(enc_str: str, key: bytes) -> bytes:
    enc_key, mac_key = key[:32], key[32:]
    _typ, rest = enc_str.split(".", 1)
    iv_b64, ct_b64, mac_b64 = rest.split("|")
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ct_b64)
    mac_given = base64.b64decode(mac_b64)
    mac_calc = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_given, mac_calc):
        raise RuntimeError("MAC verification failed while decrypting vault key")
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    plaintext = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    return plaintext[: -plaintext[-1]]


def _ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def _request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: Dict[str, str] | None = None,
    insecure: bool = True,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_context(insecure), timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:500]!r}") from exc


def wait_for_vaultwarden(base_url: str, *, insecure: bool, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error = "not attempted"
    while time.time() < deadline:
        try:
            status, _ = _request(f"{base_url.rstrip('/')}/api/config", insecure=insecure)
            if status == 200:
                return
            last_error = f"status={status}"
        except Exception as exc:  # noqa: BLE001 - poll until ready
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"Vaultwarden not ready after {timeout_seconds}s: {last_error}")


def register_user(
    base_url: str,
    email: str,
    password: str,
    *,
    name: str,
    iterations: int,
    insecure: bool,
) -> tuple[bytes, str]:
    email_n = email.lower().strip()
    master_key = _pbkdf2(password.encode("utf-8"), email_n.encode("utf-8"), iterations)
    master_password_hash = base64.b64encode(
        _pbkdf2(master_key, password.encode("utf-8"), 1)
    ).decode("ascii")
    stretched = _stretch_master_key(master_key)
    user_key = os.urandom(64)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pkcs8 = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "email": email_n,
        "name": name,
        "masterPasswordHash": master_password_hash,
        "masterPasswordHint": None,
        "key": _encrypt(user_key, stretched),
        "kdf": 0,
        "kdfIterations": iterations,
        "kdfMemory": None,
        "kdfParallelism": None,
        "keys": {
            "publicKey": base64.b64encode(public_der).decode("ascii"),
            "encryptedPrivateKey": _encrypt(private_pkcs8, user_key),
        },
    }
    _request(
        f"{base_url.rstrip('/')}/api/accounts/register",
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        insecure=insecure,
    )
    return stretched, master_password_hash


def obtain_token(
    base_url: str,
    email: str,
    master_password_hash: str,
    *,
    insecure: bool,
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": email.lower().strip(),
            "password": master_password_hash,
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": "21",
            "deviceName": "eso-bridge-integration",
            "deviceIdentifier": "00000000-0000-4000-8000-0000000000ab",
        }
    ).encode("utf-8")
    _status, raw = _request(
        f"{base_url.rstrip('/')}/identity/connect/token",
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        insecure=insecure,
    )
    return json.loads(raw.decode("utf-8"))


def create_item(
    base_url: str,
    access_token: str,
    user_key: bytes,
    *,
    item_name: str,
    field_name: str,
    field_value: str,
    login_username: str,
    login_password: str,
    insecure: bool,
) -> None:
    cipher = {
        "type": 1,
        "name": _encrypt_str(item_name, user_key),
        "notes": None,
        "favorite": False,
        "reprompt": 0,
        "folderId": None,
        "organizationId": None,
        "login": {
            "username": _encrypt_str(login_username, user_key),
            "password": _encrypt_str(login_password, user_key),
            "totp": None,
            "uris": [],
        },
        "fields": [
            {
                "type": 0,
                "name": _encrypt_str(field_name, user_key),
                "value": _encrypt_str(field_value, user_key),
                "linkedId": None,
            }
        ],
        "card": None,
        "identity": None,
        "secureNote": None,
        "passwordHistory": None,
        "attachments": None,
        "collectionIds": None,
    }
    _request(
        f"{base_url.rstrip('/')}/api/ciphers",
        method="POST",
        data=json.dumps(cipher).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        },
        insecure=insecure,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.getenv("VAULTWARDEN_URL", "https://vaultwarden:80"),
    )
    parser.add_argument("--email", default=os.getenv("BW_EMAIL", "integration@example.com"))
    parser.add_argument(
        "--password",
        default=os.getenv("BW_PASSWORD", "<example-only-integration-password>"),
    )
    parser.add_argument("--item-name", default=os.getenv("SEED_ITEM_NAME", "default/demo-secret"))
    parser.add_argument("--field-name", default=os.getenv("SEED_FIELD_NAME", "api-key"))
    parser.add_argument(
        "--field-value",
        default=os.getenv("SEED_FIELD_VALUE", "<example-only-seed-field-value>"),
    )
    parser.add_argument("--wait-seconds", type=int, default=60)
    parser.add_argument("--kdf-iterations", type=int, default=600000)
    parser.add_argument(
        "--insecure",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip TLS certificate verification (default for self-signed integration certs)",
    )
    args = parser.parse_args()

    print(f"Waiting for Vaultwarden at {args.base_url} ...")
    wait_for_vaultwarden(args.base_url, insecure=args.insecure, timeout_seconds=args.wait_seconds)

    print(f"Registering user {args.email} ...")
    stretched, master_password_hash = register_user(
        args.base_url,
        args.email,
        args.password,
        name="ESO Bridge Integration",
        iterations=args.kdf_iterations,
        insecure=args.insecure,
    )

    print("Obtaining session token ...")
    token = obtain_token(
        args.base_url,
        args.email,
        master_password_hash,
        insecure=args.insecure,
    )
    user_key = _decrypt(token["Key"], stretched)

    print(f"Seeding item {args.item_name} field {args.field_name} ...")
    create_item(
        args.base_url,
        token["access_token"],
        user_key,
        item_name=args.item_name,
        field_name=args.field_name,
        field_value=args.field_value,
        login_username="integration",
        login_password="<example-only-unused-login-password>",
        insecure=args.insecure,
    )
    print("Vaultwarden seed complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
