"""PBKDF2 password hashing without extra runtime dependencies."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

SCHEME = "pbkdf2_sha256"
ITERATIONS = 210_000
SALT_BYTES = 16
DIGEST_BYTES = 32


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("password must not be empty")
    raw_salt = salt if salt is not None else os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        raw_salt,
        ITERATIONS,
        dklen=DIGEST_BYTES,
    )
    return (
        f"{SCHEME}${ITERATIONS}${raw_salt.hex()}${digest.hex()}"
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iteration_text, salt_hex, digest_hex = stored.split("$", 3)
        iterations = int(iteration_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    if scheme != SCHEME or iterations < 1:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(candidate, expected)


def dummy_hash() -> str:
    """Constant-time comparison target when the username is unknown."""

    return hash_password("wirescope-invalid-login", salt=b"\x00" * SALT_BYTES)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
