"""Where the Ed25519 signing key lives. The rest of the server only sees `KeyProvider.sign` and `public_key`, so the
key can move into a cloud KMS later without touching anything else. Never log a key or a token."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class KeyProvider(Protocol):
    def sign(self, data: bytes) -> bytes: ...
    def public_key(self) -> bytes: ...


class _Local:
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_provider() -> KeyProvider:
    """A fresh in-memory key (tests and throw-away demos only)."""
    return _Local(Ed25519PrivateKey.generate())


def from_seed(seed: bytes) -> KeyProvider:
    return _Local(Ed25519PrivateKey.from_private_bytes(seed))


# --- encrypted key file: MAGIC | salt(16) | nonce(12) | AES-GCM(seed) -----------------------------------------
_MAGIC = b"CLNKEY1"


def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def write_encrypted_key(path: Path, passphrase: str) -> bytes:
    """Create a new signing key, store it encrypted, return the public key bytes. Refuses to overwrite."""
    if path.exists():
        raise FileExistsError(f"{path} already exists; refusing to overwrite a signing key")
    if len(passphrase) < 12:
        raise ValueError("use a passphrase of at least 12 characters")
    seed = os.urandom(32)
    salt, nonce = os.urandom(16), os.urandom(12)
    blob = _MAGIC + salt + nonce + AESGCM(_derive(passphrase, salt)).encrypt(nonce, seed, _MAGIC)
    path.write_bytes(blob)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return from_seed(seed).public_key()


def load_encrypted_key(path: Path, passphrase: str) -> KeyProvider:
    blob = path.read_bytes()
    if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + 28 + 48:
        raise ValueError("not a ClearNAI signing key file")
    body = blob[len(_MAGIC) :]
    salt, nonce, ct = body[:16], body[16:28], body[28:]
    seed = AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, _MAGIC)
    return from_seed(seed)
