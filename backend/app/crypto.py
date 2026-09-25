"""Verschlüsselung gespeicherter API-Zugangsdaten (AES-256-GCM).

Format: b"v1" + 12 Byte Nonce + Ciphertext/Tag, base64-kodiert. Der Verwendungszweck (z. B. `central:<id>`)
ist Associated Data – ein Chiffrat lässt sich nicht unbemerkt einem anderen Datensatz unterschieben.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

_PREFIX = b"v1"
_key_cache: bytes | None = None


def _key() -> bytes:
    global _key_cache
    if _key_cache is None:
        if not config.MASTER_KEY_B64:
            raise RuntimeError("FWM_MASTER_KEY fehlt – mit `openssl rand -base64 32` erzeugen und in .env eintragen")
        key = base64.b64decode(config.MASTER_KEY_B64)
        if len(key) != 32:
            raise RuntimeError("FWM_MASTER_KEY muss 32 Byte (base64-kodiert) lang sein")
        _key_cache = key
    return _key_cache


def encrypt(plaintext: str, purpose: str) -> str:
    nonce = os.urandom(12)
    blob = _PREFIX + nonce + AESGCM(_key()).encrypt(nonce, plaintext.encode(), purpose.encode())
    return base64.b64encode(blob).decode()


def decrypt(value: str, purpose: str) -> str:
    blob = base64.b64decode(value)
    if not blob.startswith(_PREFIX):
        raise ValueError("Unbekanntes Chiffrat-Format")
    nonce, ct = blob[2:14], blob[14:]
    return AESGCM(_key()).decrypt(nonce, ct, purpose.encode()).decode()
