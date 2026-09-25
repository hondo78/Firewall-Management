"""Zwei-Faktor-Anmeldung (TOTP nach RFC 6238, 30 s, 6 Stellen, SHA-1 – kompatibel zu allen Authenticator-Apps)."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from sqlalchemy.orm import Session as DbSession

from . import crypto, permissions, settings
from .models import User

ISSUER = "Firewall-Management"
PRIVILEGED = ("change.approve", "change.deploy", "firewall.manage", "firmware.manage", "admin")


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify(secret: str, code: str, at: float | None = None, window: int = 1) -> bool:
    code = (code or "").replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    counter = int((at or time.time()) // 30)
    return any(hmac.compare_digest(_code(secret, counter + d), code) for d in range(-window, window + 1))


def provisioning_uri(secret: str, username: str) -> str:
    return (f"otpauth://totp/{quote(ISSUER)}:{quote(username)}?secret={secret}&issuer={quote(ISSUER)}"
            "&algorithm=SHA1&digits=6&period=30")


def secret_of(user: User) -> str:
    return crypto.decrypt(user.totp_secret_enc, f"totp:{user.id}") if user.totp_secret_enc else ""


def check_user_code(user: User, code: str) -> bool:
    return bool(user.totp_enabled and verify(secret_of(user), code))


def required(db: DbSession, user: User) -> bool:
    """Muss dieser Benutzer einen zweiten Faktor verwenden?"""
    mode = settings.get(db, "require_mfa")
    if mode == "all":
        return True
    if mode == "privileged":
        return user.is_superadmin or any(permissions.can_anywhere(db, user, p) for p in PRIVILEGED)
    return False
