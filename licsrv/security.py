"""Admin authentication: argon2 passwords, TOTP second factor, signed session cookie with a CSRF token, lockout."""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import AdminUser

COOKIE = "licsrv_session"
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("use a password of at least 12 characters")
    return _hasher.hash(password)


def check_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_totp_secret() -> str:
    return pyotp.random_base32()


def check_totp(secret: str, code: str) -> bool:
    return bool(code) and pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def _serializer() -> URLSafeTimedSerializer:
    if len(settings.session_secret) < 32:
        raise RuntimeError("LICSRV_SESSION_SECRET must be set to a random value of at least 32 characters")
    return URLSafeTimedSerializer(settings.session_secret, salt="licsrv-session")


def make_session(admin_id: str) -> tuple[str, str]:
    """(cookie value, csrf token)."""
    csrf = secrets.token_urlsafe(24)
    return _serializer().dumps({"a": admin_id, "c": csrf}), csrf


def read_session(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    try:
        return _serializer().loads(cookie, max_age=settings.session_hours * 3600)
    except (BadSignature, SignatureExpired):
        return None


def is_locked(admin: AdminUser) -> bool:
    return bool(admin.locked_until and _aware(admin.locked_until) > datetime.now(timezone.utc))


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def register_failure(db: Session, admin: AdminUser) -> None:
    admin.failed_logins += 1
    if admin.failed_logins >= settings.max_failed_logins:
        admin.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.lockout_minutes)
        admin.failed_logins = 0
    db.commit()


def current_admin(request: Request, db: Session = Depends(get_db)) -> AdminUser:
    data = read_session(request.cookies.get(COOKIE))
    if not data:
        raise HTTPException(401, "Sign in first.")
    admin = db.get(AdminUser, data["a"])
    if not admin or not admin.active:
        raise HTTPException(401, "Sign in first.")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent, data["c"]):
            raise HTTPException(403, "Missing or wrong CSRF token.")
    return admin


def scope_org(admin: AdminUser, org_id: str) -> None:
    """Org admins may only touch their own organisation; super admins (org_id None) may touch any."""
    if admin.org_id is not None and admin.org_id != org_id:
        raise HTTPException(403, "That belongs to another organisation.")
