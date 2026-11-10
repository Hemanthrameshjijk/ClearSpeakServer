"""Business rules shared by the JSON API and the web pages: organisations, their people, seats and validity."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import security, tokens
from .config import settings
from .models import AdminUser, License, Org

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def new_temp_password() -> str:
    """A one-time password the owner/admin must change at the first sign-in."""
    return secrets.token_urlsafe(12)


def seats_used(db: Session, org_id: str) -> int:
    return db.scalar(select(func.count()).select_from(License).where(License.org_id == org_id, License.status == "active")) or 0


def org_state(db: Session, org: Org) -> dict:
    """What the dashboard and the billing page show."""
    until = aware(org.paid_until)
    now = datetime.now(timezone.utc)
    return {
        "seats": org.seats, "used": seats_used(db, org.id), "paid_until": until,
        "valid": bool(org.status == "active" and until and until > now),
        "days_left": max(0, (until - now).days) if until else 0,
        "price_paise": org.seat_price_paise or settings.seat_price_paise,
    }


def _clean_features(features: list[str]) -> list[str]:
    feats = sorted(set(features))
    if any(f not in tokens.FEATURES for f in feats):
        raise HTTPException(422, f"features must be a subset of {list(tokens.FEATURES)}.")
    return feats


def create_org_with_owner(db: Session, name: str, owner_name: str, owner_email: str, seats: int, days: int,
                          features: list[str]) -> tuple[Org, AdminUser, str]:
    name, owner_email = name.strip(), owner_email.strip().lower()
    if len(name) < 2:
        raise HTTPException(422, "Enter an organisation name of at least 2 letters.")
    if not EMAIL.match(owner_email):
        raise HTTPException(422, "Enter the owner's email address.")
    if not owner_name.strip():
        raise HTTPException(422, "Enter the owner's name.")
    if not 0 <= seats <= settings.max_seats or not 0 <= days <= 3650:
        raise HTTPException(422, "Seats or days are out of range.")
    if db.scalar(select(Org).where(Org.name == name)):
        raise HTTPException(409, "An organisation with that name exists.")
    if db.scalar(select(AdminUser).where(AdminUser.email == owner_email)):
        raise HTTPException(409, "That email already has a sign-in.")
    org = Org(name=name, seats=seats, paid_until=datetime.now(timezone.utc) + timedelta(days=days) if days else None,
              features=_clean_features(features) or list(tokens.FEATURES))
    db.add(org)
    db.flush()
    owner, temp = _new_admin(db, org.id, owner_name, owner_email, "owner")
    db.commit()
    return org, owner, temp


def _new_admin(db: Session, org_id: str, name: str, email: str, role: str) -> tuple[AdminUser, str]:
    temp = new_temp_password()
    a = AdminUser(org_id=org_id, name=name.strip(), email=email, role=role, password_hash=security.hash_password(temp),
                  totp_secret=security.new_totp_secret(), totp_enabled=False, must_change_password=True)
    db.add(a)
    db.flush()
    return a, temp


def create_org_admin(db: Session, org: Org, name: str, email: str) -> tuple[AdminUser, str]:
    email = email.strip().lower()
    if not EMAIL.match(email) or not name.strip():
        raise HTTPException(422, "Enter a name and an email address.")
    if db.scalar(select(AdminUser).where(AdminUser.email == email)):
        raise HTTPException(409, "That email already has a sign-in.")
    a, temp = _new_admin(db, org.id, name, email, "admin")
    db.commit()
    return a, temp


def reset_password(db: Session, target: AdminUser) -> str:
    temp = new_temp_password()
    target.password_hash = security.hash_password(temp)
    target.must_change_password = True
    target.failed_logins, target.locked_until = 0, None
    db.commit()
    return temp


def set_entitlements(org: Org, seats: int, days_from_now: int | None, features: list[str], price_paise: int | None) -> None:
    if not 0 <= seats <= settings.max_seats:
        raise HTTPException(422, "Seats are out of range.")
    org.seats = seats
    if days_from_now is not None:
        if not 0 <= days_from_now <= 3650:
            raise HTTPException(422, "Days are out of range.")
        org.paid_until = datetime.now(timezone.utc) + timedelta(days=days_from_now)
    feats = _clean_features(features)
    if not feats:
        raise HTTPException(422, "Allow at least one feature.")
    org.features = feats
    org.seat_price_paise = price_paise if price_paise and price_paise > 0 else None


def check_can_issue(db: Session, org: Org, features: list[str], days: int, replacing: License | None = None) -> int:
    """Raises if the organisation may not get another license; returns the days to put in the token (capped to what is paid)."""
    if org.status != "active":
        raise HTTPException(403, "This organisation is switched off. Contact ClearNAI.")
    until = aware(org.paid_until)
    now = datetime.now(timezone.utc)
    if not until or until <= now:
        raise HTTPException(402, "The subscription has ended. Renew it on the Billing page.")
    allowed = set(org.features or tokens.FEATURES)
    bad = sorted(set(features) - allowed)
    if bad:
        raise HTTPException(403, f"Your plan does not include: {', '.join(bad)}.")
    used = seats_used(db, org.id) - (1 if replacing is not None and replacing.status == "active" else 0)
    if used >= org.seats:
        raise HTTPException(402, f"All {org.seats} seats are in use. Add seats on the Billing page or revoke a license.")
    return max(1, min(days, int((until - now).total_seconds() // 86400)))


def require_owner(admin: AdminUser) -> None:
    if admin.org_id is not None and admin.role != "owner":
        raise HTTPException(403, "Only the organisation owner can do that.")
