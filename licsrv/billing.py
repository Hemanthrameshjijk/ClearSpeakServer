"""Payments. A gateway creates an order, the customer pays on the gateway's page, and we only trust the result after
checking the gateway's signature. Fulfilment is idempotent: the same payment can arrive by browser and by webhook."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import AdminUser, Org, Payment
from .service import aware, seats_used


class GatewayError(Exception):
    pass


class MockGateway:
    """Local testing only: the 'checkout' is our own page with a Pay button. Signatures use the session secret."""

    name = "mock"

    def create_order(self, amount_paise: int, currency: str, receipt: str) -> str:
        return "mock_order_" + secrets.token_hex(8)

    def _sig(self, order_id: str, payment_id: str) -> str:
        return hmac.new(settings.session_secret.encode(), f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()

    def sign(self, order_id: str, payment_id: str) -> str:
        return self._sig(order_id, payment_id)

    def verify_payment(self, order_id: str, payment_id: str, signature: str) -> bool:
        return hmac.compare_digest(self._sig(order_id, payment_id), signature)

    def verify_webhook(self, body: bytes, signature: str) -> bool:
        return False  # the mock has no webhook


class RazorpayGateway:
    name = "razorpay"

    def __init__(self) -> None:
        if not (settings.razorpay_key_id and settings.razorpay_key_secret):
            raise GatewayError("Razorpay keys are not set (LICSRV_RAZORPAY_KEY_ID / LICSRV_RAZORPAY_KEY_SECRET).")

    def create_order(self, amount_paise: int, currency: str, receipt: str) -> str:
        try:
            r = httpx.post("https://api.razorpay.com/v1/orders", auth=(settings.razorpay_key_id, settings.razorpay_key_secret), timeout=20,
                           json={"amount": amount_paise, "currency": currency, "receipt": receipt[:40]})
            r.raise_for_status()
            return r.json()["id"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise GatewayError("The payment provider did not accept the order. Try again in a moment.") from e

    def verify_payment(self, order_id: str, payment_id: str, signature: str) -> bool:
        want = hmac.new(settings.razorpay_key_secret.encode(), f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, signature)

    def verify_webhook(self, body: bytes, signature: str) -> bool:
        if not settings.razorpay_webhook_secret:
            return False
        want = hmac.new(settings.razorpay_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, signature)


def make_gateway():
    if settings.payment_provider == "razorpay":
        return RazorpayGateway()
    if settings.payment_provider == "mock":
        return MockGateway()
    raise GatewayError(f"Unknown payment provider {settings.payment_provider!r}.")


# ---- pricing --------------------------------------------------------------------------------------------------
def price_per_seat(org: Org) -> int:
    return org.seat_price_paise or settings.seat_price_paise


def quote(db: Session, org: Org, kind: str, seats: int, months: int) -> tuple[int, int, int]:
    """(amount in paise, seats to record, months to record). Raises HTTPException for a request that makes no sense."""
    per = price_per_seat(org)
    if kind == "renew":
        if not 1 <= seats <= settings.max_seats:
            raise HTTPException(422, f"Choose between 1 and {settings.max_seats} seats.")
        if not 1 <= months <= settings.max_months:
            raise HTTPException(422, f"Choose between 1 and {settings.max_months} months.")
        used = seats_used(db, org.id)
        if seats < used:
            raise HTTPException(409, f"{used} licenses are active. Revoke some first, or choose at least {used} seats.")
        return seats * months * per, seats, months
    if kind == "add_seats":
        until = aware(org.paid_until)
        now = datetime.now(timezone.utc)
        if not until or until <= now:
            raise HTTPException(409, "The subscription has ended. Renew it first.")
        if not 1 <= seats <= settings.max_seats - org.seats:
            raise HTTPException(422, "That many extra seats is not allowed.")
        days_left = max(1, math.ceil((until - now).total_seconds() / 86400))
        return math.ceil(seats * per * days_left / 30), seats, 0
    raise HTTPException(422, "Unknown purchase type.")


def start(db: Session, gateway, org: Org, admin: AdminUser, kind: str, seats: int, months: int) -> Payment:
    amount, seats, months = quote(db, org, kind, seats, months)
    if amount < 100:
        raise HTTPException(422, "The amount is too small to charge.")
    try:
        order_id = gateway.create_order(amount, settings.currency, f"{org.id[:8]}-{secrets.token_hex(4)}")
    except GatewayError as e:
        raise HTTPException(502, str(e)) from None
    p = Payment(org_id=org.id, kind=kind, seats=seats, months=months, amount_paise=amount, currency=settings.currency,
                provider=gateway.name, provider_order_id=order_id, created_by=admin.id)
    db.add(p)
    db.commit()
    return p


def fulfil(db: Session, payment_id: str, provider_payment_id: str) -> bool:
    """Mark a payment paid and grant what it bought. True the first time, False if it was already done."""
    p = db.scalar(select(Payment).where(Payment.id == payment_id).with_for_update())
    if p is None or p.status == "paid":
        return False
    org = db.scalar(select(Org).where(Org.id == p.org_id).with_for_update())
    now = datetime.now(timezone.utc)
    if p.kind == "renew":
        base = max(now, aware(org.paid_until) or now)
        org.paid_until = base + timedelta(days=30 * p.months)
        org.seats = p.seats
    else:
        org.seats += p.seats
    p.status, p.provider_payment_id, p.paid_at = "paid", provider_payment_id, now
    db.commit()
    return True


def confirm_from_browser(db: Session, gateway, order_id: str, payment_id: str, signature: str, org_id: str | None = None) -> Payment:
    """`org_id` = the organisation of the person confirming (None for staff): nobody can apply another organisation's payment."""
    p = db.scalar(select(Payment).where(Payment.provider_order_id == order_id))
    if p is not None and org_id is not None and p.org_id != org_id:
        raise HTTPException(403, "That payment belongs to another organisation.")
    if p is None or not gateway.verify_payment(order_id, payment_id, signature):
        raise HTTPException(400, "The payment could not be verified. If money was taken, it will be applied automatically within minutes.")
    fulfil(db, p.id, payment_id)
    return db.get(Payment, p.id)


def confirm_from_webhook(db: Session, gateway, body: bytes, signature: str) -> str:
    """Handles Razorpay's payment.captured / order.paid. Returns a short note for the log."""
    import json

    if not gateway.verify_webhook(body, signature):
        raise HTTPException(400, "Bad signature.")
    event = json.loads(body)
    if event.get("event") not in ("payment.captured", "order.paid"):
        return "ignored"
    pay = event.get("payload", {}).get("payment", {}).get("entity", {})
    p = db.scalar(select(Payment).where(Payment.provider_order_id == pay.get("order_id", "")))
    if p is None:
        return "unknown order"
    if pay.get("amount") != p.amount_paise or pay.get("currency") != p.currency:
        return "amount mismatch"
    return "applied" if fulfil(db, p.id, pay.get("id", "")) else "already applied"
