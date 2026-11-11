"""ClearNAI license server: admins create users and issue device-bound license tokens the app checks offline."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import billing, security, service, tokens
from .config import settings
from .db import Base, engine, get_db
from .keys import KeyProvider
from .models import AdminUser, AuditLog, License, Org, Payment, User, new_id


class LoginIn(BaseModel):
    email: str
    password: str
    totp: str = ""


class OrgIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    owner_name: str = ""
    owner_email: str = ""
    seats: int = 0
    days: int = 0
    features: list[str] = Field(default_factory=lambda: list(tokens.FEATURES))


class EntitlementsIn(BaseModel):
    seats: int
    days_from_now: int | None = None
    features: list[str]
    seat_price_paise: int | None = None


class AdminIn(BaseModel):
    name: str
    email: str


class OrderIn(BaseModel):
    kind: str = "renew"  # renew | add_seats
    seats: int
    months: int = 1


class VerifyIn(BaseModel):
    order_id: str
    payment_id: str
    signature: str


class UserIn(BaseModel):
    org_id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(default="", max_length=320)
    employee_id: str = Field(default="", max_length=100)


class IssueIn(BaseModel):
    user_id: str
    device_code: str
    features: list[str] = Field(default_factory=lambda: list(tokens.FEATURES))
    days: int = 90


class RenewIn(BaseModel):
    days: int = 90


class ChangeIn(BaseModel):
    features: list[str]
    days: int = 90


class ReplaceIn(BaseModel):
    device_code: str


class RevokeIn(BaseModel):
    reason: str = Field(default="", max_length=300)


def audit(db: Session, request: Request, admin: AdminUser | None, action: str, target_type: str = "", target_id: str = "", **detail) -> None:
    db.add(AuditLog(admin_id=admin.id if admin else None, org_id=admin.org_id if admin else None, action=action, target_type=target_type, target_id=target_id, detail=detail,
                    ip=request.client.host if request.client else ""))
    db.commit()


def _license_out(lic: License, with_token: bool = False) -> dict:
    out = {
        "id": lic.id, "org_id": lic.org_id, "user_id": lic.user_id, "device_code": lic.device_code, "features": lic.features,
        "issued_at": lic.issued_at.isoformat(), "expires_at": lic.expires_at.isoformat(), "status": lic.status,
        "replaced_by": lic.replaced_by, "revoked_reason": lic.revoked_reason,
    }
    if with_token:
        out["token"] = lic.token
    return out


def create_app(keys: KeyProvider, create_tables: bool = False, gateway=None) -> FastAPI:
    app = FastAPI(title="ClearNAI license server", docs_url=None, redoc_url=None)
    app.state.keys = keys
    app.state.gateway = gateway
    if create_tables:
        Base.metadata.create_all(engine)

    def get_gateway():
        if app.state.gateway is None:
            try:
                app.state.gateway = billing.make_gateway()
            except billing.GatewayError as e:
                raise HTTPException(503, str(e)) from None
        return app.state.gateway

    def _issue(db: Session, request: Request, admin: AdminUser, user: User, device_code: str, features: list[str], days: int,
               replacing: License | None = None) -> License:
        if not (settings.min_days <= days <= settings.max_days):
            raise HTTPException(422, f"days must be between {settings.min_days} and {settings.max_days}.")
        feats = sorted(set(features))
        if not feats or any(f not in tokens.FEATURES for f in feats):
            raise HTTPException(422, f"features must be a non-empty subset of {list(tokens.FEATURES)}.")
        if not user.active:
            raise HTTPException(409, "That user is switched off.")
        days = service.check_can_issue(db, db.get(Org, user.org_id), feats, days, replacing)
        try:
            devs = tokens.parse_device_code(device_code)
        except tokens.DeviceCodeError as e:
            raise HTTPException(422, str(e)) from None
        now = int(time.time())
        lid = new_id()
        org = db.get(Org, user.org_id)
        payload = tokens.Payload(lid=lid, org=user.org_id, uid=user.id, name=user.name, dev=devs, feat=feats, iat=now, exp=now + days * 86400,
                                 email=user.email or "", orgname=org.name if org else "")
        token = tokens.build_token(payload, app.state.keys.sign)
        lic = License(id=lid, org_id=user.org_id, user_id=user.id, device_code=_group("".join(devs)),
                      devices=devs, features=feats, issued_at=datetime.fromtimestamp(now, timezone.utc),
                      expires_at=datetime.fromtimestamp(now + days * 86400, timezone.utc), issued_by=admin.id, token=token)
        db.add(lic)
        db.commit()
        return lic

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/v1/public-key")
    def public_key():
        pk = app.state.keys.public_key()
        return {"hex": pk.hex(), "b64url": tokens.b64e(pk)}

    # ---- auth ---------------------------------------------------------------------------------------------
    @app.post("/v1/auth/login")
    def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
        generic = HTTPException(401, "Wrong email, password or code.")
        admin = db.scalar(select(AdminUser).where(AdminUser.email == body.email.strip().lower()))
        if not admin or not admin.active:
            security.check_password(security.hash_password("x" * 16), body.password)  # keep the timing alike
            audit(db, request, None, "login_failed", detail={"email": body.email[:100]})
            raise generic
        if security.is_locked(admin):
            audit(db, request, admin, "login_locked")
            raise HTTPException(429, "Too many wrong attempts. Try again later.")
        if not security.credentials_ok(admin, body.password, body.totp):
            security.register_failure(db, admin)
            audit(db, request, admin, "login_failed")
            raise generic
        admin.failed_logins = 0
        db.commit()
        cookie, csrf = security.make_session(admin.id)
        response.set_cookie(security.COOKIE, cookie, httponly=True, samesite="strict", secure=settings.cookie_secure,
                            max_age=settings.session_hours * 3600)
        audit(db, request, admin, "login")
        return {"csrf": csrf, "email": admin.email, "org_id": admin.org_id, "role": admin.role if admin.org_id else "super",
                "must_change_password": admin.must_change_password}

    @app.post("/v1/auth/logout")
    def logout(response: Response, admin: AdminUser = Depends(security.current_admin)):
        response.delete_cookie(security.COOKIE)
        return {"ok": True}

    # ---- orgs & users -------------------------------------------------------------------------------------
    @app.post("/v1/orgs", status_code=201)
    def create_org(body: OrgIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        if admin.org_id is not None:
            raise HTTPException(403, "Only a super admin can create organisations.")
        if body.owner_email:
            org, owner, temp = service.create_org_with_owner(db, body.name, body.owner_name, body.owner_email, body.seats, body.days, body.features)
            audit(db, request, admin, "org_create", "org", org.id, owner=owner.email, seats=body.seats, days=body.days)
            return {"id": org.id, "name": org.name, "owner_id": owner.id, "owner_email": owner.email, "temporary_password": temp}
        if db.scalar(select(Org).where(Org.name == body.name.strip())):
            raise HTTPException(409, "An organisation with that name exists.")
        org = Org(name=body.name.strip(), features=list(tokens.FEATURES))
        db.add(org)
        db.commit()
        audit(db, request, admin, "org_create", "org", org.id)
        return {"id": org.id, "name": org.name}

    def _org_out(db: Session, o: Org) -> dict:
        st = service.org_state(db, o)
        return {"id": o.id, "name": o.name, "status": o.status, "seats": st["seats"], "seats_used": st["used"],
                "paid_until": st["paid_until"].isoformat() if st["paid_until"] else None, "features": o.features, "valid": st["valid"]}

    @app.put("/v1/orgs/{org_id}/entitlements")
    def set_entitlements(org_id: str, body: EntitlementsIn, request: Request, admin: AdminUser = Depends(security.current_admin),
                         db: Session = Depends(get_db)):
        if admin.org_id is not None:
            raise HTTPException(403, "Only a super admin can set what an organisation has.")
        org = db.get(Org, org_id)
        if not org:
            raise HTTPException(404, "No such organisation.")
        service.set_entitlements(org, body.seats, body.days_from_now, body.features, body.seat_price_paise)
        db.commit()
        audit(db, request, admin, "org_entitlements", "org", org.id, seats=body.seats, days=body.days_from_now, features=org.features)
        return _org_out(db, org)

    @app.post("/v1/orgs/{org_id}/admins", status_code=201)
    def add_admin(org_id: str, body: AdminIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        org = db.get(Org, org_id)
        if not org:
            raise HTTPException(404, "No such organisation.")
        security.scope_org(admin, org_id)
        service.require_owner(admin)
        a, temp = service.create_org_admin(db, org, body.name, body.email)
        audit(db, request, admin, "admin_create", "admin", a.id, email=a.email)
        return {"id": a.id, "email": a.email, "temporary_password": temp}

    @app.get("/v1/me")
    def me(admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        out = {"email": admin.email, "name": admin.name, "role": admin.role if admin.org_id else "super", "totp_enabled": admin.totp_enabled}
        if admin.org_id:
            out["org"] = _org_out(db, db.get(Org, admin.org_id))
        return out

    # ---- billing ------------------------------------------------------------------------------------------
    @app.post("/v1/billing/orders", status_code=201)
    def create_order(body: OrderIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        if admin.org_id is None:
            raise HTTPException(403, "Sign in as an organisation owner to buy.")
        service.require_owner(admin)
        org = db.get(Org, admin.org_id)
        p = billing.start(db, get_gateway(), org, admin, body.kind, body.seats, body.months)
        audit(db, request, admin, "payment_start", "payment", p.id, amount=p.amount_paise, kind=p.kind)
        return {"payment_id": p.id, "order_id": p.provider_order_id, "amount_paise": p.amount_paise, "currency": p.currency, "provider": p.provider}

    @app.post("/v1/billing/verify")
    def verify_payment(body: VerifyIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        p = billing.confirm_from_browser(db, get_gateway(), body.order_id, body.payment_id, body.signature, admin.org_id)
        audit(db, request, admin, "payment_paid", "payment", p.id)
        return {"status": p.status, "org": _org_out(db, db.get(Org, p.org_id))}

    @app.post("/v1/webhooks/razorpay")
    async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
        note = billing.confirm_from_webhook(db, get_gateway(), await request.body(), request.headers.get("x-razorpay-signature", ""))
        audit(db, request, None, "payment_webhook", note=note)
        return {"ok": True, "note": note}

    @app.get("/v1/orgs")
    def list_orgs(admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        q = select(Org) if admin.org_id is None else select(Org).where(Org.id == admin.org_id)
        return [{"id": o.id, "name": o.name} for o in db.scalars(q.order_by(Org.name))]

    @app.post("/v1/users", status_code=201)
    def create_user(body: UserIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        org_id = admin.org_id or body.org_id
        if not org_id or not db.get(Org, org_id):
            raise HTTPException(422, "Choose an organisation.")
        security.scope_org(admin, org_id)
        user = User(org_id=org_id, name=body.name.strip(), email=body.email.strip().lower(), employee_id=body.employee_id.strip())
        db.add(user)
        db.commit()
        audit(db, request, admin, "user_create", "user", user.id)
        return {"id": user.id, "org_id": user.org_id, "name": user.name, "email": user.email, "employee_id": user.employee_id, "active": user.active}

    @app.get("/v1/users")
    def list_users(admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        q = select(User) if admin.org_id is None else select(User).where(User.org_id == admin.org_id)
        return [{"id": u.id, "org_id": u.org_id, "name": u.name, "email": u.email, "employee_id": u.employee_id, "active": u.active}
                for u in db.scalars(q.order_by(User.name))]

    @app.post("/v1/users/{user_id}/deactivate")
    def deactivate_user(user_id: str, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(404, "No such user.")
        security.scope_org(admin, user.org_id)
        user.active = False
        revoked = 0
        for lic in db.scalars(select(License).where(License.user_id == user.id, License.status == "active")):
            lic.status, lic.revoked_reason = "revoked", "user switched off"
            revoked += 1
        db.commit()
        audit(db, request, admin, "user_deactivate", "user", user.id, revoked_licenses=revoked)
        return {"ok": True, "revoked_licenses": revoked}

    # ---- licenses -----------------------------------------------------------------------------------------
    @app.post("/v1/licenses", status_code=201)
    def issue(body: IssueIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        user = db.get(User, body.user_id)
        if not user:
            raise HTTPException(404, "No such user.")
        security.scope_org(admin, user.org_id)
        lic = _issue(db, request, admin, user, body.device_code, body.features, body.days)
        audit(db, request, admin, "license_issue", "license", lic.id, user_id=user.id, days=body.days, features=lic.features)
        return _license_out(lic, with_token=True)

    @app.get("/v1/licenses")
    def list_licenses(user_id: str | None = None, status: str | None = None, expiring_within_days: int | None = None,
                      admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        q = select(License)
        if admin.org_id is not None:
            q = q.where(License.org_id == admin.org_id)
        if user_id:
            q = q.where(License.user_id == user_id)
        if status:
            q = q.where(License.status == status)
        if expiring_within_days is not None:
            q = q.where(License.expires_at <= datetime.now(timezone.utc) + timedelta(days=expiring_within_days), License.status == "active")
        return [_license_out(lic) for lic in db.scalars(q.order_by(License.expires_at))]

    def _get_license(db: Session, admin: AdminUser, license_id: str) -> License:
        lic = db.get(License, license_id)
        if not lic:
            raise HTTPException(404, "No such license.")
        security.scope_org(admin, lic.org_id)
        return lic

    @app.get("/v1/licenses/{license_id}")
    def get_license(license_id: str, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        return _license_out(_get_license(db, admin, license_id), with_token=True)

    @app.get("/v1/licenses/{license_id}/file", response_class=PlainTextResponse)
    def license_file(license_id: str, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        lic = _get_license(db, admin, license_id)
        audit(db, request, admin, "license_download", "license", lic.id)
        return PlainTextResponse(lic.token + "\n", headers={"Content-Disposition": f'attachment; filename="clearnai-{lic.id[:8]}.lic"'})

    def _supersede(db, request, admin, old: License, device_code: str, days: int, action: str, features: list[str] | None = None) -> License:
        if old.status != "active":
            raise HTTPException(409, f"That license is {old.status}.")
        user = db.get(User, old.user_id)
        new = _issue(db, request, admin, user, device_code, features if features is not None else old.features, days, replacing=old)
        old.status, old.replaced_by = "replaced", new.id
        db.commit()
        audit(db, request, admin, action, "license", new.id, replaces=old.id, days=days)
        return new

    @app.post("/v1/licenses/{license_id}/renew", status_code=201)
    def renew(license_id: str, body: RenewIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        old = _get_license(db, admin, license_id)
        return _license_out(_supersede(db, request, admin, old, old.device_code, body.days, "license_renew"), with_token=True)

    @app.post("/v1/licenses/{license_id}/change", status_code=201)
    def change(license_id: str, body: ChangeIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        """Same PC, new features and/or days: a new license replaces the old one; the person pastes it into ClearNAI."""
        old = _get_license(db, admin, license_id)
        return _license_out(_supersede(db, request, admin, old, old.device_code, body.days, "license_change", body.features), with_token=True)

    @app.post("/v1/licenses/{license_id}/replace-device", status_code=201)
    def replace_device(license_id: str, body: ReplaceIn, request: Request, admin: AdminUser = Depends(security.current_admin),
                       db: Session = Depends(get_db)):
        old = _get_license(db, admin, license_id)
        remaining = max(1, int((_aware(old.expires_at) - datetime.now(timezone.utc)).total_seconds() // 86400))
        return _license_out(_supersede(db, request, admin, old, body.device_code, remaining, "license_replace_device"), with_token=True)

    @app.post("/v1/licenses/{license_id}/revoke")
    def revoke(license_id: str, body: RevokeIn, request: Request, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        lic = _get_license(db, admin, license_id)
        if lic.status != "active":
            raise HTTPException(409, f"That license is {lic.status}.")
        lic.status, lic.revoked_reason = "revoked", body.reason
        db.commit()
        audit(db, request, admin, "license_revoke", "license", lic.id, reason=body.reason)
        return _license_out(lic)

    @app.get("/v1/audit")
    def audit_list(limit: int = 200, admin: AdminUser = Depends(security.current_admin), db: Session = Depends(get_db)):
        if admin.org_id is not None:
            raise HTTPException(403, "Only a super admin can read the audit log.")
        rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(max(limit, 1), 1000)))
        return [{"id": r.id, "ts": r.ts.isoformat(), "admin_id": r.admin_id, "action": r.action, "target_type": r.target_type,
                 "target_id": r.target_id, "detail": r.detail, "ip": r.ip} for r in rows]

    from .web import register

    register(app, _issue, _supersede, get_gateway)
    return app


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _group(flat: str) -> str:
    return "-".join(flat[i : i + 4] for i in range(0, len(flat), 4))
