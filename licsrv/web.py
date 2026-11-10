"""Web pages (server-rendered). They use the same session cookie and business rules as the JSON API; every form carries the
session's CSRF token in a hidden field.

Who sees what:  super admin (ClearNAI staff) = organisations, plans, everything;  owner = own organisation, billing, team;
admin = own organisation's users and licenses."""

from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import segno
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from . import billing, security, service, tokens
from .config import settings
from .db import SessionLocal
from .models import AdminUser, AuditLog, License, Org, Payment, User

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["rupees"] = lambda paise: f"₹{paise / 100:,.2f}"
templates.env.filters["day"] = lambda d: d.strftime("%d %b %Y") if d else "-"


def register(app: FastAPI, issue, supersede, get_gateway) -> None:
    """`issue(db, request, admin, user, device_code, features, days)` and
    `supersede(db, request, admin, old, device_code, days, action)` are the functions the JSON API uses."""

    def session(request: Request):
        """(db, admin, csrf) for a signed-in browser, or None. The caller closes db."""
        data = security.read_session(request.cookies.get(security.COOKIE))
        if not data:
            return None
        db = SessionLocal()
        admin = db.get(AdminUser, data["a"])
        if not admin or not admin.active:
            db.close()
            return None
        return db, admin, data["c"]

    def page(request: Request, name: str, ctx: dict, status: int = 200):
        db, admin, csrf = ctx.pop("_s")
        try:
            org = db.get(Org, admin.org_id) if admin.org_id else None
            base = {"admin": admin, "csrf": csrf, "is_super": admin.org_id is None, "is_owner": admin.org_id is not None and admin.role == "owner",
                    "my_org": org, "st": service.org_state(db, org) if org else None}
            return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status)
        finally:
            db.close()

    def need(request: Request, csrf_field: str | None = None, allow_change: bool = False):
        """Signed-in session, and for form posts the matching CSRF token; else None (caller redirects to /login)."""
        s = session(request)
        if s is None:
            return None
        if csrf_field is not None and not hmac.compare_digest(csrf_field, s[2]):
            s[0].close()
            raise HTTPException(403, "Missing or wrong CSRF token.")
        return s

    def go(path: str, msg: str = "", **q):
        qs = "&".join(f"{k}={quote(str(v))}" for k, v in q.items() if v != "")
        if msg:
            qs = f"msg={quote(msg)}" + ("&" + qs if qs else "")
        return RedirectResponse(path + ("?" + qs if qs else ""), status_code=303)

    def login_redirect():
        return RedirectResponse("/login", status_code=303)

    def gate(s):
        """After sign-in: a person with a temporary password may only change it."""
        if s[1].must_change_password:
            s[0].close()
            return RedirectResponse("/password", status_code=303)
        return None

    def audit(db, request, admin, action, target_type="", target_id="", org_id=None, **detail):
        db.add(AuditLog(admin_id=admin.id if admin else None, org_id=org_id or (admin.org_id if admin else None), action=action,
                        target_type=target_type, target_id=target_id, detail=detail, ip=request.client.host if request.client else ""))
        db.commit()

    def scoped(q, admin, col):
        return q if admin.org_id is None else q.where(col == admin.org_id)

    def deny(db, text):
        db.close()
        raise HTTPException(403, text)

    # ---- sign in ------------------------------------------------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, msg: str = ""):
        return templates.TemplateResponse(request, "login.html", {"error": "", "msg": msg})

    @app.post("/login")
    def login_submit(request: Request, email: str = Form(...), password: str = Form(...), totp: str = Form("")):
        db = SessionLocal()
        try:
            admin = db.scalar(select(AdminUser).where(AdminUser.email == email.strip().lower()))

            def fail(text="Wrong email, password or code.", code=401):
                return templates.TemplateResponse(request, "login.html", {"error": text, "msg": ""}, status_code=code)

            if not admin or not admin.active:
                return fail()
            if security.is_locked(admin):
                return fail("Too many wrong attempts. Try again later.", 429)
            if not security.credentials_ok(admin, password, totp):
                security.register_failure(db, admin)
                audit(db, request, admin, "login_failed")
                return fail()
            if admin.org_id and db.get(Org, admin.org_id).status != "active":
                return fail("This organisation is switched off. Contact ClearNAI.", 403)
            admin.failed_logins = 0
            db.commit()
            cookie, _ = security.make_session(admin.id)
            resp = RedirectResponse("/password" if admin.must_change_password else "/", status_code=303)
            resp.set_cookie(security.COOKIE, cookie, httponly=True, samesite="strict", secure=settings.cookie_secure, max_age=settings.session_hours * 3600)
            audit(db, request, admin, "login")
            return resp
        finally:
            db.close()

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        s = need(request, csrf)
        if s:
            s[0].close()
        resp = login_redirect()
        resp.delete_cookie(security.COOKIE)
        return resp

    @app.get("/password", response_class=HTMLResponse)
    def password_form(request: Request, msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        return page(request, "password.html", {"_s": s, "msg": msg, "error": error, "forced": s[1].must_change_password})

    @app.post("/password")
    def password_change(request: Request, csrf: str = Form(""), current: str = Form(...), new: str = Form(...), again: str = Form(...)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            if not security.check_password(admin.password_hash, current):
                return go("/password", error="The current password is wrong.")
            if new != again:
                return go("/password", error="The two new passwords differ.")
            if len(new) < 12:
                return go("/password", error="Use at least 12 characters.")
            if new == current:
                return go("/password", error="Choose a password you have not used before.")
            admin.password_hash = security.hash_password(new)
            admin.must_change_password = False
            db.commit()
            audit(db, request, admin, "password_change")
            return go("/", "Password changed.")
        finally:
            db.close()

    # ---- two-step sign-in (optional) --------------------------------------------------------------------
    @app.get("/security", response_class=HTMLResponse)
    def security_page(request: Request, msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        admin = s[1]
        qr = ""
        uri = f"otpauth://totp/ClearNAI:{admin.email}?secret={admin.totp_secret}&issuer=ClearNAI"
        if not admin.totp_enabled:
            qr = segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#1c2233", light="#ffffff")
        return page(request, "security.html", {"_s": s, "msg": msg, "error": error, "qr": qr, "uri": uri})

    @app.post("/security/2fa/enable")
    def twofa_enable(request: Request, csrf: str = Form(""), code: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            if not security.check_totp(admin.totp_secret, code):
                return go("/security", error="That code is not right. Check the clock on your phone and try the next code.")
            admin.totp_enabled = True
            db.commit()
            audit(db, request, admin, "2fa_enable")
            return go("/security", "Two-step sign-in is on.")
        finally:
            db.close()

    @app.post("/security/2fa/disable")
    def twofa_disable(request: Request, csrf: str = Form(""), password: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            if admin.org_id is None:
                return go("/security", error="Super admins must keep two-step sign-in on.")
            if not security.check_password(admin.password_hash, password):
                return go("/security", error="Wrong password.")
            admin.totp_enabled = False
            admin.totp_secret = security.new_totp_secret()
            db.commit()
            audit(db, request, admin, "2fa_disable")
            return go("/security", "Two-step sign-in is off.")
        finally:
            db.close()

    # ---- dashboard ----------------------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, msg: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        db, admin, _ = s
        now = datetime.now(timezone.utc)
        users = db.scalar(scoped(select(func.count()).select_from(User).where(User.active.is_(True)), admin, User.org_id))
        active = db.scalar(scoped(select(func.count()).select_from(License).where(License.status == "active"), admin, License.org_id))
        soon = db.scalars(scoped(select(License).where(License.status == "active", License.expires_at <= now + timedelta(days=30)), admin, License.org_id)
                          .order_by(License.expires_at)).all()
        names = {u.id: u.name for u in db.scalars(scoped(select(User), admin, User.org_id))}
        platform = None
        if admin.org_id is None:
            platform = {
                "orgs": db.scalar(select(func.count()).select_from(Org)),
                "paid_orgs": db.scalar(select(func.count()).select_from(Org).where(Org.paid_until > now)),
                "revenue": db.scalar(select(func.coalesce(func.sum(Payment.amount_paise), 0)).where(Payment.status == "paid")),
            }
        return page(request, "dashboard.html", {"_s": s, "active": active, "users": users, "soon": soon, "names": names, "platform": platform, "msg": msg})

    # ---- organisations (super admin) ----------------------------------------------------------------------
    def only_super(s):
        if s[1].org_id is not None:
            deny(s[0], "Only ClearNAI staff can manage organisations.")

    @app.get("/orgs", response_class=HTMLResponse)
    def orgs_page(request: Request, msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        only_super(s)
        db = s[0]
        rows = db.scalars(select(Org).order_by(Org.name)).all()
        info = {o.id: service.org_state(db, o) for o in rows}
        owners = {o.id: db.scalar(select(AdminUser).where(AdminUser.org_id == o.id, AdminUser.role == "owner")) for o in rows}
        return page(request, "orgs.html", {"_s": s, "orgs": rows, "info": info, "owners": owners, "msg": msg, "error": error, "features": tokens.FEATURES})

    @app.post("/orgs", response_class=HTMLResponse)
    def orgs_create(request: Request, csrf: str = Form(""), name: str = Form(...), owner_name: str = Form(...), owner_email: str = Form(...),
                    seats: int = Form(0), days: int = Form(0), features: list[str] = Form(default=[])):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        only_super(s)
        db, admin, _ = s
        try:
            org, owner, temp = service.create_org_with_owner(db, name, owner_name, owner_email, seats, days, features)
        except HTTPException as e:
            db.close()
            return go("/orgs", error=str(e.detail))
        audit(db, request, admin, "org_create", "org", org.id, org_id=org.id, owner=owner.email, seats=seats, days=days)
        return page(request, "credentials.html", {"_s": s, "who": owner, "org": org, "temp": temp, "back": "/orgs", "login_url": settings.public_url + "/login"})

    @app.get("/orgs/{org_id}", response_class=HTMLResponse)
    def org_page(org_id: str, request: Request, msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        only_super(s)
        db = s[0]
        org = db.get(Org, org_id)
        if not org:
            deny(db, "No such organisation.")
        team = db.scalars(select(AdminUser).where(AdminUser.org_id == org.id).order_by(AdminUser.role.desc(), AdminUser.email)).all()
        pays = db.scalars(select(Payment).where(Payment.org_id == org.id).order_by(Payment.created_at.desc()).limit(50)).all()
        return page(request, "org.html", {"_s": s, "org": org, "o_st": service.org_state(db, org), "team": team, "pays": pays, "features": tokens.FEATURES,
                                          "msg": msg, "error": error})

    @app.post("/orgs/{org_id}/entitlements")
    def org_entitlements(org_id: str, request: Request, csrf: str = Form(""), seats: int = Form(...), days_from_now: str = Form(""),
                         features: list[str] = Form(default=[]), price_rupees: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        only_super(s)
        db, admin, _ = s
        try:
            org = db.get(Org, org_id)
            if not org:
                raise HTTPException(404, "No such organisation.")
            price = int(round(float(price_rupees) * 100)) if price_rupees.strip() else None
            service.set_entitlements(org, seats, int(days_from_now) if days_from_now.strip() else None, features, price)
            db.commit()
            audit(db, request, admin, "org_entitlements", "org", org.id, org_id=org.id, seats=seats, features=org.features)
            return go(f"/orgs/{org_id}", "Saved.")
        except (HTTPException, ValueError) as e:
            return go(f"/orgs/{org_id}", error=str(getattr(e, "detail", "Check the numbers.")))
        finally:
            db.close()

    @app.post("/orgs/{org_id}/status")
    def org_status(org_id: str, request: Request, csrf: str = Form(""), status: str = Form(...)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        only_super(s)
        db, admin, _ = s
        try:
            org = db.get(Org, org_id)
            if not org or status not in ("active", "suspended"):
                raise HTTPException(404, "No such organisation.")
            org.status = status
            db.commit()
            audit(db, request, admin, "org_status", "org", org.id, org_id=org.id, status=status)
            return go(f"/orgs/{org_id}", "Switched on." if status == "active" else "Switched off.")
        finally:
            db.close()

    # ---- team (owner / super) -----------------------------------------------------------------------------
    def team_org(s, org_id: str):
        db, admin, _ = s
        oid = admin.org_id or org_id
        org = db.get(Org, oid) if oid else None
        if not org:
            deny(db, "Choose an organisation.")
        security.scope_org(admin, org.id)
        if admin.org_id is not None and admin.role != "owner":
            deny(db, "Only the organisation owner can manage the team.")
        return org

    @app.get("/team", response_class=HTMLResponse)
    def team_page(request: Request, org_id: str = "", msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        org = team_org(s, org_id)
        rows = s[0].scalars(select(AdminUser).where(AdminUser.org_id == org.id).order_by(AdminUser.role.desc(), AdminUser.email)).all()
        return page(request, "team.html", {"_s": s, "org": org, "team": rows, "msg": msg, "error": error})

    @app.post("/team", response_class=HTMLResponse)
    def team_add(request: Request, csrf: str = Form(""), org_id: str = Form(""), name: str = Form(...), email: str = Form(...)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        org = team_org(s, org_id)
        db, admin, _ = s
        try:
            a, temp = service.create_org_admin(db, org, name, email)
        except HTTPException as e:
            db.close()
            return go("/team", error=str(e.detail), org_id=org_id)
        audit(db, request, admin, "admin_create", "admin", a.id, org_id=org.id, email=a.email)
        return page(request, "credentials.html", {"_s": s, "who": a, "org": org, "temp": temp, "back": "/team" + (f"?org_id={org.id}" if admin.org_id is None else ""),
                                                  "login_url": settings.public_url + "/login"})

    def team_target(s, admin_id: str) -> AdminUser:
        db, admin, _ = s
        target = db.get(AdminUser, admin_id)
        if not target or target.org_id is None:
            deny(db, "No such person.")
        security.scope_org(admin, target.org_id)
        if admin.org_id is not None and admin.role != "owner":
            deny(db, "Only the organisation owner can manage the team.")
        return target

    @app.post("/team/{admin_id}/reset", response_class=HTMLResponse)
    def team_reset(admin_id: str, request: Request, csrf: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        target = team_target(s, admin_id)
        db, admin, _ = s
        if target.id == admin.id:
            return go("/password", error="Change your own password here.")
        temp = service.reset_password(db, target)
        audit(db, request, admin, "admin_password_reset", "admin", target.id, org_id=target.org_id)
        return page(request, "credentials.html", {"_s": s, "who": target, "org": db.get(Org, target.org_id), "temp": temp, "back": "/team",
                                                  "login_url": settings.public_url + "/login"})

    @app.post("/team/{admin_id}/toggle")
    def team_toggle(admin_id: str, request: Request, csrf: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        target = team_target(s, admin_id)
        db, admin, _ = s
        try:
            if target.id == admin.id or target.role == "owner":
                return go("/team", error="The owner cannot be switched off here.", org_id=target.org_id if admin.org_id is None else "")
            target.active = not target.active
            db.commit()
            audit(db, request, admin, "admin_toggle", "admin", target.id, org_id=target.org_id, active=target.active)
            return go("/team", "Updated.", org_id=target.org_id if admin.org_id is None else "")
        finally:
            db.close()

    # ---- billing (owner) ----------------------------------------------------------------------------------
    def owner_only(s):
        if s[1].org_id is None or s[1].role != "owner":
            deny(s[0], "Billing is for the organisation owner.")

    @app.get("/billing", response_class=HTMLResponse)
    def billing_page(request: Request, msg: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        owner_only(s)
        db, admin, _ = s
        pays = db.scalars(select(Payment).where(Payment.org_id == admin.org_id).order_by(Payment.created_at.desc()).limit(50)).all()
        return page(request, "billing.html", {"_s": s, "pays": pays, "msg": msg, "error": error, "months_max": settings.max_months,
                                              "mock": settings.payment_provider == "mock"})

    @app.post("/billing/checkout", response_class=HTMLResponse)
    def billing_checkout(request: Request, csrf: str = Form(""), kind: str = Form("renew"), seats: int = Form(...), months: int = Form(1)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        owner_only(s)
        db, admin, _ = s
        try:
            gw = get_gateway()
            p = billing.start(db, gw, db.get(Org, admin.org_id), admin, kind, seats, months)
        except HTTPException as e:
            db.close()
            return go("/billing", error=str(e.detail))
        audit(db, request, admin, "payment_start", "payment", p.id, amount=p.amount_paise, kind=p.kind)
        extra = {}
        if gw.name == "mock":
            pid = "mock_pay_" + p.id[:8]
            extra = {"mock_payment_id": pid, "mock_signature": gw.sign(p.provider_order_id, pid)}
        return page(request, "checkout.html", {"_s": s, "p": p, "key_id": settings.razorpay_key_id, "provider": gw.name, **extra})

    @app.post("/billing/verify")
    def billing_verify(request: Request, csrf: str = Form(""), order_id: str = Form(...), payment_id: str = Form(...), signature: str = Form(...)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        owner_only(s)
        db, admin, _ = s
        try:
            p = billing.confirm_from_browser(db, get_gateway(), order_id, payment_id, signature, admin.org_id)
            audit(db, request, admin, "payment_paid", "payment", p.id, amount=p.amount_paise)
            return go("/billing", "Payment received. Your plan is updated.")
        except HTTPException as e:
            return go("/billing", error=str(e.detail))
        finally:
            db.close()

    @app.get("/billing/{payment_id}/receipt", response_class=HTMLResponse)
    def receipt(payment_id: str, request: Request):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        p = db.get(Payment, payment_id)
        if not p or p.status != "paid":
            deny(db, "No such receipt.")
        security.scope_org(admin, p.org_id)
        return page(request, "receipt.html", {"_s": s, "p": p, "org": db.get(Org, p.org_id)})

    # ---- users --------------------------------------------------------------------------------------------
    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request, msg: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        db, admin, _ = s
        rows = db.scalars(scoped(select(User), admin, User.org_id).order_by(User.name)).all()
        orgs = db.scalars(scoped(select(Org), admin, Org.id).order_by(Org.name)).all()
        return page(request, "users.html", {"_s": s, "users": rows, "orgs": orgs, "msg": msg})

    @app.post("/users")
    def users_create(request: Request, csrf: str = Form(""), name: str = Form(...), email: str = Form(""), employee_id: str = Form(""), org_id: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            oid = admin.org_id or org_id
            if not oid or not db.get(Org, oid):
                return go("/users", "Choose an organisation.")
            security.scope_org(admin, oid)
            if not name.strip():
                return go("/users", "Enter a name.")
            u = User(org_id=oid, name=name.strip(), email=email.strip().lower(), employee_id=employee_id.strip())
            db.add(u)
            db.commit()
            audit(db, request, admin, "user_create", "user", u.id)
            return go("/users", "User added.")
        finally:
            db.close()

    @app.post("/users/{user_id}/deactivate")
    def users_deactivate(user_id: str, request: Request, csrf: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            u = db.get(User, user_id)
            if not u:
                raise HTTPException(404, "No such user.")
            security.scope_org(admin, u.org_id)
            u.active = False
            n = 0
            for lic in db.scalars(select(License).where(License.user_id == u.id, License.status == "active")):
                lic.status, lic.revoked_reason = "revoked", "user switched off"
                n += 1
            db.commit()
            audit(db, request, admin, "user_deactivate", "user", u.id, revoked_licenses=n)
            return go("/users", "User switched off. Their seat is free again.")
        finally:
            db.close()

    # ---- licenses -----------------------------------------------------------------------------------------
    @app.get("/licenses", response_class=HTMLResponse)
    def licenses_page(request: Request, status: str = "", msg: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        db, admin, _ = s
        q = scoped(select(License), admin, License.org_id)
        if status:
            q = q.where(License.status == status)
        rows = db.scalars(q.order_by(License.expires_at)).all()
        names = {u.id: u.name for u in db.scalars(scoped(select(User), admin, User.org_id))}
        return page(request, "licenses.html", {"_s": s, "licenses": rows, "names": names, "status": status, "msg": msg})

    @app.get("/licenses/new", response_class=HTMLResponse)
    def license_new(request: Request, user_id: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        db, admin, _ = s
        users = db.scalars(scoped(select(User).where(User.active.is_(True)), admin, User.org_id).order_by(User.name)).all()
        allowed = tokens.FEATURES
        if admin.org_id:
            allowed = [f for f in tokens.FEATURES if f in (db.get(Org, admin.org_id).features or [])]
        return page(request, "issue.html", {"_s": s, "users": users, "features": allowed, "user_id": user_id, "error": error,
                                            "min_days": settings.min_days, "max_days": settings.max_days})

    @app.post("/licenses/new", response_class=HTMLResponse)
    def license_issue(request: Request, csrf: str = Form(""), user_id: str = Form(...), device_code: str = Form(...), days: int = Form(90),
                      features: list[str] = Form(default=[])):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        user = db.get(User, user_id)
        try:
            if not user:
                raise HTTPException(404, "No such user.")
            security.scope_org(admin, user.org_id)
            lic = issue(db, request, admin, user, device_code, features, days)
            audit(db, request, admin, "license_issue", "license", lic.id, org_id=user.org_id, user_id=user.id, days=days, features=lic.features)
        except HTTPException as e:
            db.close()
            return go("/licenses/new", error=str(e.detail), user_id=user_id)
        return page(request, "issued.html", {"_s": s, "lic": lic, "user": user})

    @app.get("/licenses/{license_id}/file", response_class=PlainTextResponse)
    def license_file(license_id: str, request: Request):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            lic = db.get(License, license_id)
            if not lic:
                raise HTTPException(404, "No such license.")
            security.scope_org(admin, lic.org_id)
            audit(db, request, admin, "license_download", "license", lic.id, org_id=lic.org_id)
            return PlainTextResponse(lic.token + "\n", headers={"Content-Disposition": f'attachment; filename="clearnai-{lic.id[:8]}.lic"'})
        finally:
            db.close()

    @app.post("/licenses/{license_id}/renew", response_class=HTMLResponse)
    def license_renew(license_id: str, request: Request, csrf: str = Form(""), days: int = Form(90)):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        old = db.get(License, license_id)
        try:
            if not old:
                raise HTTPException(404, "No such license.")
            security.scope_org(admin, old.org_id)
            new = supersede(db, request, admin, old, old.device_code, days, "license_renew")
        except HTTPException as e:
            db.close()
            return go("/licenses", str(e.detail))
        return page(request, "issued.html", {"_s": s, "lic": new, "user": db.get(User, new.user_id)})

    @app.post("/licenses/{license_id}/revoke")
    def license_revoke(license_id: str, request: Request, csrf: str = Form(""), reason: str = Form("")):
        s = need(request, csrf)
        if not s:
            return login_redirect()
        db, admin, _ = s
        try:
            lic = db.get(License, license_id)
            if not lic:
                raise HTTPException(404, "No such license.")
            security.scope_org(admin, lic.org_id)
            if lic.status != "active":
                return go("/licenses", f"That license is {lic.status}.")
            lic.status, lic.revoked_reason = "revoked", reason[:300]
            db.commit()
            audit(db, request, admin, "license_revoke", "license", lic.id, org_id=lic.org_id, reason=reason[:300])
            return go("/licenses", "License revoked. The seat is free again.")
        finally:
            db.close()

    # ---- audit --------------------------------------------------------------------------------------------
    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request):
        s = need(request)
        if not s:
            return login_redirect()
        if (r := gate(s)) is not None:
            return r
        db, admin, _ = s
        if admin.org_id is not None and admin.role != "owner":
            deny(db, "Only the owner or ClearNAI staff can read the audit log.")
        q = select(AuditLog) if admin.org_id is None else select(AuditLog).where(AuditLog.org_id == admin.org_id)
        rows = db.scalars(q.order_by(AuditLog.id.desc()).limit(300)).all()
        ids = {r.admin_id for r in rows if r.admin_id}
        who = {a.id: a.email for a in db.scalars(select(AdminUser).where(AdminUser.id.in_(ids)))} if ids else {}
        return page(request, "audit.html", {"_s": s, "rows": rows, "who": who})
