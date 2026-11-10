"""Admin web pages (server-rendered). They use the same session cookie and the same business functions as the JSON API;
forms carry the session's CSRF token in a hidden field."""

from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from . import security, tokens
from .config import settings
from .db import SessionLocal
from .models import AdminUser, AuditLog, License, Org, User

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def register(app: FastAPI, issue, supersede) -> None:
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
        s = ctx.pop("_s")
        db, admin, csrf = s
        try:
            return templates.TemplateResponse(request, name, {"admin": admin, "csrf": csrf, "is_super": admin.org_id is None, **ctx}, status_code=status)
        finally:
            db.close()

    def need(request: Request, csrf_field: str | None = None):
        """Signed-in session, and for form posts the matching CSRF token; else None (caller redirects to /login)."""
        s = session(request)
        if s is None:
            return None
        if csrf_field is not None and not hmac.compare_digest(csrf_field, s[2]):
            s[0].close()
            raise HTTPException(403, "Missing or wrong CSRF token.")
        return s

    def login_redirect():
        return RedirectResponse("/login", status_code=303)

    def audit(db, request, admin, action, target_type="", target_id="", **detail):
        db.add(AuditLog(admin_id=admin.id, action=action, target_type=target_type, target_id=target_id, detail=detail,
                        ip=request.client.host if request.client else ""))
        db.commit()

    # ---- login --------------------------------------------------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": ""})

    @app.post("/login")
    def login_submit(request: Request, email: str = Form(...), password: str = Form(...), totp: str = Form("")):
        db = SessionLocal()
        try:
            admin = db.scalar(select(AdminUser).where(AdminUser.email == email.strip().lower()))
            bad = templates.TemplateResponse(request, "login.html", {"error": "Wrong email, password or code."}, status_code=401)
            if not admin or not admin.active:
                return bad
            if security.is_locked(admin):
                return templates.TemplateResponse(request, "login.html", {"error": "Too many wrong attempts. Try again later."}, status_code=429)
            if not (security.check_password(admin.password_hash, password) and security.check_totp(admin.totp_secret, totp)):
                security.register_failure(db, admin)
                audit(db, request, admin, "login_failed")
                return bad
            admin.failed_logins = 0
            db.commit()
            cookie, _ = security.make_session(admin.id)
            resp = RedirectResponse("/", status_code=303)
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

    # ---- dashboard ----------------------------------------------------------------------------------------
    def scoped(q, admin, col):
        return q if admin.org_id is None else q.where(col == admin.org_id)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        now = datetime.now(timezone.utc)
        active = db.scalar(scoped(select(func.count()).select_from(License).where(License.status == "active"), admin, License.org_id))
        soon = db.scalars(scoped(select(License).where(License.status == "active", License.expires_at <= now + timedelta(days=30)), admin, License.org_id)
                          .order_by(License.expires_at)).all()
        users = db.scalar(scoped(select(func.count()).select_from(User).where(User.active.is_(True)), admin, User.org_id))
        names = {u.id: u.name for u in db.scalars(select(User))}
        return page(request, "dashboard.html", {"_s": s, "active": active, "users": users, "soon": soon, "names": names})

    # ---- users --------------------------------------------------------------------------------------------
    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request, msg: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
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
                return RedirectResponse("/users?msg=Choose+an+organisation.", status_code=303)
            security.scope_org(admin, oid)
            if not name.strip():
                return RedirectResponse("/users?msg=Enter+a+name.", status_code=303)
            u = User(org_id=oid, name=name.strip(), email=email.strip().lower(), employee_id=employee_id.strip())
            db.add(u)
            db.commit()
            audit(db, request, admin, "user_create", "user", u.id)
            return RedirectResponse("/users?msg=User+added.", status_code=303)
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
            return RedirectResponse("/users?msg=User+switched+off.", status_code=303)
        finally:
            db.close()

    # ---- licenses -----------------------------------------------------------------------------------------
    @app.get("/licenses", response_class=HTMLResponse)
    def licenses_page(request: Request, status: str = "", msg: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        q = scoped(select(License), admin, License.org_id)
        if status:
            q = q.where(License.status == status)
        rows = db.scalars(q.order_by(License.expires_at)).all()
        names = {u.id: u.name for u in db.scalars(select(User))}
        return page(request, "licenses.html", {"_s": s, "licenses": rows, "names": names, "status": status, "msg": msg})

    @app.get("/licenses/new", response_class=HTMLResponse)
    def license_new(request: Request, user_id: str = "", error: str = ""):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        users = db.scalars(scoped(select(User).where(User.active.is_(True)), admin, User.org_id).order_by(User.name)).all()
        return page(request, "issue.html", {"_s": s, "users": users, "features": tokens.FEATURES, "user_id": user_id, "error": error,
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
            audit(db, request, admin, "license_issue", "license", lic.id, user_id=user.id, days=days, features=lic.features)
        except HTTPException as e:
            db.close()
            from urllib.parse import quote

            return RedirectResponse(f"/licenses/new?user_id={quote(user_id)}&error={quote(str(e.detail))}", status_code=303)
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
            audit(db, request, admin, "license_download", "license", lic.id)
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
            from urllib.parse import quote

            return RedirectResponse(f"/licenses?msg={quote(str(e.detail))}", status_code=303)
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
                return RedirectResponse(f"/licenses?msg=That+license+is+{lic.status}.", status_code=303)
            lic.status, lic.revoked_reason = "revoked", reason[:300]
            db.commit()
            audit(db, request, admin, "license_revoke", "license", lic.id, reason=reason[:300])
            return RedirectResponse("/licenses?msg=License+revoked.", status_code=303)
        finally:
            db.close()

    # ---- audit --------------------------------------------------------------------------------------------
    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request):
        s = need(request)
        if not s:
            return login_redirect()
        db, admin, _ = s
        if admin.org_id is not None:
            db.close()
            raise HTTPException(403, "Only a super admin can read the audit log.")
        rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(300)).all()
        return page(request, "audit.html", {"_s": s, "rows": rows})
