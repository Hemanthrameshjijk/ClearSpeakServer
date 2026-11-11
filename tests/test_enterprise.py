"""The company flow: ClearNAI staff make an organisation and its owner; the owner adds admins and people, pays for seats,
and issues licenses within the seats and validity they have."""

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from fastapi.testclient import TestClient

from conftest import PASSWORD, login
from licsrv import billing, tokens
from licsrv.config import settings
from licsrv.db import SessionLocal
from licsrv.models import AdminUser, Org, Payment

PC = {"guid": "dddddddd-0000-0000-0000-000000000001", "bios": "SN-E1", "cpu": "CPU-E1", "disk": None}
CODE = tokens.make_device_code(PC)


def client(world):
    return TestClient(world["app"], base_url="http://testserver", follow_redirects=False)


def csrf_of(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).text).group(1)


def staff(world):
    c = client(world)
    info = world["super"]
    r = c.post("/login", data={"email": info["email"], "password": PASSWORD, "totp": pyotp.TOTP(info["secret"]).now()})
    assert r.status_code == 303
    return c


def make_org(world, name="Acme", email="owner@acme.example", seats="2", days="30"):
    """ClearNAI staff create an organisation; returns (owner email, temporary password)."""
    c = staff(world)
    r = c.post("/orgs", data={"csrf": csrf_of(c, "/orgs"), "name": name, "owner_name": "Olive Owner", "owner_email": email,
                              "seats": seats, "days": days, "features": ["nc", "accent"]})
    assert r.status_code == 200
    return email, re.search(r'id="pw">([^<]+)<', r.text).group(1)


def owner_session(world, email, temp, new="a brand new password 1"):
    """Sign in with the temporary password (no authenticator), choose a real password, and return the signed-in client."""
    c = client(world)
    r = c.post("/login", data={"email": email, "password": temp})
    assert r.status_code == 303 and r.headers["location"] == "/password"
    assert c.get("/users").headers["location"] == "/password", "nothing else opens before the password is changed"
    r = c.post("/password", data={"csrf": csrf_of(c, "/password"), "current": temp, "new": new, "again": new})
    assert r.status_code == 303 and r.headers["location"].startswith("/")
    assert c.get("/users").status_code == 200
    return c


def add_person(c, name):
    c.post("/users", data={"csrf": csrf_of(c, "/users"), "name": name})
    return re.findall(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text)


def issue(c, user_id, days="30", features=("nc",), code=CODE):
    return c.post("/licenses/new", data={"csrf": csrf_of(c, "/licenses/new"), "user_id": user_id, "device_code": code, "days": days, "features": list(features)})


def test_staff_create_org_owner_signs_in_changes_password_and_works(world):
    email, temp = make_org(world)
    c = owner_session(world, email, temp)
    assert "Acme" in c.get("/").text and "0 / 2" in c.get("/").text
    (uid,) = add_person(c, "Pat Agent")
    r = issue(c, uid)
    assert r.status_code == 200 and "License issued" in r.text
    assert "1 / 2" in c.get("/licenses").text
    assert c.post("/login", data={"email": email, "password": temp}).status_code == 401, "the temporary password stops working"


def test_seats_are_enforced_and_freed_by_revoking(world):
    email, temp = make_org(world, seats="1")
    c = owner_session(world, email, temp)
    add_person(c, "One")
    add_person(c, "Two")
    ids = re.findall(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text)
    assert issue(c, ids[0]).status_code == 200
    r = issue(c, ids[1], code=tokens.make_device_code({**PC, "guid": "dddddddd-0000-0000-0000-000000000002", "bios": "SN-E2", "cpu": "CPU-E2"}))
    assert r.status_code == 303 and "seats" in r.headers["location"].lower()
    lic_id = re.search(r"/licenses/([0-9a-f-]{36})/revoke", c.get("/licenses").text).group(1)
    c.post(f"/licenses/{lic_id}/revoke", data={"csrf": csrf_of(c, "/licenses"), "reason": "left"})
    assert issue(c, ids[1]).status_code == 200


def test_renewing_a_license_does_not_use_an_extra_seat(world):
    email, temp = make_org(world, seats="1")
    c = owner_session(world, email, temp)
    (uid,) = add_person(c, "Solo")
    issue(c, uid)
    lic_id = re.search(r"/licenses/([0-9a-f-]{36})/renew", c.get("/licenses").text).group(1)
    r = c.post(f"/licenses/{lic_id}/renew", data={"csrf": csrf_of(c, "/licenses"), "days": "10"})
    assert r.status_code == 200 and "License issued" in r.text


def test_license_cannot_outlive_the_paid_period_and_plan_features_apply(world):
    email, temp = make_org(world, days="10")
    c = owner_session(world, email, temp)
    (uid,) = add_person(c, "Pat")
    r = issue(c, uid, days="300", features=("nc", "accent"))
    assert r.status_code == 200
    token = re.search(r"(CLNAI1\.[A-Za-z0-9_.-]+)", r.text).group(1)
    pk = world["provider"].public_key()
    p = tokens.verify_token(token, pk, tokens.parse_device_code(CODE), int(datetime.now(timezone.utc).timestamp()))
    assert p.exp - p.iat <= 10 * 86400 + 5, "capped to the paid period"
    r = issue(c, uid, features=("bvc",), code=tokens.make_device_code({**PC, "guid": "dddddddd-0000-0000-0000-000000000003", "bios": "SN-E3", "cpu": "CPU-E3"}))
    assert r.status_code == 303 and "does+not+include" in r.headers["location"].replace("%20", "+")


def test_an_ended_subscription_blocks_new_licenses_and_shows_a_banner(world):
    email, temp = make_org(world, days="0")
    c = owner_session(world, email, temp)
    assert "subscription has ended" in c.get("/").text
    (uid,) = add_person(c, "Pat")
    r = issue(c, uid)
    assert r.status_code == 303 and "ended" in r.headers["location"]


def test_suspended_org_cannot_sign_in(world):
    email, temp = make_org(world)
    s = staff(world)
    with SessionLocal() as db:
        org = db.query(Org).filter_by(name="Acme").one()
        oid = org.id
    owner_session(world, email, temp)
    s.post(f"/orgs/{oid}/status", data={"csrf": csrf_of(s, f"/orgs/{oid}"), "status": "suspended"})
    r = client(world).post("/login", data={"email": email, "password": "a brand new password 1"})
    assert r.status_code == 403


def test_owner_manages_team_and_plain_admins_cannot_touch_billing_or_team(world):
    email, temp = make_org(world)
    c = owner_session(world, email, temp)
    r = c.post("/team", data={"csrf": csrf_of(c, "/team"), "org_id": "", "name": "Ann Admin", "email": "ann@acme.example"})
    assert r.status_code == 200 and "Temporary password" in r.text
    ann_temp = re.search(r'id="pw">([^<]+)<', r.text).group(1)
    a = owner_session(world, "ann@acme.example", ann_temp)
    for path in ("/billing", "/team"):
        assert a.get(path).status_code == 403, path
    assert a.get("/audit").status_code == 403
    assert a.get("/users").status_code == 200 and a.get("/licenses/new").status_code == 200
    assert a.post("/billing/checkout", data={"csrf": csrf_of(a, "/users"), "kind": "renew", "seats": "1", "months": "1"}).status_code == 403


def test_two_step_sign_in_is_optional_and_can_be_turned_on(world):
    email, temp = make_org(world)
    c = owner_session(world, email, temp)
    with SessionLocal() as db:
        secret = db.query(AdminUser).filter_by(email=email).one().totp_secret
    assert "<svg" in c.get("/security").text, "a QR code is shown"
    r = c.post("/security/2fa/enable", data={"csrf": csrf_of(c, "/security"), "code": "000000"})
    assert "not%20right" in r.headers["location"]
    c.post("/security/2fa/enable", data={"csrf": csrf_of(c, "/security"), "code": pyotp.TOTP(secret).now()})
    fresh = client(world)
    assert fresh.post("/login", data={"email": email, "password": "a brand new password 1"}).status_code == 401
    assert fresh.post("/login", data={"email": email, "password": "a brand new password 1", "totp": pyotp.TOTP(secret).now()}).status_code == 303


# ---- payments ---------------------------------------------------------------------------------------------------
def pay_form(html):
    return {n: re.search(rf'name="{n}" value="([^"]*)"', html).group(1) for n in ("order_id", "payment_id", "signature")}


def test_mock_payment_renews_and_is_not_applied_twice(world):
    email, temp = make_org(world, seats="2", days="5")
    c = owner_session(world, email, temp)
    r = c.post("/billing/checkout", data={"csrf": csrf_of(c, "/billing"), "kind": "renew", "seats": "4", "months": "3"})
    assert r.status_code == 200 and "Pay" in r.text
    assert f"{4 * 3 * settings.seat_price_paise / 100:,.2f}" in r.text
    form = pay_form(r.text)
    csrf = csrf_of(c, "/billing")
    assert c.post("/billing/verify", data={"csrf": csrf, **form, "signature": "0" * 64}).headers["location"].startswith("/billing?error")
    with SessionLocal() as db:
        assert db.query(Org).filter_by(name="Acme").one().seats == 2, "a bad signature gives nothing"
    assert "Payment%20received" in c.post("/billing/verify", data={"csrf": csrf, **form}).headers["location"]
    with SessionLocal() as db:
        org = db.query(Org).filter_by(name="Acme").one()
        first = org.paid_until
        assert org.seats == 4 and (first.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days >= 5 + 89 - 1
    c.post("/billing/verify", data={"csrf": csrf, **form})
    with SessionLocal() as db:
        assert db.query(Org).filter_by(name="Acme").one().paid_until == first, "replaying the same payment changes nothing"
    assert "Receipt" in c.get("/billing").text


def test_cannot_renew_below_the_seats_already_in_use_or_buy_extra_when_ended(world):
    email, temp = make_org(world, seats="3", days="30")
    c = owner_session(world, email, temp)
    add_person(c, "A")
    add_person(c, "B")
    ids = re.findall(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text)
    issue(c, ids[0])
    issue(c, ids[1], code=tokens.make_device_code({**PC, "guid": "dddddddd-0000-0000-0000-000000000009", "bios": "SN-E9", "cpu": "CPU-E9"}))
    r = c.post("/billing/checkout", data={"csrf": csrf_of(c, "/billing"), "kind": "renew", "seats": "1", "months": "1"})
    assert r.status_code == 303 and "error" in r.headers["location"]
    email2, temp2 = make_org(world, name="Ended", email="o@ended.example", days="0")
    d = owner_session(world, email2, temp2)
    r = d.post("/billing/checkout", data={"csrf": csrf_of(d, "/billing"), "kind": "add_seats", "seats": "1", "months": "0"})
    assert r.status_code == 303 and "error" in r.headers["location"]


def test_adding_seats_is_prorated_to_the_remaining_time(world):
    email, temp = make_org(world, seats="2", days="15")
    c = owner_session(world, email, temp)
    r = c.post("/billing/checkout", data={"csrf": csrf_of(c, "/billing"), "kind": "add_seats", "seats": "2", "months": "0"})
    assert r.status_code == 200
    with SessionLocal() as db:
        p = db.query(Payment).one()
        assert p.amount_paise == -(-2 * settings.seat_price_paise * 15 // 30) or abs(p.amount_paise - 2 * settings.seat_price_paise * 0.5) < settings.seat_price_paise * 0.1
    c.post("/billing/verify", data={"csrf": csrf_of(c, "/billing"), **pay_form(r.text)})
    with SessionLocal() as db:
        assert db.query(Org).filter_by(name="Acme").one().seats == 4


def test_one_company_cannot_see_or_confirm_anothers_payment(world):
    e1, t1 = make_org(world)
    c1 = owner_session(world, e1, t1)
    r = c1.post("/billing/checkout", data={"csrf": csrf_of(c1, "/billing"), "kind": "renew", "seats": "1", "months": "1"})
    form = pay_form(r.text)
    e2, t2 = make_org(world, name="Other", email="o@other.example")
    c2 = owner_session(world, e2, t2)
    r = c2.post("/billing/verify", data={"csrf": csrf_of(c2, "/billing"), **form})
    assert r.status_code == 303 and "another%20organisation" in r.headers["location"]
    with SessionLocal() as db:
        assert db.query(Payment).one().status == "created", "nothing was applied"
    assert csrf_of(c1, "/billing") and c1.post("/billing/verify", data={"csrf": csrf_of(c1, "/billing"), **form}).status_code == 303


def razorpay(world, monkeypatch):
    monkeypatch.setattr(settings, "razorpay_key_id", "rzp_test_x")
    monkeypatch.setattr(settings, "razorpay_key_secret", "key_secret_x")
    monkeypatch.setattr(settings, "razorpay_webhook_secret", "whsec_x")
    gw = billing.RazorpayGateway()
    gw.create_order = lambda amount, currency, receipt: "order_RZP" + hashlib.sha1(receipt.encode()).hexdigest()[:10]
    world["app"].state.gateway = gw
    return gw


def webhook(c, body: dict, secret="whsec_x"):
    raw = json.dumps(body).encode()
    return c.post("/v1/webhooks/razorpay", content=raw, headers={"x-razorpay-signature": hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()})


def test_razorpay_signatures_and_webhook(world, monkeypatch):
    razorpay(world, monkeypatch)
    email, temp = make_org(world, days="5")
    c = owner_session(world, email, temp)
    r = c.post("/billing/checkout", data={"csrf": csrf_of(c, "/billing"), "kind": "renew", "seats": "3", "months": "1"})
    assert r.status_code == 200 and "checkout.razorpay.com" in r.text and "rzp_test_x" in r.text
    with SessionLocal() as db:
        p = db.query(Payment).one()
        order, amount, pid = p.provider_order_id, p.amount_paise, p.id
    evt = {"event": "payment.captured", "payload": {"payment": {"entity": {"id": "pay_1", "order_id": order, "amount": amount, "currency": "INR"}}}}
    api = TestClient(world["app"], base_url="http://testserver")
    assert api.post("/v1/webhooks/razorpay", content=json.dumps(evt), headers={"x-razorpay-signature": "bad"}).status_code == 400
    assert webhook(api, {**evt, "payload": {"payment": {"entity": {**evt["payload"]["payment"]["entity"], "amount": 1}}}}).json()["note"] == "amount mismatch"
    with SessionLocal() as db:
        assert db.get(Payment, pid).status == "created"
    assert webhook(api, evt).json()["note"] == "applied"
    assert webhook(api, evt).json()["note"] == "already applied"
    with SessionLocal() as db:
        org = db.query(Org).filter_by(name="Acme").one()
        assert org.seats == 3 and db.get(Payment, pid).status == "paid"
    # the browser's confirmation after the webhook is harmless
    sig = hmac.new(b"key_secret_x", f"{order}|pay_1".encode(), hashlib.sha256).hexdigest()
    c.post("/billing/verify", data={"csrf": csrf_of(c, "/billing"), "order_id": order, "payment_id": "pay_1", "signature": sig})
    with SessionLocal() as db:
        assert db.query(Org).filter_by(name="Acme").one().seats == 3


def test_json_api_org_flow_and_entitlements(world):
    s = login(world, "super")
    r = s.post("/v1/orgs", json={"name": "ApiCo", "owner_name": "Ola", "owner_email": "ola@api.example", "seats": 3, "days": 20})
    assert r.status_code == 201 and r.json()["temporary_password"]
    oid = r.json()["id"]
    o = s.put(f"/v1/orgs/{oid}/entitlements", json={"seats": 9, "days_from_now": 100, "features": ["nc"]})
    assert o.status_code == 200 and o.json()["seats"] == 9 and o.json()["features"] == ["nc"] and o.json()["valid"]
    a = login(world, "a")
    assert a.put(f"/v1/orgs/{oid}/entitlements", json={"seats": 99, "features": ["nc"]}).status_code == 403
    me = a.get("/v1/me").json()
    assert me["role"] == "owner" and me["org"]["seats"] == 50
    assert a.post("/v1/billing/orders", json={"kind": "renew", "seats": 5, "months": 1}).status_code == 201
    assert s.post("/v1/billing/orders", json={"kind": "renew", "seats": 5, "months": 1}).status_code == 403
    r = a.post("/v1/billing/orders", json={"kind": "renew", "seats": 5, "months": 999})
    assert r.status_code == 422


def test_staff_can_add_another_super_admin(world):
    s = staff(world)
    r = s.post("/staff", data={"csrf": csrf_of(s, "/staff"), "name": "Second Staff", "email": "second@clearnai.example"})
    assert r.status_code == 200 and "Super admin" in r.text
    temp = re.search(r'id="pw">([^<]+)<', r.text).group(1)
    c = owner_session(world, "second@clearnai.example", temp)
    assert c.get("/orgs").status_code == 200 and c.get("/staff").status_code == 200
    # an organisation owner cannot reach the staff page
    email, otemp = make_org(world)
    o = owner_session(world, email, otemp)
    assert o.get("/staff").status_code == 403


def test_dev_otp_works_only_when_set_and_not_on_secure_cookies(world, monkeypatch):
    info = world["super"]
    c = client(world)
    assert c.post("/login", data={"email": info["email"], "password": PASSWORD, "totp": "111111"}).status_code == 401
    monkeypatch.setattr(settings, "dev_otp", "111111")
    assert c.post("/login", data={"email": info["email"], "password": PASSWORD, "totp": "111111"}).status_code == 303
    monkeypatch.setattr(settings, "cookie_secure", True)
    assert c.post("/login", data={"email": info["email"], "password": PASSWORD, "totp": "111111"}).status_code == 401


def test_login_page_shows_the_dev_code_only_in_local_mode(world, monkeypatch):
    c = client(world)
    assert "Local test mode" not in c.get("/login").text
    monkeypatch.setattr(settings, "dev_otp", "111111")
    assert "Local test mode" in c.get("/login").text
    monkeypatch.setattr(settings, "cookie_secure", True)
    assert "Local test mode" not in c.get("/login").text


def test_one_form_creates_the_person_and_the_license(world):
    email, temp = make_org(world, seats="2")
    c = owner_session(world, email, temp)
    r = c.post("/licenses/new", data={"csrf": csrf_of(c, "/licenses/new"), "user_id": "", "new_name": "Nia New", "new_email": "nia@acme.example",
                                      "device_code": CODE, "days": "30", "features": ["nc", "accent"]})
    assert r.status_code == 200 and "License issued for Nia New" in r.text
    assert "Nia New" in c.get("/users").text and "1 / 2" in c.get("/licenses").text
    r = c.post("/licenses/new", data={"csrf": csrf_of(c, "/licenses/new"), "user_id": "", "new_name": "", "device_code": CODE, "days": "30", "features": ["nc"]})
    assert r.status_code == 303 and "error" in r.headers["location"]


def test_changing_features_makes_a_new_license_that_replaces_the_old_one(world):
    email, temp = make_org(world, seats="1")
    c = owner_session(world, email, temp)
    (uid,) = add_person(c, "Pat")
    issue(c, uid, features=("nc", "accent"))
    old_id = re.search(r"/licenses/([0-9a-f-]{36})/change", c.get("/licenses").text).group(1)
    r = c.post(f"/licenses/{old_id}/change", data={"csrf": csrf_of(c, "/licenses"), "days": "20", "features": ["nc"]})
    assert r.status_code == 200 and "License changed" in r.text
    token = re.search(r"(CLNAI1\.[A-Za-z0-9_.-]+)", r.text).group(1)
    p = tokens.verify_token(token, world["provider"].public_key(), tokens.parse_device_code(CODE), int(datetime.now(timezone.utc).timestamp()))
    assert p.feat == ["nc"], "the accent feature was taken away"
    page = c.get("/licenses").text
    assert "replaced" in page and "1 / 1" in page, "still one seat"
    r = c.post(f"/licenses/{old_id}/change", data={"csrf": csrf_of(c, "/licenses"), "days": "20", "features": ["nc"]})
    assert r.status_code == 303, "the replaced license cannot be changed again"
