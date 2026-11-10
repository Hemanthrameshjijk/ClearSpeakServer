import time

import pyotp
from fastapi.testclient import TestClient

from conftest import PASSWORD, login
from licsrv import tokens

PC = {"guid": "aaaaaaaa-0000-0000-0000-000000000001", "bios": "SN-1", "cpu": "CPU-1", "disk": None}
PC2 = {"guid": "bbbbbbbb-0000-0000-0000-000000000002", "bios": "SN-2", "cpu": "CPU-2", "disk": None}
CODE = tokens.make_device_code(PC)
CODE2 = tokens.make_device_code(PC2)


def mk_user(client, org_id=None, name="Asha Rao"):
    body = {"name": name, "email": "asha@example.com"}
    if org_id:
        body["org_id"] = org_id
    r = client.post("/v1/users", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_login_needs_the_right_password_and_totp(world):
    client = TestClient(world["app"])
    who = world["super"]
    for body in (
        {"email": who["email"], "password": "wrong password!!", "totp": pyotp.TOTP(who["secret"]).now()},
        {"email": who["email"], "password": PASSWORD, "totp": "000000"},
        {"email": "nobody@example.com", "password": PASSWORD, "totp": "123456"},
    ):
        r = client.post("/v1/auth/login", json=body)
        assert r.status_code == 401
        assert r.json()["detail"] == "Wrong email, password or code.", "the same message for every failure"


def test_account_locks_after_repeated_failures(world):
    client = TestClient(world["app"])
    who = world["a"]
    for _ in range(5):
        client.post("/v1/auth/login", json={"email": who["email"], "password": "wrong password!!", "totp": "000000"})
    r = client.post("/v1/auth/login", json={"email": who["email"], "password": PASSWORD, "totp": pyotp.TOTP(who["secret"]).now()})
    assert r.status_code == 429


def test_everything_needs_a_session_and_a_csrf_token(world):
    anon = TestClient(world["app"])
    assert anon.get("/v1/orgs").status_code == 401
    assert anon.post("/v1/licenses", json={}).status_code == 401
    client = login(world)
    del client.headers["x-csrf-token"]
    assert client.post("/v1/orgs", json={"name": "No token Org"}).status_code == 403


def test_issue_a_license_the_reference_verifier_accepts(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    r = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "features": ["nc", "accent"], "days": 90})
    assert r.status_code == 201, r.text
    lic = r.json()
    pk = bytes.fromhex(client.get("/v1/public-key").json()["hex"])
    now = int(time.time())
    p = tokens.verify_token(lic["token"], pk, tokens.parse_device_code(CODE), now)
    assert (p.name, p.feat, p.org, p.uid) == ("Asha Rao", ["accent", "nc"], world["org_a"], user["id"])
    assert 89 * 86400 < p.exp - p.iat < 91 * 86400
    try:
        tokens.verify_token(lic["token"], pk, tokens.parse_device_code(CODE2), now)
        raise AssertionError("another PC must be refused")
    except tokens.TokenError as e:
        assert str(e) == "wrong device"


def test_issue_validates_its_input(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    ok = {"user_id": user["id"], "device_code": CODE, "features": ["nc"], "days": 30}
    assert client.post("/v1/licenses", json={**ok, "days": 0}).status_code == 422
    assert client.post("/v1/licenses", json={**ok, "days": 9999}).status_code == 422
    assert client.post("/v1/licenses", json={**ok, "features": []}).status_code == 422
    assert client.post("/v1/licenses", json={**ok, "features": ["magic"]}).status_code == 422
    assert client.post("/v1/licenses", json={**ok, "device_code": "nonsense"}).status_code == 422
    assert client.post("/v1/licenses", json={**ok, "user_id": "missing"}).status_code == 404


def test_renew_replaces_the_old_license_and_keeps_the_device(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    first = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 30}).json()
    renewed = client.post(f"/v1/licenses/{first['id']}/renew", json={"days": 60})
    assert renewed.status_code == 201
    assert renewed.json()["device_code"] == first["device_code"]
    assert client.get(f"/v1/licenses/{first['id']}").json()["status"] == "replaced"
    assert client.post(f"/v1/licenses/{first['id']}/renew", json={"days": 60}).status_code == 409, "a replaced license cannot be renewed again"


def test_replace_device_issues_for_the_new_pc_and_retires_the_old(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    first = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 30}).json()
    moved = client.post(f"/v1/licenses/{first['id']}/replace-device", json={"device_code": CODE2})
    assert moved.status_code == 201
    pk = bytes.fromhex(client.get("/v1/public-key").json()["hex"])
    tokens.verify_token(moved.json()["token"], pk, tokens.parse_device_code(CODE2), int(time.time()))
    assert client.get(f"/v1/licenses/{first['id']}").json()["status"] == "replaced"


def test_revoke_and_deactivate_user(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    lic = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 30}).json()
    r = client.post(f"/v1/licenses/{lic['id']}/revoke", json={"reason": "left the company"})
    assert r.json()["status"] == "revoked"
    assert client.post(f"/v1/licenses/{lic['id']}/revoke", json={}).status_code == 409
    lic2 = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE2, "days": 30}).json()
    d = client.post(f"/v1/users/{user['id']}/deactivate").json()
    assert d["revoked_licenses"] == 1
    assert client.get(f"/v1/licenses/{lic2['id']}").json()["status"] == "revoked"
    assert client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 30}).status_code == 409


def test_org_admins_only_see_and_touch_their_own_org(world):
    sup = login(world)
    a, b = login(world, "a"), login(world, "b")
    user_a = mk_user(a, name="Agent A")
    mk_user(b, name="Agent B")
    lic = a.post("/v1/licenses", json={"user_id": user_a["id"], "device_code": CODE, "days": 30}).json()
    assert [u["name"] for u in a.get("/v1/users").json()] == ["Agent A"]
    assert [u["name"] for u in b.get("/v1/users").json()] == ["Agent B"]
    assert len(sup.get("/v1/users").json()) == 2
    assert b.get(f"/v1/licenses/{lic['id']}").status_code == 403
    assert b.post(f"/v1/licenses/{lic['id']}/revoke", json={}).status_code == 403
    assert b.post("/v1/licenses", json={"user_id": user_a["id"], "device_code": CODE, "days": 30}).status_code == 403
    assert b.post("/v1/orgs", json={"name": "Sneaky"}).status_code == 403
    assert b.get("/v1/licenses").json() == []
    assert b.get("/v1/audit").status_code == 403
    assert len(sup.get("/v1/orgs").json()) == 2 and len(a.get("/v1/orgs").json()) == 1


def test_list_filters_and_license_file(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    soon = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 5}).json()
    client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE2, "days": 200})
    assert [x["id"] for x in client.get("/v1/licenses?expiring_within_days=10").json()] == [soon["id"]]
    assert len(client.get(f"/v1/licenses?user_id={user['id']}&status=active").json()) == 2
    f = client.get(f"/v1/licenses/{soon['id']}/file")
    assert f.status_code == 200 and f.text.strip() == soon["token"]
    assert "attachment" in f.headers["content-disposition"]


def test_the_audit_log_records_actions_but_never_tokens(world):
    client = login(world)
    user = mk_user(client, world["org_a"])
    lic = client.post("/v1/licenses", json={"user_id": user["id"], "device_code": CODE, "days": 30}).json()
    log = client.get("/v1/audit").json()
    actions = [r["action"] for r in log]
    assert "license_issue" in actions and "user_create" in actions and "login" in actions
    assert lic["token"] not in str(log)
