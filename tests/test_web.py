import re

import pyotp
from fastapi.testclient import TestClient

from conftest import PASSWORD
from licsrv import tokens

PC = {"guid": "cccccccc-0000-0000-0000-000000000001", "bios": "SN-9", "cpu": "CPU-9", "disk": None}
CODE = tokens.make_device_code(PC)


def web_login(world, who="super"):
    c = TestClient(world["app"], base_url="http://testserver", follow_redirects=False)
    info = world[who]
    r = c.post("/login", data={"email": info["email"], "password": PASSWORD, "totp": pyotp.TOTP(info["secret"]).now()})
    assert r.status_code == 303, r.text
    return c


def csrf_of(c, path="/users"):
    html = c.get(path).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_pages_redirect_to_login_when_signed_out(world):
    c = TestClient(world["app"], follow_redirects=False)
    for path in ("/", "/users", "/licenses", "/licenses/new", "/audit"):
        r = c.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    assert c.get("/login").status_code == 200


def test_bad_login_shows_one_message(world):
    c = TestClient(world["app"], follow_redirects=False)
    r = c.post("/login", data={"email": world["super"]["email"], "password": "wrong password!!", "totp": "000000"})
    assert r.status_code == 401 and "Wrong email, password or code." in r.text


def test_add_a_user_and_issue_a_license_through_the_pages(world):
    c = web_login(world, "a")
    csrf = csrf_of(c)
    r = c.post("/users", data={"csrf": csrf, "name": "Asha <b>Rao</b>", "email": "asha@example.com"})
    assert r.status_code == 303
    page = c.get("/users").text
    assert "Asha &lt;b&gt;Rao&lt;/b&gt;" in page, "names are escaped, not rendered as HTML"
    user_id = re.search(r"/licenses/new\?user_id=([0-9a-f-]{36})", page).group(1)
    issue_page = c.get(f"/licenses/new?user_id={user_id}")
    assert "selected" in issue_page.text
    r = c.post("/licenses/new", data={"csrf": csrf, "user_id": user_id, "device_code": CODE, "days": "45", "features": ["nc", "accent"]})
    assert r.status_code == 200 and "License issued" in r.text
    token = re.search(r"(CLNAI1\.[A-Za-z0-9_.-]+)", r.text).group(1)
    pk = bytes.fromhex(TestClient(world["app"]).get("/v1/public-key").json()["hex"])
    import time

    p = tokens.verify_token(token, pk, tokens.parse_device_code(CODE), int(time.time()))
    assert p.feat == ["accent", "nc"] and 44 * 86400 < p.exp - p.iat < 46 * 86400
    assert "Download" in c.get("/licenses").text


def test_a_bad_device_code_shows_the_error_on_the_form(world):
    c = web_login(world, "a")
    csrf = csrf_of(c)
    c.post("/users", data={"csrf": csrf, "name": "Ravi"})
    user_id = re.search(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text).group(1)
    r = c.post("/licenses/new", data={"csrf": csrf, "user_id": user_id, "device_code": "nonsense", "days": "30", "features": ["nc"]})
    assert r.status_code == 303
    assert "not+a+valid+Device+Code" in r.headers["location"] or "not%20a%20valid%20Device%20Code" in r.headers["location"]
    assert "not a valid Device Code" in c.get(r.headers["location"]).text


def test_form_posts_need_the_csrf_token(world):
    c = web_login(world, "a")
    assert c.post("/users", data={"csrf": "wrong", "name": "X"}).status_code == 403
    assert c.post("/users", data={"name": "X"}).status_code == 403 or c.post("/users", data={"name": "X"}).status_code == 422


def test_renew_and_revoke_from_the_pages(world):
    c = web_login(world, "a")
    csrf = csrf_of(c)
    c.post("/users", data={"csrf": csrf, "name": "Meena"})
    user_id = re.search(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text).group(1)
    c.post("/licenses/new", data={"csrf": csrf, "user_id": user_id, "device_code": CODE, "days": "10", "features": ["nc"]})
    lic_id = re.search(r"/licenses/([0-9a-f-]{36})/file", c.get("/licenses").text).group(1)
    r = c.post(f"/licenses/{lic_id}/renew", data={"csrf": csrf, "days": "60"})
    assert r.status_code == 200 and "License issued" in r.text
    assert "replaced" in c.get("/licenses").text
    new_id = re.search(r"/licenses/([0-9a-f-]{36})/file", c.get("/licenses?status=active").text).group(1)
    r = c.post(f"/licenses/{new_id}/revoke", data={"csrf": csrf, "reason": "left"})
    assert r.status_code == 303
    assert "left" in c.get("/licenses?status=revoked").text


def test_org_admins_cannot_reach_other_orgs_or_the_audit_page(world):
    a, b = web_login(world, "a"), web_login(world, "b")
    csrf_a = csrf_of(a)
    a.post("/users", data={"csrf": csrf_a, "name": "Only A"})
    user_id = re.search(r"/licenses/new\?user_id=([0-9a-f-]{36})", a.get("/users").text).group(1)
    csrf_b = csrf_of(b)
    r = b.post("/licenses/new", data={"csrf": csrf_b, "user_id": user_id, "device_code": CODE, "days": "30", "features": ["nc"]})
    assert r.status_code == 303 and "another+organisation" in r.headers["location"].replace("%20", "+")
    assert "Only A" not in b.get("/users").text
    assert "CLNAI1" not in b.get("/licenses").text, "nothing was issued"
    assert b.get("/audit").status_code == 403
    assert web_login(world).get("/audit").status_code == 200


def test_dashboard_lists_licenses_expiring_soon(world):
    c = web_login(world, "a")
    csrf = csrf_of(c)
    c.post("/users", data={"csrf": csrf, "name": "Soon Soon"})
    user_id = re.search(r"/licenses/new\?user_id=([0-9a-f-]{36})", c.get("/users").text).group(1)
    c.post("/licenses/new", data={"csrf": csrf, "user_id": user_id, "device_code": CODE, "days": "7", "features": ["nc"]})
    html = c.get("/").text
    assert "Soon Soon" in html and "Renew" in html
