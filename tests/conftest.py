import os

# Must be set before licsrv is imported: settings are read once.
os.environ["LICSRV_DATABASE_URL"] = "sqlite://"
os.environ["LICSRV_SESSION_SECRET"] = "x" * 48
os.environ["LICSRV_COOKIE_SECURE"] = "false"
os.environ["LICSRV_DEV_OTP"] = ""  # a local .env must not change what the tests expect

from datetime import datetime, timedelta, timezone  # noqa: E402

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from licsrv import keys, security  # noqa: E402
from licsrv.db import Base, SessionLocal, engine  # noqa: E402
from licsrv.main import create_app  # noqa: E402
from licsrv.models import AdminUser, Org  # noqa: E402

PASSWORD = "correct horse battery"


@pytest.fixture()
def provider():
    return keys.generate_provider()


@pytest.fixture()
def world(provider):
    """Fresh database with two organisations, a super admin and an admin for each organisation."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    out = {}
    with SessionLocal() as db:
        far = datetime.now(timezone.utc) + timedelta(days=400)
        a, b = (Org(name=n, seats=50, paid_until=far, features=["accent", "bvc", "nc"]) for n in ("Org A", "Org B"))
        db.add_all([a, b])
        db.flush()
        for key, org in (("super", None), ("a", a.id), ("b", b.id)):
            secret = security.new_totp_secret()
            admin = AdminUser(email=f"{key}@example.com", org_id=org, role="owner" if org else "admin", totp_enabled=True, password_hash=security.hash_password(PASSWORD), totp_secret=secret)
            db.add(admin)
            out[key] = {"email": admin.email, "secret": secret}
        db.commit()
        out["org_a"], out["org_b"] = a.id, b.id
    out["app"] = create_app(provider)
    out["provider"] = provider
    return out


def login(world, who="super"):
    """Returns a client already logged in as `who` and its CSRF header."""
    client = TestClient(world["app"], base_url="http://testserver")
    info = world[who]
    r = client.post("/v1/auth/login", json={"email": info["email"], "password": PASSWORD, "totp": pyotp.TOTP(info["secret"]).now()})
    assert r.status_code == 200, r.text
    client.headers.update({"x-csrf-token": r.json()["csrf"]})
    return client
