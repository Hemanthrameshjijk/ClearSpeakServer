"""Create an admin who can log in to the portal. Super admin: no --org. Prints the TOTP secret once; add it to an
authenticator app.   python scripts/create_admin.py admin@example.com [--org "Org name"]"""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from licsrv import security  # noqa: E402
from licsrv.db import Base, SessionLocal, engine  # noqa: E402
from licsrv.models import AdminUser, Org  # noqa: E402

args = sys.argv[1:]
if not args:
    sys.exit('usage: python scripts/create_admin.py <email> [--org "Org name"]')
email = args[0].strip().lower()
org_name = args[args.index("--org") + 1] if "--org" in args else None
pw = getpass.getpass("Password (12+ characters): ")
if pw != getpass.getpass("Again: "):
    sys.exit("The passwords differ.")

Base.metadata.create_all(engine)
with SessionLocal() as db:
    org = None
    if org_name:
        org = db.scalar(select(Org).where(Org.name == org_name)) or Org(name=org_name)
        db.add(org)
        db.flush()
    secret = security.new_totp_secret()
    db.add(AdminUser(email=email, org_id=org.id if org else None, role="owner" if org else "admin", password_hash=security.hash_password(pw), totp_secret=secret))
    db.commit()
print(f"Admin {email} created ({'org admin of ' + org_name if org_name else 'super admin'}).")
print(f"TOTP secret (shown once): {secret}")
print(f"otpauth://totp/ClearNAI:{email}?secret={secret}&issuer=ClearNAI")
