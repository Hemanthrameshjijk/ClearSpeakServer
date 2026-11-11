"""Production entry point: `uvicorn licsrv.wsgi:app`. Opens the encrypted signing key from the environment."""

from .config import settings
from .keys import load_encrypted_key
from .main import create_app

if not settings.key_passphrase:
    raise RuntimeError("LICSRV_KEY_PASSPHRASE is not set")

# Tables come from `alembic upgrade head` (run before start; the Dockerfile does it), not from create_all.
_keys = load_encrypted_key(settings.signing_key_file, settings.key_passphrase)
_pub = _keys.public_key().hex()
if settings.expected_public_key and _pub != settings.expected_public_key.strip().lower():
    raise RuntimeError(
        f"The signing key {settings.signing_key_file} (public key {_pub}) is not the key the ClearNAI app trusts "
        f"({settings.expected_public_key}). Licenses from it would be rejected. Point LICSRV_SIGNING_KEY_FILE at the right key."
    )
print(f"ClearNAI license server: signing with public key {_pub}", flush=True)
app = create_app(_keys, create_tables=False)
