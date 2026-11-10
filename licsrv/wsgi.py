"""Production entry point: `uvicorn licsrv.wsgi:app`. Opens the encrypted signing key from the environment."""

from .config import settings
from .keys import load_encrypted_key
from .main import create_app

if not settings.key_passphrase:
    raise RuntimeError("LICSRV_KEY_PASSPHRASE is not set")

# Tables come from `alembic upgrade head` (run before start; the Dockerfile does it), not from create_all.
app = create_app(load_encrypted_key(settings.signing_key_file, settings.key_passphrase), create_tables=False)
