# ClearNAI license server

Admins create users and issue device-bound license tokens that the ClearNAI app checks offline (see
`docs/token-spec.md`). Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL (SQLite for dev/tests).

## First setup

    python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
    python scripts/newkey.py signing.key          # production signing key (encrypted); prints the public key for the app
    # .env (never commit): LICSRV_SESSION_SECRET (32+ random chars), LICSRV_KEY_PASSPHRASE, LICSRV_DATABASE_URL
    alembic upgrade head                              # create the tables
    python scripts/create_admin.py you@example.com    # super admin; prints the TOTP secret once
    uvicorn licsrv.wsgi:app --port 8000

Put a TLS reverse proxy in front (see `docker-compose.yml`). The public key from `newkey.py` goes into the app's
`app/src/license_key.rs`; rebuild the app after that. **Back up `signing.key` and its passphrase offline: without them no
new valid token can be made. If someone else gets them they can make tokens for anyone.**

## Tests

    python -m pytest -q

`tests/vectors.json` is shared with the app repo (regenerate with `scripts/make_vectors.py` only when the format changes).

## What is not built yet

Online sign-in mode, organisation certificates and the offline admin tool, revocation lists inside renewal tokens,
a CI badge and a hosted instance. Tables come from migrations: `alembic upgrade head` before starting (the Dockerfile does this).
