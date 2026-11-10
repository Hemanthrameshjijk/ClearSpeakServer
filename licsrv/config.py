from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LICSRV_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./licsrv.db"
    # Signing key: an encrypted file made by scripts/newkey.py, opened with the passphrase.
    signing_key_file: Path = Path("signing.key")
    key_passphrase: str = ""
    # Signs the admin session cookie. Must be long and random in production.
    session_secret: str = ""
    session_hours: int = 8
    cookie_secure: bool = True  # set false only for local http testing
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_days: int = 1
    max_days: int = 400


settings = Settings()
