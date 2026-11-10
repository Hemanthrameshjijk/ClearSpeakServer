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
    public_url: str = "http://127.0.0.1:8000"
    # Payments. "mock" = a fake checkout for local testing (never use in production); "razorpay" = real payments.
    payment_provider: str = "mock"
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_webhook_secret: str = ""
    currency: str = "INR"
    seat_price_paise: int = 29900  # price of one seat for one month, in paise (INR 299.00). Placeholder: set your real price.
    max_seats: int = 5000
    max_months: int = 24


settings = Settings()
