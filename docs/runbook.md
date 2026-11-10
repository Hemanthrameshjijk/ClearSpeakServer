# Runbook

## Roles and the company flow
1. **ClearNAI staff (super admin)** open **Organisations**, create the company and its owner (name, email, seats, free days, features) and hand over the temporary password shown once.
2. **The owner** signs in, chooses a password, optionally turns on two-step sign-in, adds admins on **Team**, people on **People**, and pays on **Billing**.
3. **Admins** add people and issue licenses. Seats = licenses active at once; revoking or switching a person off frees the seat.
4. A license can never run longer than the paid period. When the period ends, new licenses are blocked until the owner renews.

## Payments
Set `LICSRV_PAYMENT_PROVIDER=razorpay`, `LICSRV_RAZORPAY_KEY_ID`, `LICSRV_RAZORPAY_KEY_SECRET`, `LICSRV_RAZORPAY_WEBHOOK_SECRET`, `LICSRV_SEAT_PRICE_PAISE`.
In the Razorpay dashboard add a webhook to `https://YOUR-DOMAIN/v1/webhooks/razorpay` for `payment.captured` and `order.paid`. `mock` is for local testing only.

## Everyday: issue a license
1. The user opens ClearNAI > Profile, presses **Copy** next to "This PC's Device Code", and sends it to you.
2. Sign in to the portal > **Issue license**: choose the user, paste the code, tick the features, choose the days.
3. Send the text (or the `.lic` file) back. The user pastes it, or uses **Import .lic file**, on the Profile page.
4. Renew before it expires from the dashboard ("Expiring in the next 30 days"). A new token replaces the old one.

## A user changes PC or reinstalls Windows
Ask for the new Device Code, then on **Licenses** use the replace-device action (API: `POST /v1/licenses/{id}/replace-device`).
The old license is marked replaced. A reinstall that keeps the BIOS and disk usually still works (2 of 3 parts match).

## Someone leaves
Users > **Switch off**. Their active licenses are revoked. Offline copies keep working until their expiry date, so keep
expiry short (30 to 90 days) for people who may leave.

## The signing key
`signing.key` is encrypted with a passphrase. Without both, no new valid license can be made; with both, anyone can make
licenses for anyone. Keep an offline backup of the file and the passphrase in different places. If it is ever lost or
leaked: make a new key (`scripts/newkey.py`), put its public key into the app (`app/src/license_key.rs`), release a new
app version, and reissue every license.

## Moving from this PC to a real host
* Put the server on a machine with a TLS reverse proxy in front (see `docker-compose.yml`); never expose port 8000.
* Use PostgreSQL (`LICSRV_DATABASE_URL=postgresql+psycopg://...`), run `alembic upgrade head`, keep `LICSRV_COOKIE_SECURE=true`.
* Set `LICSRV_SESSION_SECRET` and `LICSRV_KEY_PASSPHRASE` as secrets on the host, not in files next to the code.
* Back up the database and the key; test restoring them.

## Privacy
The server stores names, emails, employee ids and hashes of hardware values (never raw serial numbers). Decide how long
to keep revoked or expired records, tell users what is stored, and limit who can open the portal and the audit log.
