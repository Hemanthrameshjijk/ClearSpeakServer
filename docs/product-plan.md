# ClearNAI Enterprise Portal — product plan (v2)

Goal: a proper, branded enterprise server (like Krisp's business dashboard) where a company signs up, admins manage
people, people sign in to the ClearNAI app, and licences/seats/devices are controlled. Runs on local SQLite for
development and PostgreSQL in production. Built on the existing `licsrv` code (tokens, keys, audit, RBAC stay).

## 0. What exists today
Admin-only portal (email + password + authenticator code), orgs, users, device-bound offline tokens, audit log.
Gaps: no company sign-up, no end-user login, no invites, no seats/plans, no password reset, no email, plain styling,
no ClearNAI branding, the admin must use an authenticator app (not friendly for a first visit).

## 1. Roles
| Role | Who | Can |
|---|---|---|
| Platform owner | ClearNAI staff | all orgs, plans, keys, audit, suspend an org |
| Org owner | first person of a company | everything in own org, billing/plan, delete org |
| Org admin | IT / team lead | invite, remove, assign seats, issue/revoke licences, view usage |
| Member (agent) | end user | sign in to the app, see own devices, request a licence |

## 2. Flows
1. **Company sign-up**: company name, work email, password -> email verification link -> org created with a 14-day
   trial (5 seats) -> owner is asked (not forced) to turn on 2FA.
2. **Invite people**: admin enters emails or uploads a CSV -> each gets an invite link (expires in 7 days) -> they set
   a password, or sign in with company SSO.
3. **Sign in (portal)**: email + password; 2FA code only if the user turned it on (owners/admins strongly nudged).
   Lockout after 5 failures, "forgot password" by email link, session list with "sign out everywhere".
4. **Sign in (desktop app)**: the app opens the browser (device-code / loopback login), user signs in once, the
   server returns a device-bound licence token for that PC. Offline afterwards until expiry; refreshed silently
   when online. This replaces copy/paste of Device Codes for normal users (paste/`.lic` stays for air-gapped desks).
5. **Seats and devices**: plan gives N seats; a seat = one user; each user has up to D devices (default 1 for agents).
   Moving PC = user signs in on the new PC, admin approves or the old device is released from the portal.
6. **Revoke / leave**: admin removes a user -> licences revoked, no refresh; offline copy ends at its expiry.
7. **Plans**: Trial, Team, Enterprise. Seats, features (nc, bvc, accent), device limit, token lifetime per plan.
   Billing is a later phase (Stripe/Razorpay); manual invoicing first.
8. **Enterprise SSO** (later phase): SAML/OIDC per org (Okta, Azure AD, Google Workspace) + SCIM-style deprovisioning.

## 3. Screens (all branded)
Public: landing/sign-in, sign-up, verify email, forgot/reset password, accept invite.
Org: Dashboard (active seats, devices online, licences expiring, usage minutes), People (invite, roles, status,
search, CSV import/export), Devices (per user, release), Licences (issue, renew, revoke, download `.lic`), Plan &
seats, Security (2FA, SSO, session policy, allowed email domains), Audit log (filter/export), Settings (org name, logo).
Platform owner: Organisations, plans, impersonation-free support view, key status, system audit.
Profile: name, avatar, password, 2FA, my devices, my sessions.

## 4. Branding / UI
Design tokens from the app: ClearNAI colours, logo, Inter/Segoe font, light + dark themes, 8-px spacing, cards,
empty states, toasts, responsive down to phones. Same wording as the app (Profile, Device Code, Noise reduction).
Per-org logo on the invite and sign-in pages. Server-rendered Jinja + HTMX (no JS build), accessible forms.

## 5. Backend work (FastAPI, SQLAlchemy 2, Alembic)
New tables: `orgs` (+plan, seats, status, domain list), `memberships` (user, org, role), `invites`, `email_tokens`
(verify/reset), `sessions`, `devices`, `plans`, `app_logins` (device-code flow), `settings`. Existing `licenses`,
`audit_log` kept; licences now link to a device row.
New endpoints: `/v1/signup`, `/v1/verify`, `/v1/password/forgot|reset`, `/v1/invites`, `/v1/me`,
`/v1/app/login/start|poll|exchange`, `/v1/app/refresh`, `/v1/devices`, `/v1/seats`, `/v1/orgs/{id}/export`.
Email: SMTP/provider behind an interface (console backend for dev so links print in the terminal).
Security: argon2, per-IP and per-account rate limits, CSRF, secure cookies, 2FA optional with recovery codes, signed
audit trail, no tokens in logs, key in KMS/HSM or encrypted file, tenant isolation tests (an admin of org A can never
see org B).
Database: SQLite for dev/tests, PostgreSQL for production (`LICSRV_DATABASE_URL`), Alembic migrations, nightly backup.

## 6. App (Rust) work
"Sign in" button on the Profile page -> opens browser -> polls the server -> stores the token (DPAPI) -> shows org name,
plan, seat status. Offline grace: keeps working until token expiry, silent refresh when online, clear message when
revoked/expired. Keep paste/`.lic` import for offline desks. Add TLS HTTP client with pinned server name; the
signing public key stays built-in.

## 7. Phases
1. **Foundations (week 1)**: branding + new layout, optional 2FA, forgot/reset password, email interface, org/membership
   model, migrations, roles + tenant-isolation tests.
2. **People (week 2)**: company sign-up + verification, invites, CSV import, People/Devices/Plan pages.
3. **App sign-in (week 3)**: device-code login endpoints, Rust login flow, refresh, seats and device limits.
4. **Production (week 4)**: PostgreSQL + Docker compose + TLS proxy, backups, monitoring, rate limits, runbook, privacy
   notice, code-signed installer.
5. **Later**: SSO (SAML/OIDC), billing, usage analytics, admin audit export to SIEM, multi-region.

## 8. Decisions I need from you
1. Hosting target (own VM, AWS, Azure, Render) and domain name — needed for email links and TLS.
2. Email provider (SMTP, SendGrid, SES) for verification and invites.
3. Self-service company sign-up, or invite-only by ClearNAI staff at first? (Invite-only is safer for v1.)
4. Pricing model (per seat per month?) and whether payments are in scope for v1.
5. Is 2FA required for admins (recommended) or optional?

## 9. Risks
Email deliverability and spoofing (SPF/DKIM), account takeover (rate limits, 2FA, session revoke), a patched app can
skip checks (cannot be fully prevented; sign the installer), personal data (names, emails, device hashes: privacy
notice, retention, DPDP/GDPR), signing-key custody, offline revocation delay (short expiry), cost of SSO support.
