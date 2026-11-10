# ClearNAI token v1 and Device Code

This file is the contract between this server (Python, `licsrv/tokens.py`) and the app (Rust, `crates/license`).
`tests/vectors.json` holds fixed tokens signed with a test-only key; both sides check their verifier against it.

## Device Code (what the app shows, what the admin pastes)

Hardware values read on the PC: `guid` (Windows MachineGuid), `bios` (BIOS/board serial), `cpu` (processor id),
optional `disk` (system disk serial). Each is lower-cased and trimmed; placeholder values ("To be filled by O.E.M.",
"Default string", empty, ...) become `unknown`. Then:

    h(name, value) = first 5 bytes of SHA-256("clearnai-device-v1|" + name + "|" + value)
    component text = base32 (RFC 4648, no padding) of h  -> 8 characters

The Device Code is the component texts joined in the order guid, bios, cpu[, disk] (24 or 32 characters), shown in
groups of four separated by dashes. Parsing ignores dashes, spaces and case. Raw serial numbers are never sent or stored.
A code whose `guid` part is the `unknown` hash is refused.

## Token

    CLNAI1.<base64url(payload)>.<base64url(signature)>        (no padding)

`payload` is compact UTF-8 JSON with sorted keys; the signature is Ed25519 over exactly those bytes. The verifier
checks the signature over the received bytes first, and only then parses.

| key | meaning |
|---|---|
| `v` | format version, 1 |
| `lid` | license id (uuid) |
| `org`, `uid` | organisation and user ids |
| `name` | the user's name, shown in the app |
| `dev` | component texts (3 or 4, same order as the Device Code) |
| `min` | how many components must match (2) |
| `feat` | features switched on: `nc`, `bvc`, `accent` |
| `iat`, `exp` | issued and expiry, unix seconds |

## Verification (both implementations)

1. Prefix and shape. 2. Signature with the public key built into the app. 3. `v == 1`.
4. `now >= iat - 86400` (one day of clock skew allowed), otherwise "not yet valid".
5. `now < exp`, otherwise "expired".
6. Device match: count components equal to the current PC's (an `unknown` component never matches);
   need at least `min` matches and at least one *strong* match (guid, bios or disk; the CPU id alone is not enough
   because identical PC models share it).

## Known limits

* A patched app can skip all of this; code signing and integrity checks raise the effort, they do not remove it.
* Revocation offline only happens at renewal; keep `exp` short (30-90 days).
* The clock guard in the app is a deterrent: a user who rolls the clock back and deletes its marker defeats it.
