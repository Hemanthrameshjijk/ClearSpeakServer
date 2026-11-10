"""Token v1 and Device Code: the exact formats the ClearNAI app (Rust, `crates/license`) verifies.

Token:       CLNAI1.<base64url payload>.<base64url signature>      (no padding)
Payload:     compact JSON, signed as the exact bytes carried in the token (no canonicalisation needed)
Device Code: base32 of the truncated hash of each hardware component, grouped 4-4-4-...  (see docs/token-spec.md)
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "CLNAI1."
FEATURES = ("nc", "bvc", "accent")

# Order matters: index in the Device Code and in the token's `dev` list.
COMPONENTS = ("guid", "bios", "cpu", "disk")
STRONG = frozenset({0, 1, 3})  # guid, bios, disk can identify a PC on their own; the CPU id is shared by identical models
REQUIRED_COMPONENTS = 3  # guid, bios, cpu; disk is optional
HASH_BYTES = 5  # 40 bits per component = 8 base32 characters


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def component_hash(name: str, raw: str | None) -> str:
    """8-character base32 hash of one hardware value. Missing or placeholder values give the UNKNOWN hash."""
    value = (raw or "").strip().lower()
    if value in PLACEHOLDERS:
        value = "unknown"
    digest = hashlib.sha256(f"clearnai-device-v1|{name}|{value}".encode("utf-8")).digest()[:HASH_BYTES]
    return base64.b32encode(digest).decode("ascii")


# Values some PC makers leave in the BIOS; they identify nothing, so they are treated as unknown.
PLACEHOLDERS = frozenset(
    {"", "unknown", "none", "n/a", "na", "default string", "to be filled by o.e.m.", "system serial number", "0", "123456789", "0123456789", "00000000", "ffffffff", "not specified", "not applicable"}
)


def unknown_hash(name: str) -> str:
    return component_hash(name, "unknown")


def make_device_code(components: dict[str, str | None]) -> str:
    """The Device Code the app shows: guid, bios, cpu (and disk if present), 8 characters each, grouped in fours."""
    names = [n for n in COMPONENTS if n != "disk" or components.get("disk") is not None]
    flat = "".join(component_hash(n, components.get(n)) for n in names)
    return "-".join(flat[i : i + 4] for i in range(0, len(flat), 4))


_CODE_RE = re.compile(r"^[A-Z2-7]{24}([A-Z2-7]{8})?$")


class DeviceCodeError(ValueError):
    pass


def parse_device_code(code: str) -> list[str]:
    """Device Code -> list of 3 (or 4) component hashes. Raises DeviceCodeError if it is not a valid code."""
    flat = re.sub(r"[\s-]+", "", code).upper()  # however it was typed: with dashes, spaces or none
    if not _CODE_RE.match(flat):
        raise DeviceCodeError("That is not a valid Device Code (it has 24 or 32 letters and digits in groups of four).")
    parts = [flat[i : i + 8] for i in range(0, len(flat), 8)]
    if parts[0] == unknown_hash("guid"):
        raise DeviceCodeError("This Device Code has no machine ID, so it cannot identify the PC. Ask for a new code.")
    return parts


def match_devices(token_devs: list[str], current: list[str], minimum: int) -> bool:
    """At least `minimum` components agree, and at least one of them is a strong one. Unknown components never match."""
    matches = 0
    strong = 0
    for i, (a, b) in enumerate(zip(token_devs, current)):
        if a == b and a != unknown_hash(COMPONENTS[i]):
            matches += 1
            if i in STRONG:
                strong += 1
    return matches >= minimum and strong >= 1


@dataclass
class Payload:
    lid: str
    org: str
    uid: str
    name: str
    dev: list[str]
    feat: list[str]
    iat: int
    exp: int
    min: int = 2
    v: int = 1

    def to_bytes(self) -> bytes:
        d = {
            "v": self.v, "lid": self.lid, "org": self.org, "uid": self.uid, "name": self.name,
            "dev": self.dev, "min": self.min, "feat": self.feat, "iat": self.iat, "exp": self.exp,
        }
        return json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def build_token(payload: Payload, sign) -> str:
    """`sign` is a callable bytes -> 64-byte Ed25519 signature (a KeyProvider.sign)."""
    body = payload.to_bytes()
    return f"{PREFIX}{b64e(body)}.{b64e(sign(body))}"


class TokenError(ValueError):
    pass


def verify_token(token: str, public_key: bytes, current_devices: list[str], now: int) -> Payload:
    """Reference verifier (the app has the Rust twin). Raises TokenError with the reason."""
    t = token.strip()
    if not t.startswith(PREFIX) or t.count(".") != 2:
        raise TokenError("malformed")
    _, body_b64, sig_b64 = t.split(".")
    try:
        body, sig = b64d(body_b64), b64d(sig_b64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, body)
    except (InvalidSignature, ValueError):
        raise TokenError("bad signature") from None
    d = json.loads(body)
    if d.get("v") != 1:
        raise TokenError("unsupported version")
    p = Payload(lid=d["lid"], org=d["org"], uid=d["uid"], name=d["name"], dev=d["dev"], feat=d["feat"], iat=d["iat"], exp=d["exp"], min=d["min"])
    if now < p.iat - 86400:
        raise TokenError("not yet valid")
    if now >= p.exp:
        raise TokenError("expired")
    if not match_devices(p.dev, current_devices, p.min):
        raise TokenError("wrong device")
    return p
