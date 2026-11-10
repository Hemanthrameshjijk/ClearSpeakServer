"""Writes tests/vectors.json: fixed tokens signed with a TEST-ONLY key, plus what a correct verifier must answer.
The ClearNAI app repo copies this file and checks its Rust verifier against it (interop test). Re-run only when the
token format changes. The seed below is public and must never be used for real licenses."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from licsrv import keys, tokens  # noqa: E402

SEED = bytes(range(32))  # TEST ONLY
NOW = 1_800_000_000

provider = keys.from_seed(SEED)
pc_a = {"guid": "11111111-aaaa-bbbb-cccc-000000000001", "bios": "SN-A-0001", "cpu": "BFEBFBFF000906EA", "disk": "DISK-A-0001"}
pc_b = {"guid": "22222222-aaaa-bbbb-cccc-000000000002", "bios": "SN-B-0002", "cpu": "BFEBFBFF000906EA", "disk": "DISK-B-0002"}
junk = {"guid": "33333333-aaaa-bbbb-cccc-000000000003", "bios": "To Be Filled By O.E.M.", "cpu": "BFEBFBFF000906EA", "disk": None}


def devs(c):
    return tokens.parse_device_code(tokens.make_device_code(c))


def token(devlist, *, name="Asha Rao", feat=("nc", "bvc", "accent"), iat=NOW - 86400, exp=NOW + 30 * 86400, mn=2, lid="00000000-0000-4000-8000-000000000001"):
    p = tokens.Payload(lid=lid, org="org-1", uid="user-1", name=name, dev=devlist, feat=sorted(feat), iat=iat, exp=exp, min=mn)
    return tokens.build_token(p, provider.sign)


good = token(devs(pc_a))
body = good.split(".")[1]
forged_body = tokens.b64e(tokens.b64d(body).replace(b"Asha Rao", b"Eve Rao!"))
cpu_changed = dict(pc_a, cpu="BFEBFBFF000306C3")  # one of three changed: still a match
two_changed = dict(pc_a, bios="SN-NEW", cpu="BFEBFBFF000306C3")  # only guid + disk left; disk is optional in the 3-part code
cases = []


def case(name, tok, current, expect):
    cases.append({"name": name, "token": tok, "current": current, "now": NOW, "expect": expect})


case("valid on the same PC", good, devs(pc_a), "ok")
case("one component changed still matches", good, devs(cpu_changed), "ok")
case("two components changed is refused", good, devs({k: v for k, v in two_changed.items() if k != "disk"}), "wrong device")
case("another PC with the same CPU model", good, devs(pc_b), "wrong device")
case("expired", token(devs(pc_a), exp=NOW - 1), devs(pc_a), "expired")
case("not yet valid (clock set far back)", token(devs(pc_a), iat=NOW + 10 * 86400, exp=NOW + 40 * 86400), devs(pc_a), "not yet valid")
case("edited name keeps the old signature", good.split(".")[0] + "." + forged_body + "." + good.split(".")[2], devs(pc_a), "bad signature")
case("not a token", "hello", devs(pc_a), "malformed")
case("placeholder BIOS never matches another placeholder PC", token(devs(junk)), devs(dict(pc_b, guid="44444444-aaaa-bbbb-cccc-000000000004", bios="Default string")), "wrong device")
case("placeholder BIOS PC still matches itself via guid + cpu", token(devs(junk)), devs(junk), "ok")

out = {
    "note": "TEST ONLY key. Signed with seed bytes 0..31.",
    "public_key_hex": provider.public_key().hex(),
    "now": NOW,
    "device_codes": {"pc_a": tokens.make_device_code(pc_a), "pc_b": tokens.make_device_code(pc_b), "junk": tokens.make_device_code(junk)},
    "components": {"pc_a": pc_a, "pc_b": pc_b, "junk": junk},
    "cases": cases,
}
Path(__file__).resolve().parent.parent.joinpath("tests", "vectors.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print("wrote tests/vectors.json with", len(cases), "cases")
