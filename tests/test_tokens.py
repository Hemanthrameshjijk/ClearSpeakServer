import json
from pathlib import Path

import pytest

from licsrv import keys, tokens

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text(encoding="utf-8"))
PK = bytes.fromhex(VECTORS["public_key_hex"])


def test_device_code_shape_and_round_trip():
    comps = VECTORS["components"]["pc_a"]
    code = tokens.make_device_code(comps)
    assert len(code) == 24 + 5 + 8 + 1 or len(code.replace("-", "")) in (24, 32)
    parts = tokens.parse_device_code(code)
    assert len(parts) == 4  # guid, bios, cpu, disk
    no_disk = tokens.make_device_code({**comps, "disk": None})
    assert len(tokens.parse_device_code(no_disk)) == 3
    assert tokens.parse_device_code(code.lower().replace("-", " ")) == parts  # tolerant of how it was typed


@pytest.mark.parametrize("bad", ["", "hello", "ABCD-EFGH", "1111-1111-1111-1111-1111-1111", "ABCD-EFGH-IJKL-MNOP-QRST-UVW"])
def test_bad_device_codes_are_refused(bad):
    with pytest.raises(tokens.DeviceCodeError):
        tokens.parse_device_code(bad)


def test_a_code_without_a_machine_id_is_refused():
    code = tokens.make_device_code({"guid": "", "bios": "SN1", "cpu": "C1"})
    with pytest.raises(tokens.DeviceCodeError):
        tokens.parse_device_code(code)


def test_placeholder_values_are_treated_as_unknown():
    assert tokens.component_hash("bios", "To Be Filled By O.E.M.") == tokens.unknown_hash("bios")
    assert tokens.component_hash("bios", " DEFAULT STRING ") == tokens.unknown_hash("bios")
    assert tokens.component_hash("bios", "SN-1") != tokens.unknown_hash("bios")


def test_matching_needs_two_components_and_one_strong():
    a = tokens.parse_device_code(tokens.make_device_code({"guid": "g1", "bios": "b1", "cpu": "c1"}))
    cpu_only_same = tokens.parse_device_code(tokens.make_device_code({"guid": "g2", "bios": "b2", "cpu": "c1"}))
    guid_and_cpu = tokens.parse_device_code(tokens.make_device_code({"guid": "g1", "bios": "b9", "cpu": "c1"}))
    guid_only = tokens.parse_device_code(tokens.make_device_code({"guid": "g1", "bios": "b9", "cpu": "c9"}))
    assert tokens.match_devices(a, a, 2)
    assert tokens.match_devices(a, guid_and_cpu, 2)
    assert not tokens.match_devices(a, cpu_only_same, 2), "a shared CPU model alone must not match"
    assert not tokens.match_devices(a, guid_only, 2), "one component is not enough"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_reference_verifier_agrees_with_the_shared_vectors(case):
    if case["expect"] == "ok":
        assert tokens.verify_token(case["token"], PK, case["current"], case["now"]).name
    else:
        with pytest.raises(tokens.TokenError) as e:
            tokens.verify_token(case["token"], PK, case["current"], case["now"])
        assert str(e.value) == case["expect"]


def test_token_size_is_pasteable():
    good = VECTORS["cases"][0]["token"]
    assert 250 <= len(good) <= 500, len(good)


def test_encrypted_key_file_round_trip(tmp_path):
    path = tmp_path / "k.key"
    pk = keys.write_encrypted_key(path, "a long enough passphrase")
    provider = keys.load_encrypted_key(path, "a long enough passphrase")
    assert provider.public_key() == pk
    sig = provider.sign(b"hello")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    Ed25519PublicKey.from_public_bytes(pk).verify(sig, b"hello")
    with pytest.raises(Exception):
        keys.load_encrypted_key(path, "the wrong passphrase!!")
    with pytest.raises(FileExistsError):
        keys.write_encrypted_key(path, "a long enough passphrase")
    with pytest.raises(ValueError):
        keys.write_encrypted_key(tmp_path / "short.key", "short")
