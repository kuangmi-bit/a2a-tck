"""Independent RFC 8785 and signed input controls for the field-level reader."""

from __future__ import annotations

import base64
import json
import struct

from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from tck.conformance.verifiers import field_level_prune as reader


if TYPE_CHECKING:
    from pathlib import Path


Sign = Callable[..., tuple[dict, dict]]


# RFC 8785 Appendix B: exact IEEE754 inputs, not decimal values rounded by a parser.
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("7fffffffffffffff", ""),
    ("7ff0000000000000", ""),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize(("bits", "expected"), APPENDIX_B)
def test_appendix_b(bits: str, expected: str) -> None:
    """Match every exact binary64 sample or domain refusal from RFC 8785 Appendix B."""
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    if not expected:
        with pytest.raises(ValueError):
            reader.jcs(value)
    else:
        assert reader.jcs(value) == expected.encode()


def b64(data: bytes) -> str:
    """Encode bytes in the unpadded base64url form used by JWS."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture
def sign() -> Sign:
    # Public disposable scalar. This key has no operational authority.
    """Create valid ES256 signatures with a disposable public test key."""
    key = ec.derive_private_key(1, ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "control",
        "x": b64(numbers.x.to_bytes(32, "big")),
        "y": b64(numbers.y.to_bytes(32, "big")),
    }
    protected = b64(b'{"alg":"ES256","kid":"control"}')

    def make(payload: bytes, header: str = protected) -> tuple[dict, dict]:
        data = (header + "." + b64(payload)).encode()
        r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        signature = {"protected": header, "signature": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}
        return signature, {"keys": [jwk]}

    return make


def run(tmp_path: Path, card: object, jwks: object) -> int:
    """Write supplied inputs and get the public verifier command outcome."""
    card_path, jwks_path = tmp_path / "card.json", tmp_path / "jwks.json"
    card_path.write_text(card if isinstance(card, str) else json.dumps(card), encoding="utf-8")
    jwks_path.write_text(jwks if isinstance(jwks, str) else json.dumps(jwks), encoding="utf-8")
    return reader.main(str(card_path), str(jwks_path))


@pytest.mark.parametrize(("value", "encoded"), [(1.0, "1"), (-0.0, "0"), (1e-6, "0.000001"), (1e20, "100000000000000000000")])
def test_signed_number_and_postsign_change(tmp_path: Path, sign: Sign, value: float, encoded: str) -> None:
    """Accept correctly canonicalized signed numbers and refuse a changed signed field."""
    signature, jwks = sign(('{"name":"control","x":' + encoded + "}").encode())
    card = {"name": "control", "x": value, "signatures": [signature]}
    assert run(tmp_path, card, jwks) == 0
    card["name"] = "changed"
    assert run(tmp_path, card, jwks) == 1


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_input_refused(tmp_path: Path, sign: Sign, bad: str) -> None:
    """Refuse nonfinite JSON even when a signature covers the invalid encoding."""
    signature, jwks = sign(('{"name":"control","x":' + bad + "}").encode())
    raw = json.dumps({"name": "control", "signatures": [signature]})[:-1] + ', "x":' + bad + "}"
    assert run(tmp_path, raw, jwks) == 1


def test_duplicate_card_member_refused_with_valid_control(tmp_path: Path, sign: Sign) -> None:
    """Refuse duplicate names while preserving the valid single-member control."""
    signature, jwks = sign(b'{"name":"control","x":1}')
    raw = json.dumps({"name": "control", "x": 1, "signatures": [signature]})
    assert run(tmp_path, raw, jwks) == 0
    assert run(tmp_path, raw.replace('"x": 1', '"x": 2, "x": 1'), jwks) == 1


def test_duplicate_protected_member_refused(tmp_path: Path, sign: Sign) -> None:
    """Refuse a signed protected header with duplicate algorithm members."""
    header = b64(b'{"alg":"other","alg":"ES256","kid":"control"}')
    signature, jwks = sign(b'{"name":"control"}', header)
    assert run(tmp_path, {"name": "control", "signatures": [signature]}, jwks) == 1


def test_duplicate_jwks_member_refused(tmp_path: Path, sign: Sign) -> None:
    """Refuse duplicate key names before key selection discards their first values."""
    signature, jwks = sign(b'{"name":"control"}')
    raw = json.dumps(jwks).replace('"kid": "control"', '"kid": "other", "kid": "control"')
    assert run(tmp_path, {"name": "control", "signatures": [signature]}, raw) == 1


@pytest.mark.parametrize("card", [None, True, [], 1, "bad", "{", {"name": "\ud800"}])
def test_invalid_card_input_returns_refusal(tmp_path: Path, card: object) -> None:
    """Return the documented refusal for malformed card values."""
    assert run(tmp_path, card, {"keys": []}) == 1


@pytest.mark.parametrize("jwks", [None, [], {}, {"keys": None}, {"keys": "bad"}, {"keys": [None]}])
def test_invalid_jwks_returns_refusal(tmp_path: Path, sign: Sign, jwks: object) -> None:
    """Return the documented refusal for malformed key-set values."""
    signature, _ = sign(b'{"name":"control"}')
    assert run(tmp_path, {"name": "control", "signatures": [signature]}, jwks) == 1


def test_utf16_order_pruning_and_array_element_retention() -> None:
    """Preserve UTF16 member order, false and zero values, and empty array elements."""
    assert reader.jcs({"\ue000": 1, "\U00010000": 2}) == '{"\U00010000":2,"\ue000":1}'.encode()
    assert reader.prune({"a": "", "b": [{"a": ""}, [], ""], "c": False, "d": 0}) == {"b": [{}, [], ""], "c": False, "d": 0}


def test_malformed_and_wrong_algorithm_signature_refused(tmp_path: Path, sign: Sign) -> None:
    """Skip malformed signatures and refuse the wrong algorithm."""
    signature, jwks = sign(b'{"name":"control"}')
    card = {"name": "control", "signatures": [None, {}, {"protected": "%%%"}, signature]}
    assert run(tmp_path, card, jwks) == 0
    signature["protected"] = b64(b'{"alg":"HS256","kid":"control"}')
    assert run(tmp_path, card, jwks) == 1


def test_bad_signature_and_key_refused(tmp_path: Path, sign: Sign) -> None:
    """Refuse invalid raw signature length and public key coordinates."""
    signature, jwks = sign(b'{"name":"control"}')
    signature["signature"] = b64(b"short")
    assert run(tmp_path, {"name": "control", "signatures": [signature]}, jwks) == 1
    signature, jwks = sign(b'{"name":"control"}')
    jwks["keys"][0]["x"] = b64(b"short")
    assert run(tmp_path, {"name": "control", "signatures": [signature]}, jwks) == 1


def test_missing_file_returns_refusal(tmp_path: Path) -> None:
    """Return the documented refusal when an input file cannot be read."""
    assert reader.main(str(tmp_path / "missing-card"), str(tmp_path / "missing-jwks")) == 1


@pytest.mark.parametrize(
    "card",
    [
        {"myFlag": True, "my_flag": True},
        {"capabilities": {"extensions": [{"uri": "urn:test", "params": {"bearerFormat": "a", "bearer_format": "b"}}]}},
        {"unknown": [{"inputModes": ["a"], "input_modes": ["b"]}]},
        {"securitySchemes": {"schemeOne": {}, "scheme_one": {}}},
    ],
)
def test_arbitrary_extension_and_map_names_are_not_schema_aliases(tmp_path: Path, sign: Sign, card: dict) -> None:
    """Preserve arbitrary extension and map names and still detect a changed signed field."""
    signature, jwks = sign(reader.jcs(reader.prune(card)))
    served = {**card, "signatures": [signature]}
    assert run(tmp_path, served, jwks) == 0
    served["changed"] = True
    assert run(tmp_path, served, jwks) == 1


@pytest.mark.parametrize(
    "card",
    [
        {"defaultInputModes": ["a"], "default_input_modes": ["b"]},
        {"skills": [{"inputModes": ["a"], "input_modes": ["b"]}]},
        {"securitySchemes": {"a": {"httpAuthSecurityScheme": {"bearerFormat": "a", "bearer_format": "b"}}}},
        {"supported_interfaces": [{"protocolBinding": "JSONRPC", "protocol_binding": "GRPC"}]},
        {"capabilities": {"pushNotifications": False, "push_notifications": False}},
        {"capabilities": {"extendedAgentCard": False, "extended_agent_card": False}},
    ],
)
def test_actual_schema_aliases_refused_even_when_signed(tmp_path: Path, sign: Sign, card: dict) -> None:
    """Refuse actual schema aliases at top level and in repeated, map, and nested fields."""
    signature, jwks = sign(reader.jcs(reader.prune(card)))
    assert run(tmp_path, {**card, "signatures": [signature]}, jwks) == 1


@pytest.mark.parametrize(
    "card",
    [
        {"defaultInputModes": ["a"]},
        {"default_input_modes": ["a"]},
        {"skills": [{"input_modes": ["a"]}]},
        {"security_schemes": {"a": {"http_auth_security_scheme": {"bearer_format": "a"}}}},
    ],
)
def test_existing_single_spelling_contract_preserved(tmp_path: Path, sign: Sign, card: dict) -> None:
    """Preserve each already supported single spelling without normalizing the signed bytes."""
    signature, jwks = sign(reader.jcs(reader.prune(card)))
    assert run(tmp_path, {**card, "signatures": [signature]}, jwks) == 0
