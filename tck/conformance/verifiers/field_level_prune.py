"""Verifier command for the card-sign runner: the ``field-level-prune`` reading, no SDK imported.

    python tck/conformance/verifiers/field_level_prune.py CARD.json JWKS.json

Exit status 0 means this reading accepts the card's signature, 1 that it refuses. The reading is the one named in
``conformance-vectors/a2a-card-sign-v01/README.md``:

* the covered bytes are the served card without its ``signatures``, with empty field values (``""``, ``[]``, ``{}``)
  removed recursively and array elements kept even when they become empty -- so a card carrying
  ``securityRequirements: [{}]`` is read as served (S1-009) and not as its pruned form (S1-010), which is the pair
  that names this reading;
* RFC 8785 over those bytes;
* unknown fields participate in that field-level pruning; this is not the separate ``unknown-retain`` reading,
  which keeps unknown fields verbatim;
* a card carrying the same schema field under both its JSON name and its protobuf name is refused,
  the reading proposed on a2aproject/A2A#2122.

Nothing is imported from an SDK or from the corpus generator: the covered bytes are built here from the served JSON,
and the signature is checked over exactly those bytes with ``cryptography`` and ``rfc8785``. JSON numbers use the RFC's binary64 input model.
"""

from __future__ import annotations

import base64
import json
import math
import re
import sys

from pathlib import Path

import rfc8785

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def snake(name: str) -> str:
    """The protobuf (snake_case) spelling of a JSON (lowerCamelCase) field name."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


SIG_LEN = 64  # r || s, 32 bytes each, as JWS ES256 spells a signature


def is_empty(value: object) -> bool:
    """True for the three empty values the reading removes: ``""``, ``[]`` and ``{}``."""
    return value in ("", [], {})


def prune(node: object) -> object:
    """Remove empty field values recursively. An element of an array is never removed, however it reads."""
    if isinstance(node, dict):
        out = {}
        for key, raw in node.items():
            member = prune(raw)
            if is_empty(member):
                continue
            out[key] = member
        return out
    if isinstance(node, list):
        return [prune(element) for element in node]
    return node


# These schema objects scope alias checks. They do not validate a card or define a new reading.
# Alias checks leave arbitrary extension and Struct member names uninterpreted. Field pruning still applies.
SCHEMAS = {
    name.replace(" ", ""): schema
    for name, schema in json.loads((Path(__file__).resolve().parents[3] / "specification/a2a.json").read_text(encoding="utf-8"))[
        "definitions"
    ].items()
}


def dual_named(node: object, schema: dict | None = None) -> bool:
    """Refuse two spellings of a declared field, preserving arbitrary extension and map names."""
    if schema is None:
        schema = SCHEMAS["AgentCard"]
    if "$ref" in schema:
        schema = SCHEMAS[schema["$ref"].split(".")[-3]]
    if isinstance(node, dict):
        properties = schema.get("properties", {})
        names = {snake(name): name for name in properties}
        if any(name != snake(name) and name in node and snake(name) in node for name in properties):
            return True
        extra = schema.get("additionalProperties")
        for name, value in node.items():
            child = properties.get(name) or properties.get(names.get(name))
            if child is None and isinstance(extra, dict):
                child = extra
            if child is not None and dual_named(value, child):
                return True
    elif isinstance(node, list) and "items" in schema:
        return any(dual_named(value, schema["items"]) for value in node)
    return False


def jcs(node: object) -> bytes:
    """RFC 8785 bytes, including ECMAScript binary64 number serialization."""
    return rfc8785.dumps(node)


def unique_members(pairs: list[tuple[str, object]]) -> dict:
    """Refuse duplicate JSON members before a parser can discard their first values."""
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def finite_number(raw: str) -> float:
    """Parse every JSON number as binary64, refusing nonfinite constants and overflow."""
    number = float(raw)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def load_json(raw: str | bytes) -> object:
    """Parse the JCS input domain without silent member or numeric reinterpretation."""
    value = json.loads(
        raw, object_pairs_hook=unique_members, parse_int=finite_number, parse_float=finite_number, parse_constant=finite_number
    )
    # This also checks strings and keys that the selected reading later prunes or excludes.
    jcs(value)
    return value


def b64u(value: str) -> bytes:
    """Base64url-decode without padding, as JWS spells its parts."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verifies(jwk: dict, protected: str, payload: bytes, signature: str) -> bool:
    """ES256 over ``protected.payload`` with the JWK's P-256 public key."""
    try:
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u(jwk["x"]), "big"), int.from_bytes(b64u(jwk["y"]), "big"), ec.SECP256R1()
        ).public_key()
        raw = b64u(signature)
        if len(raw) != SIG_LEN:
            return False
        signing_input = (protected + "." + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()).encode("utf-8")
        public.verify(
            utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:  # any failure to verify is a refusal
        return False


def verify_card(card_path: str, jwks_path: str) -> int:
    """Return 0 if a signature on the served card verifies over the bytes this reading covers, else 1."""
    card = load_json(Path(card_path).read_text(encoding="utf-8"))
    if not isinstance(card, dict):
        return 1
    if dual_named(card):
        return 1
    covered = prune({key: value for key, value in card.items() if key != "signatures"})
    payload = jcs(covered)
    jwks = load_json(Path(jwks_path).read_text(encoding="utf-8"))
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return 1
    keys = [key for key in jwks["keys"] if isinstance(key, dict)]
    for signature in card.get("signatures") or []:
        try:
            if not isinstance(signature, dict):
                continue
            header = load_json(b64u(signature["protected"]))
            if not isinstance(header, dict):
                continue
        except Exception:
            continue
        if header.get("alg") != "ES256":
            continue
        jwk = next((key for key in keys if key.get("kid") == header.get("kid")), None)
        if jwk is not None and verifies(jwk, signature["protected"], payload, signature["signature"]):
            return 0
    return 1


def main(card_path: str, jwks_path: str) -> int:
    """Return a refusal for invalid inputs while keeping the verifier command's 0/1 contract."""
    try:
        return verify_card(card_path, jwks_path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
