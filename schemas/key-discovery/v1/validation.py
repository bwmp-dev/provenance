"""Offline reference contract checks; never discovers or trusts a key origin."""

import base64
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator


SCHEMA = json.loads(Path(__file__).with_name("schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
MAX_DOCUMENT_BYTES = 1024 * 1024


def _members(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid key discovery document")
        value[key] = item
    return value


def _invalid_constant(_):
    raise ValueError("invalid key discovery document")


def validate(raw: bytes) -> dict:
    """Return a new parsed snapshot; all failures have static, non-secret text."""
    try:
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError()
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(text, object_pairs_hook=_members, parse_constant=_invalid_constant)
        VALIDATOR.validate(document)
        seen = set()
        for key in document["keys"]:
            identifier = key["keyId"]
            if identifier in seen or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/#-]*", identifier) is None:
                raise ValueError()
            seen.add(identifier)
            encoded = key["publicKey"]
            decoded = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
            if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != encoded:
                raise ValueError()
        return document
    except Exception:
        raise ValueError("invalid key discovery document") from None


def validate_transition(previous: bytes, following: bytes) -> dict:
    """Check continuity relative to caller-trusted previous bytes, not trust."""
    old, new = validate(previous), validate(following)
    indexed = {key["keyId"]: key for key in new["keys"]}
    for key in old["keys"]:
        next_key = indexed.get(key["keyId"])
        if (next_key is None or key["publicKey"] != next_key["publicKey"]
                or key["algorithm"] != next_key["algorithm"]
                or (key["status"] == "retired" and next_key["status"] != "retired")):
            raise ValueError("invalid key discovery transition")
    return new
