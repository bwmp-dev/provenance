from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "attestation/v1/schema.json").read_text(encoding="utf-8"))
FIXTURES = ROOT / "fixtures/attestation"
DOMAIN = b"Provenance Attestation v1\n"


def canonicalize(value) -> bytes:
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, float):
        raise TypeError("attestation v1 does not permit floating-point numbers")
    if isinstance(value, list):
        return b"[" + b",".join(canonicalize(item) for item in value) + b"]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda item: item.encode("utf-16-be"))
        members = (
            canonicalize(key) + b":" + canonicalize(value[key])
            for key in keys
        )
        return b"{" + b",".join(members) + b"}"
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def signing_input(document: dict) -> bytes:
    return (
        DOMAIN
        + document["signature"]["keyId"].encode("utf-8")
        + b"\n"
        + canonicalize(document["statement"])
    )


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def set_path(document, path, value):
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

    valid_paths = sorted((FIXTURES / "valid").glob("*.json"))
    valid_documents = {}
    for path in valid_paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        errors = list(validator.iter_errors(document))
        if errors:
            raise AssertionError(f"valid fixture {path.name} failed: {errors[0].message}")
        valid_documents[path.name] = document

    cases = json.loads((FIXTURES / "invalid/cases.json").read_text(encoding="utf-8"))
    for case in cases:
        document = copy.deepcopy(valid_documents["hosted.json"])
        set_path(document, case["path"], case["value"])
        errors = list(validator.iter_errors(document))
        expected_path = list(case["errorPath"])
        if not any(
            error.validator == case["validator"] and list(error.absolute_path) == expected_path
            for error in errors
        ):
            rendered = [(error.validator, list(error.absolute_path), error.message) for error in errors]
            raise AssertionError(f"invalid fixture {case['name']!r} did not fail as expected: {rendered}")

    vector_paths = sorted((FIXTURES / "vectors").glob("*.json"))
    for vector_path in vector_paths:
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        fixture_path = (vector_path.parent / vector["fixture"]).resolve()
        document = json.loads(fixture_path.read_text(encoding="utf-8"))
        canonical = canonicalize(document["statement"])
        payload = signing_input(document)
        signature = decode_base64url(vector["signatureBase64Url"])

        if hashlib.sha256(canonical).hexdigest() != vector["canonicalStatementSha256"]:
            raise AssertionError(f"canonical statement changed for {vector_path.name}")
        if hashlib.sha256(payload).hexdigest() != vector["signingInputSha256"]:
            raise AssertionError(f"signing input changed for {vector_path.name}")
        if document["signature"]["value"] != vector["signatureBase64Url"]:
            raise AssertionError(f"fixture signature differs from {vector_path.name}")
        if base64.urlsafe_b64encode(signature).rstrip(b"=").decode() != vector["signatureBase64Url"]:
            raise AssertionError(f"non-canonical base64url signature in {vector_path.name}")

        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["privateKeySeedHex"]))
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vector["publicKeyHex"]))
        if private_key.public_key().public_bytes_raw().hex() != vector["publicKeyHex"]:
            raise AssertionError(f"private/public key mismatch in {vector_path.name}")
        if private_key.sign(payload) != signature:
            raise AssertionError(f"deterministic signature changed for {vector_path.name}")
        public_key.verify(signature, payload)

        tampered = copy.deepcopy(document)
        tampered["statement"]["subject"]["sizeBytes"] += 1
        try:
            public_key.verify(signature, signing_input(tampered))
        except InvalidSignature:
            pass
        else:
            raise AssertionError(f"tampering was not detected for {vector_path.name}")

        relabeled = copy.deepcopy(document)
        relabeled["signature"]["keyId"] += "-rotated"
        try:
            public_key.verify(signature, signing_input(relabeled))
        except InvalidSignature:
            pass
        else:
            raise AssertionError(f"key ID relabeling was not detected for {vector_path.name}")

    print(f"validated {len(valid_paths)} valid attestation fixtures")
    print(f"rejected {len(cases)} invalid attestation fixtures")
    print(f"reproduced and verified {len(vector_paths)} Ed25519 vectors")


if __name__ == "__main__":
    main()
