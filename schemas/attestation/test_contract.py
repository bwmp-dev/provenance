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


def check_v2_contract() -> None:
    schema = json.loads((ROOT / "attestation/v2/schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    # Freeze the precise versioned delta, rather than accidentally loosening
    # unrelated subject/source/environment/key constraints while copying v1.
    expected = copy.deepcopy(SCHEMA)
    expected["$id"] = "https://schemas.provenance.dev/attestation/v2/schema.json"
    expected["title"] = "Provenance attestation envelope v2"
    expected["properties"]["mediaType"]["const"] = "application/vnd.provenance.attestation.v2+json"
    expected["$defs"]["statement"]["properties"]["apiVersion"]["const"] = "provenance.dev/attestation/v2"
    expected["$defs"]["assertion"]["properties"]["type"]["enum"].append("console-contains")
    expected["$defs"]["assertion"]["properties"]["id"] = {
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]*(?![\s\S])",
    }
    assert schema == expected, "unexpected v2 contract change"
    document = json.loads((FIXTURES / "valid/hosted.json").read_text(encoding="utf-8"))
    assert not validator.is_valid(document), "v1 envelope admitted as v2"
    document["mediaType"] = "application/vnd.provenance.attestation.v2+json"
    document["statement"]["apiVersion"] = "provenance.dev/attestation/v2"
    literal = document["statement"]["assertions"][2]
    literal["type"] = "console-contains"
    literal["id"] = "console-contains:smoke:0"
    validator.validate(document)
    assert not Draft202012Validator(SCHEMA).is_valid(document)
    for path, value in [
        (["mediaType"], "application/vnd.provenance.attestation.v1+json"),
        (["statement", "apiVersion"], "provenance.dev/attestation/v1"),
        (["statement", "assertions", 2, "type"], "console-default"),
        (["statement", "assertions", 2, "id"], "literal\n"),
        (["statement", "assertions", 2, "id"], "literal/unsafe"),
        (["statement", "assertions", 2, "id"], "a" * 129),
        (["statement", "assertions", 2, "pattern"], "private-pattern"),
    ]:
        invalid = copy.deepcopy(document)
        set_path(invalid, path, value)
        assert not validator.is_valid(invalid), (path, value)
    vector = json.loads((FIXTURES / "vectors/hosted.json").read_text(encoding="utf-8"))
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["privateKeySeedHex"]))
    body = document["signature"]["keyId"].encode() + b"\n" + canonicalize(document["statement"])
    payload = b"Provenance Attestation v2\n" + body
    signature = private.sign(payload)
    private.public_key().verify(signature, payload)
    try:
        private.public_key().verify(signature, DOMAIN + body)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("v2 signature admitted in v1 domain")
    golden = json.loads((FIXTURES / "interop/small-artifact-v2.json").read_text(encoding="utf-8"))
    validator.validate(golden["document"])
    canonical = canonicalize(golden["document"]["statement"])
    assert canonical.decode() == golden["canonicalStatement"]
    assert hashlib.sha256(canonical).hexdigest() == golden["canonicalStatementSha256"]
    payload = b"Provenance Attestation v2\n" + golden["document"]["signature"]["keyId"].encode() + b"\n" + canonical
    assert hashlib.sha256(payload).hexdigest() == golden["signingInputSha256"]
    signature = decode_base64url(golden["signatureBase64Url"])
    assert golden["document"]["signature"]["value"] == golden["signatureBase64Url"]
    assert private.sign(payload) == signature
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(golden["publicKeyHex"])).verify(signature, payload)
    artifact = bytes.fromhex(golden["artifactHex"])
    assert len(artifact) == golden["document"]["statement"]["subject"]["sizeBytes"]
    assert hashlib.sha256(artifact).hexdigest() == golden["document"]["statement"]["subject"]["digest"]["value"]
    print("validated v2 literal schema, separate domain and shared Go/JS/Python golden")


def main() -> None:
    check_v2_contract()
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    version_validator = Draft202012Validator(SCHEMA["$defs"]["minecraftVersion"])
    for version in ["1.20.6", "1.21", "26.1", "26.1.2", "26.12.0"]:
        assert version_validator.is_valid(version), version
    for version in ["26.0", "26.01", "26.1-rc1", "27.1", "latest"]:
        assert not version_validator.is_valid(version), version


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
