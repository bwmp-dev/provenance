import base64
import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

sys.dont_write_bytecode = True

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/key-discovery"
spec = importlib.util.spec_from_file_location("discovery", Path(__file__).parent / "v1/validation.py")
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)
initial = (FIXTURES / "valid/initial.json").read_bytes()
rotated = (FIXTURES / "valid/rotated.json").read_bytes()


def encoded(value):
    return json.dumps(value).encode()


class Contract(unittest.TestCase):
    def test_schema_and_shared_invalid_vectors(self):
        discovery.Draft202012Validator.check_schema(discovery.SCHEMA)
        attestation = json.loads((ROOT / "attestation/v1/schema.json").read_text())
        self.assertEqual(discovery.SCHEMA["properties"]["keys"]["items"]["properties"]["keyId"],
                         attestation["$defs"]["signature"]["properties"]["keyId"])
        for path in (FIXTURES / "valid").glob("*.json"):
            discovery.validate(path.read_bytes())
        for case in json.loads((FIXTURES / "invalid/cases.json").read_text()):
            with self.subTest(case=case["name"]):
                document = json.loads(initial)
                target = document
                for part in case["path"][:-1]:
                    target = target[part]
                target[case["path"][-1]] = case["value"]
                with self.assertRaisesRegex(ValueError, "^invalid key discovery document$"):
                    discovery.validate(encoded(document))

    def test_required_fields_types_bounds_and_duplicates(self):
        original = json.loads(initial)
        for path in [[], ["keys", 0]]:
            for field in (original if not path else original["keys"][0]):
                document = copy.deepcopy(original)
                target = document if not path else document["keys"][0]
                del target[field]
                with self.assertRaises(ValueError):
                    discovery.validate(encoded(document))
        document = copy.deepcopy(original)
        document["keys"].append(copy.deepcopy(document["keys"][0]))
        with self.assertRaises(ValueError):
            discovery.validate(encoded(document))
        document["keys"][1]["publicKey"] = json.loads(rotated)["keys"][1]["publicKey"]
        with self.assertRaises(ValueError):
            discovery.validate(encoded(document))
        for size in [1, 1024, 1025]:
            document = {"version": 1, "keys": [dict(original["keys"][0], keyId=f"key-{n}") for n in range(size)]}
            if size <= 1024:
                discovery.validate(encoded(document))
            else:
                with self.assertRaises(ValueError):
                    discovery.validate(encoded(document))
        for size in [200, 201]:
            document = copy.deepcopy(original)
            document["keys"][0]["keyId"] = "a" * size
            if size == 200:
                discovery.validate(encoded(document))
            else:
                with self.assertRaises(ValueError):
                    discovery.validate(encoded(document))
        for value in [None, [], 1, "text"]:
            with self.assertRaises(ValueError):
                discovery.validate(encoded(value))

    def test_strict_raw_json_and_static_errors(self):
        for raw in [
            b'{"version":1,"version":1,"keys":[]}',
            b'{"version":1,"ver\\u0073ion":1,"keys":[]}',
            initial.replace(b'"algorithm": "Ed25519"', b'"algorithm":"Ed25519","algorithm":"Ed25519"'),
            b"\xef\xbb\xbf" + initial, initial + b" {}", initial + b"\xff",
            initial.replace(b'"active"', b'"\\ud800"'),
            initial.replace(b'"active"', b'"\\udc00"'),
            initial.replace(b'"version": 1', b'"version": NaN'),
            initial.replace(b'"version": 1', b'"version": Infinity'),
            b" " * (discovery.MAX_DOCUMENT_BYTES + 1), b"hostile-secret",
        ]:
            with self.subTest(raw=raw[:30]), self.assertRaisesRegex(ValueError, "^invalid key discovery document$"):
                discovery.validate(raw)

    def test_lineage_and_exact_ids(self):
        after = discovery.validate_transition(initial, rotated)
        discovery.validate_transition(rotated, rotated)
        for mutation in ["remove", "rebind", "reactivate"]:
            changed = copy.deepcopy(after)
            if mutation == "remove":
                changed["keys"].pop(0)
            elif mutation == "rebind":
                changed["keys"][0]["publicKey"] = changed["keys"][1]["publicKey"]
            else:
                changed["keys"][0]["status"] = "active"
            with self.assertRaisesRegex(ValueError, "^invalid key discovery transition$"):
                discovery.validate_transition(rotated, encoded(changed))
        both_active = copy.deepcopy(after)
        both_active["keys"][0]["status"] = "active"
        discovery.validate(encoded(both_active))
        all_retired = copy.deepcopy(after)
        all_retired["keys"][1]["status"] = "retired"
        discovery.validate_transition(rotated, encoded(all_retired))
        ids = {key["keyId"] for key in after["keys"]}
        self.assertNotIn(after["keys"][0]["keyId"].upper(), ids)
        self.assertNotIn(after["keys"][0]["keyId"].split("#")[0], ids)

    def test_existing_signatures_verify_after_rotation_without_network(self):
        after = discovery.validate_transition(initial, rotated)
        by_id = {key["keyId"]: key for key in after["keys"]}
        attestation_spec = importlib.util.spec_from_file_location("attestation_contract", ROOT / "attestation/test_contract.py")
        attestation = importlib.util.module_from_spec(attestation_spec)
        attestation_spec.loader.exec_module(attestation)
        for name in ["hosted", "self-hosted"]:
            document = json.loads((ROOT / f"fixtures/attestation/valid/{name}.json").read_text())
            key = by_id[document["signature"]["keyId"]]
            public = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(key["publicKey"] + "="))
            public.verify(attestation.decode_base64url(document["signature"]["value"]),
                          attestation.signing_input(document))
            document["signature"]["keyId"] += "-relabel"
            self.assertNotIn(document["signature"]["keyId"], by_id)
            with self.assertRaises(attestation.InvalidSignature):
                public.verify(attestation.decode_base64url(document["signature"]["value"]),
                              attestation.signing_input(document))


if __name__ == "__main__":
    unittest.main()
