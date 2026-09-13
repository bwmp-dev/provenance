"""Independent offline Draft 2020-12 and canonical configuration-v2 check."""
import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

root = Path(__file__).resolve().parents[1]
v1 = json.loads((root / "config/v1/schema.json").read_text())
v2 = json.loads((root / "config/v2/schema.json").read_text())
Draft202012Validator.check_schema(v2)


def refuse_remote(uri):
    raise AssertionError("remote schema resolution is forbidden")


registry = Registry(retrieve=refuse_remote).with_resource(v1["$id"], Resource.from_contents(v1))
validator = Draft202012Validator(v2, registry=registry)
vector = json.loads((root / "fixtures/config/v2/vectors.json").read_text())
document = json.loads(vector["canonical"])
validator.validate(document)
canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
assert canonical == vector["canonical"]
assert hashlib.sha256(canonical.encode()).hexdigest() == vector["sha256"]
assert not Draft202012Validator(v1).is_valid(document)
for key, value in [("mode", "unrestricted"), ("permissions", []), ("maximumConnections", 0),
                   ("maximumBytesPerSecond", 0), ("maximumBytesPerSecond", 4294967296),
                   ("resolver", "customer.example"), ("maximumConnections", True)]:
    bad = copy.deepcopy(document)
    bad["network"][key] = value
    assert not validator.is_valid(bad), key
for host in ["localhost", "127.0.0.1", "0x7f.0.0.1", "0177.0.0.1", "*.example", "A.example", "a.example\n"]:
    bad = copy.deepcopy(document)
    bad["network"]["permissions"][0]["hostname"] = host
    assert not validator.is_valid(bad), host
none = copy.deepcopy(document)
none["network"] = {"mode": "none", "permissions": [], "maximumConnections": 0, "maximumBytesPerSecond": 0}
validator.validate(none)
none["network"]["maximumBytesPerSecond"] = 1
assert not validator.is_valid(none)
print("validated offline v2 schema, frozen canonical/hash, legacy refusal and closed network boundaries")
