from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "v1/schema.json").read_text(encoding="utf-8")
)
HASH = "a" * 64
VALID = {
    "schemaVersion": "provenance.paper-metadata/v1",
    "artifactSha256": HASH,
    "status": "valid",
    "issues": [],
    "plugin": {
        "name": "ExamplePlugin",
        "version": "1.0.0",
        "mainClass": "example.ExamplePlugin",
        "apiVersion": "1.21",
        "requiredDependencies": ["Required"],
        "softDependencies": ["Optional"],
        "loadBeforeDependencies": [],
        "permissions": ["example.use"],
        "commands": ["example"],
    },
}


def assert_invalid(validator: Draft202012Validator, document: dict) -> None:
    if not list(validator.iter_errors(document)):
        raise AssertionError(f"invalid Paper metadata result was accepted: {document}")


def assert_public_strings_reject_invalid_characters(
    validator: Draft202012Validator,
) -> None:
    fields = {
        "artifactSha256": (HASH, lambda document, value: document.__setitem__("artifactSha256", value)),
        "name": ("ExamplePlugin", lambda document, value: document["plugin"].__setitem__("name", value)),
        "version": ("1.0.0", lambda document, value: document["plugin"].__setitem__("version", value)),
        "mainClass": ("example.ExamplePlugin", lambda document, value: document["plugin"].__setitem__("mainClass", value)),
        "apiVersion": ("1.21", lambda document, value: document["plugin"].__setitem__("apiVersion", value)),
        "dependency": ("Required", lambda document, value: document["plugin"].__setitem__("requiredDependencies", [value])),
        "permission": ("example.use", lambda document, value: document["plugin"].__setitem__("permissions", [value])),
        "command": ("example", lambda document, value: document["plugin"].__setitem__("commands", [value])),
    }
    for field, (valid_value, mutate) in fields.items():
        positions = {
            "beginning": "\n" + valid_value,
            "middle": valid_value[:1] + "\n" + valid_value[1:],
            "end": valid_value + "\n",
        }
        for position, value in positions.items():
            document = copy.deepcopy(VALID)
            mutate(document, value)
            if not list(validator.iter_errors(document)):
                raise AssertionError(
                    f"{field} accepted a control character at the {position}"
                )
        for surrogate_name, surrogate in (("high", "\ud800"), ("low", "\udc00")):
            document = copy.deepcopy(VALID)
            mutate(document, valid_value[:1] + surrogate + valid_value[1:])
            if not list(validator.iter_errors(document)):
                raise AssertionError(f"{field} accepted an unpaired {surrogate_name} surrogate")


def assert_canonical_strings_reject_edge_spaces(
    validator: Draft202012Validator,
) -> None:
    fields = {
        "name": ("ExamplePlugin", lambda plugin, value: plugin.__setitem__("name", value)),
        "version": ("1.0.0", lambda plugin, value: plugin.__setitem__("version", value)),
        "apiVersion": ("1.21", lambda plugin, value: plugin.__setitem__("apiVersion", value)),
        "dependency": ("Required", lambda plugin, value: plugin.__setitem__("requiredDependencies", [value])),
        "permission": ("example.use", lambda plugin, value: plugin.__setitem__("permissions", [value])),
        "command": ("example", lambda plugin, value: plugin.__setitem__("commands", [value])),
    }
    for field, (valid_value, mutate) in fields.items():
        for position, value in {
            "blank": " ",
            "beginning": " " + valid_value,
            "end": valid_value + " ",
        }.items():
            document = copy.deepcopy(VALID)
            mutate(document["plugin"], value)
            if not list(validator.iter_errors(document)):
                raise AssertionError(f"{field} accepted {position} ASCII space")


def validate_result(schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.load(sys.stdin))


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    if SCHEMA.get("$id") != "https://schemas.provenance.dev/paper-metadata/v1/schema.json":
        raise AssertionError("Paper metadata schema $id is not the canonical public URI")
    validator = Draft202012Validator(SCHEMA)
    validator.validate(VALID)
    without_api_version = copy.deepcopy(VALID)
    without_api_version["plugin"]["apiVersion"] = None
    validator.validate(without_api_version)
    validator.validate(
        {
            "schemaVersion": "provenance.paper-metadata/v1",
            "artifactSha256": HASH,
            "status": "missing",
            "issues": ["plugin_metadata_missing"],
        }
    )
    validator.validate(
        {
            "schemaVersion": "provenance.paper-metadata/v1",
            "artifactSha256": HASH,
            "status": "invalid",
            "issues": ["plugin_metadata_utf8_invalid"],
        }
    )

    invalid_hash = copy.deepcopy(VALID)
    invalid_hash["artifactSha256"] = "not-a-hash"
    assert_invalid(validator, invalid_hash)

    valid_without_plugin = copy.deepcopy(VALID)
    del valid_without_plugin["plugin"]
    assert_invalid(validator, valid_without_plugin)

    invalid_with_plugin = copy.deepcopy(VALID)
    invalid_with_plugin["status"] = "invalid"
    invalid_with_plugin["issues"] = ["plugin_metadata_yaml_invalid"]
    assert_invalid(validator, invalid_with_plugin)

    unbounded_issue = copy.deepcopy(VALID)
    unbounded_issue["status"] = "invalid"
    unbounded_issue.pop("plugin")
    unbounded_issue["issues"] = ["raw parser exception or path"]
    assert_invalid(validator, unbounded_issue)

    invalid_missing_code = copy.deepcopy(unbounded_issue)
    invalid_missing_code["issues"] = ["plugin_metadata_missing"]
    assert_invalid(validator, invalid_missing_code)

    missing_wrong_code = copy.deepcopy(unbounded_issue)
    missing_wrong_code["status"] = "missing"
    missing_wrong_code["issues"] = ["artifact_invalid"]
    assert_invalid(validator, missing_wrong_code)

    assert_public_strings_reject_invalid_characters(validator)
    assert_canonical_strings_reject_edge_spaces(validator)
    for reserved_name in ("bukkit", "MineCraft", "MOJANG", "spigot", "Paper"):
        reserved = copy.deepcopy(VALID)
        reserved["plugin"]["name"] = reserved_name
        assert_invalid(validator, reserved)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--validate-result":
        validate_result(Path(sys.argv[2]))
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: test_contract.py [--validate-result SCHEMA]")
