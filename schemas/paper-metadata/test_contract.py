from __future__ import annotations

import copy
import json
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


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA)
    validator.validate(VALID)
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


if __name__ == "__main__":
    main()
