from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "config/v1/schema.json").read_text(encoding="utf-8"))
FIXTURES = ROOT / "fixtures/config"


class UniqueKeyLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are not permitted")
        return super().compose_node(parent, index)


def construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise TypeError("configuration mapping keys must be strings")
        if key in result:
            raise ValueError(f"duplicate configuration key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
)


def load_document(path: Path):
    if path.suffix == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
    else:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    assert_json_model(document)
    return document


def assert_json_model(value):
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not permitted")
        return
    if isinstance(value, list):
        for item in value:
            assert_json_model(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("configuration mapping keys must be strings")
            assert_json_model(item)
        return
    raise TypeError(f"configuration contains a non-JSON value: {type(value).__name__}")


def set_path(document, path, value):
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def main() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

    hosted_yaml = load_document(FIXTURES / "valid/hosted.yml")
    hosted_json = load_document(FIXTURES / "valid/hosted.normalized.json")
    if hosted_yaml != hosted_json:
        raise AssertionError("hosted.yml does not equal its normalized JSON fixture")

    valid_paths = sorted(
        path for path in (FIXTURES / "valid").glob("*") if path.suffix in {".json", ".yml"}
    )
    for path in valid_paths:
        errors = list(validator.iter_errors(load_document(path)))
        if errors:
            raise AssertionError(f"valid fixture {path.name} failed: {errors[0].message}")

    cases = load_document(FIXTURES / "invalid/cases.json")
    for case in cases:
        document = copy.deepcopy(hosted_json)
        set_path(document, case["path"], case["value"])
        errors = list(validator.iter_errors(document))
        expected_path = list(case["errorPath"])
        if not any(
            error.validator == case["validator"] and list(error.absolute_path) == expected_path
            for error in errors
        ):
            rendered = [(error.validator, list(error.absolute_path), error.message) for error in errors]
            raise AssertionError(f"invalid fixture {case['name']!r} did not fail as expected: {rendered}")

    invalid_yaml_paths = sorted((FIXTURES / "invalid-yaml").glob("*.yml"))
    for path in invalid_yaml_paths:
        try:
            load_document(path)
        except (TypeError, ValueError, yaml.YAMLError):
            pass
        else:
            raise AssertionError(f"unsafe YAML fixture {path.name} was accepted")

    compact = json.dumps(hosted_json, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if "\n" in compact or compact.endswith("\n"):
        raise AssertionError("normalized serialization is not compact")
    expected_hash = (FIXTURES / "valid/hosted.normalized.sha256").read_text(encoding="ascii").strip()
    actual_hash = hashlib.sha256(compact.encode("utf-8")).hexdigest()
    if actual_hash != expected_hash:
        raise AssertionError(f"configuration hash changed: {actual_hash}")

    print(f"validated {len(valid_paths)} valid config fixtures")
    print(f"rejected {len(cases)} invalid config fixtures")
    print(f"rejected {len(invalid_yaml_paths)} unsafe YAML fixtures")
    print(f"normalized hosted fixture to {len(compact.encode('utf-8'))} bytes")
    print(f"verified normalized configuration SHA-256 {actual_hash}")


if __name__ == "__main__":
    main()
