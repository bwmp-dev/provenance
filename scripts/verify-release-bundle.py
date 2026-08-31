import argparse
import hashlib
import io
import json
import posixpath
import re
import tarfile
from pathlib import Path, PurePosixPath


REPOSITORY = "https://github.com/bwmp-dev/provenance"
BUNDLES = (
    "attestation-schema",
    "config-schema",
    "openapi",
    "runner-protocol",
    "typescript-client",
)
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024
MAX_MEMBER_SIZE = 20 * 1024 * 1024
MAX_UNPACKED_SIZE = 100 * 1024 * 1024


def fail(message):
    raise ValueError(message)


def require(condition, message):
    if not condition:
        fail(message)


def hash_bytes(contents, algorithm="sha256"):
    return hashlib.new(algorithm, contents).hexdigest()


def read_bounded(path, maximum, description):
    require(path.is_file() and not path.is_symlink(), f"{description} is not a regular file")
    require(path.stat().st_size <= maximum, f"{description} is too large")
    return path.read_bytes()


def read_json(contents, description):
    try:
        return json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{description} is not valid JSON: {error}")


def safe_archive_path(name, root):
    require(name and "\\" not in name, f"unsafe archive path: {name}")
    require(not name.startswith("/"), f"absolute archive path: {name}")
    require(posixpath.normpath(name) == name, f"non-normalized archive path: {name}")
    require(name == root or name.startswith(f"{root}/"), f"archive path leaves root: {name}")
    require(".." not in PurePosixPath(name).parts, f"archive path contains traversal: {name}")


def archive_name(bundle, version):
    return f"provenance-{bundle}-{version}.tar.gz"


def package_url(ecosystem, name, version):
    if ecosystem == "npm" and name.startswith("@"):
        scope, package_name = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{package_name}@{version}"
    return f"pkg:{ecosystem}/{name}@{version}"


def verify_openapi_inventory(document, inventory):
    require(isinstance(document, dict) and document.get("openapi") == "3.1.1", "OpenAPI JSON version differs")
    require(isinstance(inventory, list), "OpenAPI operation inventory is invalid")
    methods = {"delete", "get", "head", "options", "patch", "post", "put"}
    operations = []
    paths = document.get("paths")
    require(isinstance(paths, dict) and paths, "OpenAPI paths are missing")
    for path, path_item in paths.items():
        require(isinstance(path_item, dict), f"OpenAPI path item is invalid: {path}")
        for method, operation in path_item.items():
            if method not in methods:
                continue
            require(isinstance(operation, dict), f"OpenAPI operation is invalid: {method} {path}")
            operation_id = operation.get("operationId")
            tags = operation.get("tags")
            require(isinstance(operation_id, str) and operation_id, f"OpenAPI operationId is missing: {method} {path}")
            require(isinstance(tags, list) and tags and isinstance(tags[0], str), f"OpenAPI tag is missing: {operation_id}")
            operations.append(
                {
                    "method": method,
                    "operationId": operation_id,
                    "path": path,
                    "tag": tags[0],
                }
            )
    key = lambda item: (item["path"], item["method"], item["operationId"])
    require(operations, "OpenAPI operation inventory is empty")
    require(
        all(
            isinstance(item, dict)
            and set(item) == {"method", "operationId", "path", "tag"}
            and all(isinstance(value, str) and value for value in item.values())
            for item in inventory
        ),
        "declared OpenAPI operation inventory is invalid",
    )
    require(len({item["operationId"] for item in operations}) == len(operations), "OpenAPI operationIds are duplicated")
    require(len({item.get("operationId") for item in inventory}) == len(inventory), "declared OpenAPI operationIds are duplicated")
    require(sorted(operations, key=key) == sorted(inventory, key=key), "OpenAPI operation inventory differs")


def read_archive(directory, artifact, version, source_sha):
    bundle = artifact.get("bundle")
    require(bundle in BUNDLES, f"unknown release bundle: {bundle}")
    expected_name = archive_name(bundle, version)
    require(artifact.get("filename") == expected_name, f"unexpected archive filename: {bundle}")
    archive_path = directory / expected_name
    archive_contents = read_bounded(archive_path, MAX_ARCHIVE_SIZE, expected_name)
    require(len(archive_contents) == artifact.get("size"), f"archive size differs: {expected_name}")
    require(hash_bytes(archive_contents) == artifact.get("sha256"), f"archive digest differs: {expected_name}")

    root = expected_name.removesuffix(".tar.gz")
    members = {}
    file_contents = {}
    unpacked_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_contents), mode="r:gz") as archive:
            entries = archive.getmembers()
            require(len(entries) <= 1000, f"archive has too many entries: {expected_name}")
            for member in entries:
                safe_archive_path(member.name, root)
                require(member.isfile(), f"archive entry is not a regular file: {member.name}")
                require(member.name not in members, f"archive contains duplicate entry: {member.name}")
                require(member.size <= MAX_MEMBER_SIZE, f"archive member is too large: {member.name}")
                unpacked_size += member.size
                require(unpacked_size <= MAX_UNPACKED_SIZE, f"archive unpacked size is too large: {expected_name}")
                stream = archive.extractfile(member)
                require(stream is not None, f"archive member cannot be read: {member.name}")
                contents = stream.read(MAX_MEMBER_SIZE + 1)
                require(len(contents) == member.size, f"archive member size differs: {member.name}")
                members[member.name] = member
                file_contents[member.name] = contents
    except (tarfile.TarError, OSError) as error:
        fail(f"archive cannot be parsed: {expected_name}: {error}")

    embedded_name = f"{root}/RELEASE-MANIFEST.json"
    require(embedded_name in file_contents, f"embedded manifest is missing: {expected_name}")
    embedded_contents = file_contents[embedded_name]
    embedded = read_json(embedded_contents, f"embedded manifest for {bundle}")
    require(embedded.get("schemaVersion") == 1, f"embedded manifest schema differs: {bundle}")
    require(embedded.get("bundle") == bundle, f"embedded manifest bundle differs: {bundle}")
    require(embedded.get("releaseVersion") == version, f"embedded manifest version differs: {bundle}")
    require(embedded.get("sourceCommit") == source_sha, f"embedded manifest source differs: {bundle}")
    declared_files = embedded.get("files")
    require(isinstance(declared_files, list), f"embedded manifest files are missing: {bundle}")
    expected_entries = {embedded_name}
    sbom_files = [
        {
            "path": "RELEASE-MANIFEST.json",
            "sha1": hash_bytes(embedded_contents, "sha1"),
            "sha256": hash_bytes(embedded_contents),
            "size": len(embedded_contents),
        }
    ]
    for record in declared_files:
        require(isinstance(record, dict), f"invalid embedded file record: {bundle}")
        path = record.get("path")
        require(isinstance(path, str), f"embedded file path is invalid: {bundle}")
        full_path = f"{root}/{path}"
        safe_archive_path(full_path, root)
        source = record.get("source")
        require(isinstance(source, str) and "\\" not in source, f"embedded source is invalid: {path}")
        require(posixpath.normpath(source) == source and not source.startswith("/"), f"embedded source is unsafe: {source}")
        require(".." not in PurePosixPath(source).parts, f"embedded source traverses: {source}")
        require(full_path not in expected_entries, f"duplicate embedded file record: {path}")
        expected_entries.add(full_path)
        contents = file_contents.get(full_path)
        require(contents is not None, f"declared archive file is missing: {path}")
        require(len(contents) == record.get("size"), f"embedded file size differs: {path}")
        require(hash_bytes(contents) == record.get("sha256"), f"embedded SHA-256 differs: {path}")
        require(hash_bytes(contents, "sha1") == record.get("sha1"), f"embedded SHA-1 differs: {path}")
        transform = record.get("transform")
        require(
            transform in (None, "release-version", "openapi-json"),
            f"unknown embedded transform: {path}",
        )
        if transform == "release-version":
            package = read_json(contents, f"versioned package {path}")
            require(package.get("version") == version, f"package version differs: {path}")
        sbom_files.append(
            {
                "path": path,
                "sha1": record["sha1"],
                "sha256": record["sha256"],
                "size": record["size"],
            }
        )
    require(set(members) == expected_entries, f"archive entry inventory differs: {bundle}")
    if bundle == "openapi":
        verify_openapi_inventory(
            read_json(file_contents[f"{root}/openapi.json"], "released OpenAPI JSON"),
            read_json(
                file_contents[f"{root}/operation-inventory.json"],
                "released OpenAPI operation inventory",
            ),
        )
    return sorted(sbom_files, key=lambda item: item["path"])


def verify_sbom(sbom, manifest, bundle_files, version, source_sha):
    require(sbom.get("spdxVersion") == "SPDX-2.3", "SPDX version differs")
    require(sbom.get("SPDXID") == "SPDXRef-DOCUMENT", "SPDX document identifier differs")
    require(sbom.get("dataLicense") == "CC0-1.0", "SPDX data license differs")
    require(sbom.get("name") == f"provenance-contracts-{version}", "SPDX name differs")
    require(
        sbom.get("documentNamespace")
        == f"{REPOSITORY}/releases/tag/v{version}/spdx/{source_sha}",
        "SPDX namespace differs",
    )
    require(
        sbom.get("creationInfo")
        == {
            "created": manifest["release"]["createdAt"],
            "creators": ["Tool: @bwmp-dev/provenance-contract-release"],
        },
        "SPDX creation metadata differs",
    )

    packages = sbom.get("packages")
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    require(isinstance(packages, list) and isinstance(files, list), "SPDX package or file inventory is missing")
    require(isinstance(relationships, list), "SPDX relationships are missing")
    package_map = {item.get("SPDXID"): item for item in packages}
    file_map = {item.get("SPDXID"): item for item in files}
    require(None not in package_map and len(package_map) == len(packages), "SPDX packages are duplicated")
    require(None not in file_map and len(file_map) == len(files), "SPDX files are duplicated")

    artifacts = {item["bundle"]: item for item in manifest["artifacts"]}
    first_party_ids = {f"SPDXRef-Package-{bundle}" for bundle in BUNDLES}
    require(set(sbom.get("documentDescribes", [])) == first_party_ids, "SPDX described packages differ")
    expected_file_names = set()
    expected_contains = set()
    for bundle in BUNDLES:
        package_id = f"SPDXRef-Package-{bundle}"
        package = package_map.get(package_id)
        artifact = artifacts[bundle]
        require(package is not None, f"SPDX first-party package is missing: {bundle}")
        require(package.get("name") == f"provenance-{bundle}", f"SPDX package name differs: {bundle}")
        require(package.get("versionInfo") == version, f"SPDX package version differs: {bundle}")
        require(package.get("packageFileName") == artifact["filename"], f"SPDX archive linkage differs: {bundle}")
        require(package.get("filesAnalyzed") is True, f"SPDX package analysis flag differs: {bundle}")
        require(
            package.get("checksums")
            == [{"algorithm": "SHA256", "checksumValue": artifact["sha256"]}],
            f"SPDX archive checksum differs: {bundle}",
        )
        verification_code = hash_bytes(
            "".join(sorted(item["sha1"] for item in bundle_files[bundle])).encode("ascii"),
            "sha1",
        )
        require(
            package.get("packageVerificationCode", {}).get("packageVerificationCodeValue")
            == verification_code,
            f"SPDX package verification code differs: {bundle}",
        )
        root = artifact["filename"].removesuffix(".tar.gz")
        for record in bundle_files[bundle]:
            file_name = f"./{root}/{record['path']}"
            expected_file_names.add(file_name)
            matches = [item for item in files if item.get("fileName") == file_name]
            require(len(matches) == 1, f"SPDX archived file linkage differs: {file_name}")
            file_record = matches[0]
            require(
                file_record.get("checksums")
                == [
                    {"algorithm": "SHA1", "checksumValue": record["sha1"]},
                    {"algorithm": "SHA256", "checksumValue": record["sha256"]},
                ],
                f"SPDX archived file checksum differs: {file_name}",
            )
            expected_contains.add((package_id, file_record["SPDXID"]))
    require({item.get("fileName") for item in files} == expected_file_names, "SPDX file inventory differs")

    dependency_ids = set(package_map) - first_party_ids
    dependency_manifest = manifest.get("dependencies")
    require(isinstance(dependency_manifest, list) and dependency_manifest, "release dependency manifest is empty")
    require(len(dependency_ids) == len(dependency_manifest), "SPDX dependency inventory differs from manifest")
    expected_depends = set()
    declared_keys = set()
    for declared in dependency_manifest:
        require(
            isinstance(declared, dict)
            and set(declared)
            == {"bundles", "checksum", "ecosystem", "license", "name", "version"},
            "release dependency declaration is invalid",
        )
        ecosystem = declared["ecosystem"]
        name = declared["name"]
        dependency_version = declared["version"]
        require(ecosystem in ("npm", "golang"), f"unknown dependency ecosystem: {ecosystem}")
        require(all(isinstance(value, str) and value for value in (name, dependency_version, declared["license"])), "dependency identity is incomplete")
        bundles = declared["bundles"]
        require(
            isinstance(bundles, list)
            and bundles
            and len(set(bundles)) == len(bundles)
            and set(bundles) <= set(BUNDLES),
            f"dependency bundle linkage is invalid: {name}@{dependency_version}",
        )
        key = (ecosystem, name, dependency_version)
        require(key not in declared_keys, f"duplicate dependency declaration: {name}@{dependency_version}")
        declared_keys.add(key)
        checksum = declared["checksum"]
        checksum_lengths = {"SHA1": 40, "SHA256": 64, "SHA512": 128}
        require(
            isinstance(checksum, dict)
            and set(checksum) == {"algorithm", "checksumValue"}
            and checksum.get("algorithm") in checksum_lengths
            and re.fullmatch(
                rf"[0-9a-f]{{{checksum_lengths.get(checksum.get('algorithm'), 0)}}}",
                checksum.get("checksumValue", ""),
            ),
            f"dependency checksum evidence is invalid: {name}@{dependency_version}",
        )
        purl = package_url(ecosystem, name, dependency_version)
        matches = [
            (dependency_id, package_map[dependency_id])
            for dependency_id in dependency_ids
            if package_map[dependency_id].get("name") == name
            and package_map[dependency_id].get("versionInfo") == dependency_version
            and any(
                reference.get("referenceType") == "purl"
                and reference.get("referenceLocator") == purl
                for reference in package_map[dependency_id].get("externalRefs", [])
            )
        ]
        require(len(matches) == 1, f"SPDX dependency identity differs: {name}@{dependency_version}")
        dependency_id, dependency = matches[0]
        require(dependency.get("filesAnalyzed") is False, f"SPDX dependency analysis flag differs: {dependency_id}")
        require(dependency.get("checksums") == [declared["checksum"]], f"SPDX dependency checksum differs: {dependency_id}")
        require(dependency.get("licenseDeclared") == declared["license"], f"SPDX dependency license differs: {dependency_id}")
        for bundle in bundles:
            expected_depends.add((f"SPDXRef-Package-{bundle}", dependency_id))

    actual_contains = set()
    actual_depends = set()
    described = set()
    relationship_keys = set()
    for relationship in relationships:
        relationship_type = relationship.get("relationshipType")
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        relationship_key = (source, relationship_type, target)
        require(relationship_key not in relationship_keys, "SPDX relationship is duplicated")
        relationship_keys.add(relationship_key)
        if relationship_type == "CONTAINS":
            actual_contains.add((source, target))
        elif relationship_type == "DEPENDS_ON":
            require(source in first_party_ids and target in dependency_ids, "invalid SPDX dependency relationship")
            actual_depends.add((source, target))
        elif relationship_type == "DESCRIBES":
            described.add((source, target))
        else:
            fail(f"unexpected SPDX relationship type: {relationship_type}")
    require(actual_contains == expected_contains, "SPDX containment relationships differ")
    require(actual_depends == expected_depends, "SPDX dependency relationships differ")
    require(
        described == {("SPDXRef-DOCUMENT", package_id) for package_id in first_party_ids},
        "SPDX description relationships differ",
    )


def verify_bundle(directory, version, source_sha):
    require(SEMVER.fullmatch(version), f"release version is not valid SemVer: {version}")
    require(SHA1.fullmatch(source_sha), "source SHA must contain 40 hexadecimal characters")
    manifest_name = f"provenance-contracts-{version}.manifest.json"
    sbom_name = f"provenance-contracts-{version}.spdx.json"
    checksum_name = f"provenance-contracts-{version}.sha256"
    expected_names = {
        manifest_name,
        sbom_name,
        checksum_name,
        *(archive_name(bundle, version) for bundle in BUNDLES),
    }
    actual_names = {path.name for path in directory.iterdir()}
    require(actual_names == expected_names, "release bundle file inventory differs")
    for name in actual_names:
        require((directory / name).is_file() and not (directory / name).is_symlink(), f"release asset is not a regular file: {name}")

    manifest_contents = read_bounded(directory / manifest_name, MAX_MEMBER_SIZE, manifest_name)
    manifest = read_json(manifest_contents, "release manifest")
    require(manifest.get("schemaVersion") == 1, "release manifest schema differs")
    require(
        manifest.get("compatibility")
        == {
            "action": "not-released",
            "attestationSchema": "v1",
            "cli": "not-released",
            "configSchema": "v1",
            "openapi": "v1",
            "runnerProtocol": "v1",
            "sdk": {"typescriptClient": version},
        },
        "release compatibility declaration differs",
    )
    release = manifest.get("release", {})
    require(release.get("version") == version, "release manifest version differs")
    require(release.get("tag") == f"v{version}", "release manifest tag differs")
    require(release.get("sourceCommit") == source_sha, "release manifest source SHA differs")
    require(release.get("repository") == REPOSITORY, "release manifest repository differs")
    require(
        isinstance(release.get("createdAt"), str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", release["createdAt"]),
        "release manifest timestamp differs",
    )
    require(
        isinstance(manifest.get("toolchain"), dict)
        and all(isinstance(value, str) and value for value in manifest["toolchain"].values()),
        "release toolchain manifest is invalid",
    )
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == len(BUNDLES), "release artifact inventory differs")
    require({item.get("bundle") for item in artifacts} == set(BUNDLES), "release bundle identifiers differ")

    checksum_contents = read_bounded(directory / checksum_name, MAX_MEMBER_SIZE, checksum_name)
    try:
        checksum_lines = checksum_contents.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        fail(f"checksum file is not ASCII: {error}")
    checksums = {}
    for line in checksum_lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        require(match is not None, f"invalid checksum line: {line}")
        require(match.group(2) not in checksums, f"duplicate checksum entry: {match.group(2)}")
        checksums[match.group(2)] = match.group(1)
    require(set(checksums) == expected_names - {checksum_name}, "checksum inventory differs")
    require(checksums[manifest_name] == hash_bytes(manifest_contents), "manifest checksum differs")

    bundle_files = {}
    for artifact in artifacts:
        name = artifact.get("filename")
        require(checksums.get(name) == artifact.get("sha256"), f"artifact checksum linkage differs: {name}")
        bundle_files[artifact["bundle"]] = read_archive(directory, artifact, version, source_sha)

    sbom_record = manifest.get("sbom", {})
    require(sbom_record.get("filename") == sbom_name, "SBOM filename differs")
    require(sbom_record.get("format") == "SPDX-2.3", "SBOM format differs")
    sbom_contents = read_bounded(directory / sbom_name, MAX_MEMBER_SIZE, sbom_name)
    require(len(sbom_contents) == sbom_record.get("size"), "SBOM size differs")
    require(hash_bytes(sbom_contents) == sbom_record.get("sha256"), "SBOM digest differs")
    require(checksums[sbom_name] == sbom_record["sha256"], "SBOM checksum linkage differs")
    verify_sbom(read_json(sbom_contents, "release SBOM"), manifest, bundle_files, version, source_sha)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    verify_bundle(arguments.directory.resolve(), arguments.version, arguments.source_sha.lower())
    print(f"Verified immutable release bundle for v{arguments.version} without executing artifact code")


if __name__ == "__main__":
    main()
