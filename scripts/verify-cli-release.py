"""Independent CLI bundle inspection. Never executes the inspected binary."""
import argparse
import hashlib
import gzip
import io
import json
import pathlib
import re
import struct
import subprocess
import tarfile

# Audited distribution dependency-license pins, not claims inferred from a
# submitter-controlled manifest. A dependency upgrade requires re-auditing this
# inventory as well as the repository's go.sum.
LICENSE_PINS = {
    "github.com/99designs/keyring": {"LICENSE": "f57f886a33e0ae7b50093f19051e65edcd1fde7cde63caa6b1ba4254856f4e4f"},
    "github.com/dlclark/regexp2": {"LICENSE": "9be5d04bb4d706914d5bf943710da4afeb42048f7c529902fb57c82762a991a9"},
    "github.com/dlclark/regexp2/v2": {"LICENSE": "9be5d04bb4d706914d5bf943710da4afeb42048f7c529902fb57c82762a991a9"},
    "github.com/dop251/goja": {
        "LICENSE": "8a1266c1dd7d22027455bea83b92087f606c8d5fc701b269a8411f008ed49a99",
        "ftoa/LICENSE_LUCENE": "eb4df27f95a096a23d88e567331a4bee5590d22185942a1b0456197e29d03e59",
        "ftoa/internal/fast/LICENSE_V8": "a1ecb1a1e1d57c90ccb2455259db836c68942d83a885091bd4375a52e74bec9d"},
    "github.com/dvsekhvalnov/jose2go": {"LICENSE": "c9b003992c61becee037549814a89434c05780288f14c190b554dc30b7fddf5f"},
    "github.com/go-sourcemap/sourcemap": {"LICENSE": "92e002c4f78b8f80445cf72c4bd33d78e4998371a5eff80886c5648a7974a19f"},
    "github.com/godbus/dbus": {"LICENSE": "e4646a82a976369d7ae8f6ed5c11d35dc0af18433a8ccc24c85b459ad8b95128"},
    "github.com/google/pprof": {"LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30", "third_party/svgpan/LICENSE": "154c946c17de61ca71d28e13673d76a5798e6e25995a7397fbae157afc8f62b4"},
    "github.com/gsterjov/go-libsecret": {"LICENSE": "d5466e16848e861100411d02dcb9778a10e9dfbf13245a435ec9d915b4197ae7"},
    "github.com/mtibben/percent": {"LICENSE": "4a69823387cc23ba25881ae73923d89db013bb5571780f1eea48910d7cc8357a"},
    "github.com/santhosh-tekuri/jsonschema/v6": {"LICENSE": "c8858a5a76440bbca484e134cf7df46385d090dd18b2c58e650f939258802e5b"},
    "go.yaml.in/yaml/v3": {"LICENSE": "d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b", "NOTICE": "f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00"},
}
for name in ["golang.org/x/sys", "golang.org/x/term", "golang.org/x/text"]:
    LICENSE_PINS[name] = {
        "LICENSE": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad" if name.endswith("/text") else "2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067",
        "PATENTS": "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def parse(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, limit=64 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink(), "nonregular asset")
    require(path.stat().st_size <= limit, "oversized asset")
    return path.read_bytes()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=15)


def verify(directory, version, source, repository):
    require(re.fullmatch(r"[0-9a-f]{40}", source), "invalid source")
    require(len(version) <= 64 and re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?", version), "invalid version")
    root = f"provenance-cli-{version}-linux-amd64"
    prefix = f"provenance-cli-{version}"
    archive_name = root + ".tar.gz"
    manifest_name, sbom_name, checksum_name = (prefix + suffix for suffix in (".manifest.json", ".spdx.json", ".sha256"))
    require(directory.is_dir() and not directory.is_symlink(), "invalid bundle directory")
    require(sorted(p.name for p in directory.iterdir()) == sorted([archive_name, manifest_name, sbom_name, checksum_name]), "asset inventory differs")
    assets = {name: read(directory / name) for name in [archive_name, manifest_name, sbom_name, checksum_name]}
    expected = "".join(f"{sha(assets[name])}  {name}\n" for name in sorted([archive_name, manifest_name, sbom_name]))
    require(assets[checksum_name].decode() == expected, "checksum inventory differs")
    manifest = parse(assets[manifest_name])
    require(set(manifest) == {"schemaVersion", "version", "tag", "sourceCommit", "createdAt", "platform", "goVersion", "cgoEnabled", "goAMD64", "archiveRoot", "archive", "files", "sourceFiles", "components", "buildInfo"}, "manifest shape differs")
    require(manifest["schemaVersion"] == 1 and manifest["version"] == version and manifest["tag"] == "cli-v" + version and manifest["sourceCommit"] == source, "release identity differs")
    require(manifest["platform"] == "linux-amd64" and manifest["goVersion"] == "go1.25.13" and manifest["cgoEnabled"] is False and manifest["goAMD64"] == "v1", "build target differs")
    require(manifest["archiveRoot"] == root and manifest["archive"] == {"filename": archive_name, "sizeBytes": len(assets[archive_name]), "sha256": sha(assets[archive_name])}, "archive identity differs")
    epoch = int(git(repository, "show", "-s", "--format=%ct", source))
    import datetime
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    require(manifest["createdAt"] == created, "timestamp not derived from source")
    paths = git(repository, "ls-tree", "-r", "--name-only", source, "--", "packages/cli-go", "packages/verification-go", "LICENSE").decode().strip().splitlines()
    require(10 < len(paths) <= 1000, "source inventory bounds")
    source_files = []
    for path in sorted(paths):
        require(re.match(rb"100(644|755) ", git(repository, "ls-tree", source, "--", path)), "source link")
        data = git(repository, "show", source + ":" + path)
        require(len(data) <= 8 * 1024 * 1024, "source file bounds")
        source_files.append({"path": path, "sizeBytes": len(data), "sha256": sha(data)})
    require(manifest["sourceFiles"] == source_files, "source inventory differs")
    files = manifest["files"]
    require(isinstance(files, list) and 5 < len(files) <= 1000, "file inventory bounds")
    expected_files = {}
    for item in files:
        require(set(item) == {"path", "sizeBytes", "sha256", "mode"}, "file declaration shape")
        path = item["path"]
        require(isinstance(path, str) and len(path) <= 400 and not path.startswith("/") and "\\" not in path and all(p not in ("", ".", "..") for p in path.split("/")), "unsafe path")
        require(path not in expected_files and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "duplicate or malformed file")
        require(type(item["sizeBytes"]) is int and 0 <= item["sizeBytes"] <= 64 * 1024 * 1024, "file size bounds")
        require(item["mode"] == (0o755 if path == "provenance" else 0o644), "file mode differs")
        expected_files[path] = item
    require(list(expected_files) == sorted(expected_files), "unsorted inventory")
    require({"provenance", "README.md", "LICENSE", "build-info.txt"}.issubset(expected_files), "required payload absent")
    contents = {}
    total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(assets[archive_name])) as compressed:
        raw_tar = compressed.read(128 * 1024 * 1024 + 1)
    require(len(raw_tar) <= 128 * 1024 * 1024, "compressed expansion bound")
    archive_end = 0
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
        for member in archive:
            require(member.isfile() and not member.pax_headers and member.name.startswith(root + "/"), "unsafe archive member")
            path = member.name[len(root) + 1:]
            require(path in expected_files and path not in contents, "unexpected/duplicate archive member")
            expected_file = expected_files[path]
            require(member.size == expected_file["sizeBytes"] and member.mode == expected_file["mode"] and member.uid == 0 and member.gid == 0 and member.mtime == epoch, "archive metadata differs")
            total += member.size
            require(total <= 128 * 1024 * 1024, "unpacked bound")
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and sha(data) == expected_file["sha256"], "archive file differs")
            contents[path] = data
            archive_end = member.offset_data + ((member.size + 511) // 512) * 512
    require(len(raw_tar) >= archive_end + 1024 and not any(raw_tar[archive_end:]), "archive trailing payload differs")
    require(list(contents) == sorted(expected_files), "archive inventory/order differs")
    binary = contents["provenance"]
    require(len(binary) > 64 and binary[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", binary, 18)[0] == 62, "not Linux amd64 ELF")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    entry_size, count = struct.unpack_from("<HH", binary, 54)
    require(entry_size >= 56 and count <= 1000 and offset + entry_size * count <= len(binary), "invalid ELF headers")
    require(all(struct.unpack_from("<I", binary, offset + i * entry_size)[0] != 3 for i in range(count)), "dynamic interpreter forbidden")
    info = contents["build-info.txt"].decode()
    require(info == manifest["buildInfo"] and f"vcs.revision={source}" in info and "vcs.modified=false" in info and "CGO_ENABLED=0" in info and "GOAMD64=v1" in info, "binary metadata declaration differs")
    # Independently parse Go's inline build-info strings, without executing Go or
    # the downloaded binary. Go1.25 uses pointer-size byte followed by flags=2.
    marker = b"\xff Go buildinf:"
    index = binary.find(marker)
    require(index >= 0 and index + 32 < len(binary) and binary[index + 15] & 2, "inline Go build information absent")
    def varint(at):
        value, shift = 0, 0
        for _ in range(10):
            require(at < len(binary), "truncated varint")
            byte = binary[at]; at += 1
            value |= (byte & 127) << shift
            if byte < 128: return value, at
            shift += 7
        raise ValueError("invalid varint")
    length, at = varint(index + 32)
    require(binary[at:at + length] == b"go1.25.13", "embedded Go version differs")
    at += length
    length, at = varint(at)
    require(length <= 1024 * 1024 and at + length <= len(binary), "embedded module info bound")
    module_info = binary[at:at + length]
    require(f"vcs.revision={source}".encode() in module_info and b"vcs.modified=false" in module_info, "embedded source differs")
    require(length >= 32, "module information truncated")
    embedded = module_info[16:-16].decode()
    require("\n".join(line.lstrip("\t") for line in info.splitlines()) + "\n" == embedded,
            "text build information differs from actual binary")
    linked = {}
    for line in embedded.splitlines():
        parts = line.split("\t")
        if parts[0] in ("dep", "mod"):
            require(parts[1] not in linked, "duplicate linked module")
            linked[parts[1]] = parts[2:]
    local_names = {"github.com/bwmp-dev/provenance/packages/cli-go", "github.com/bwmp-dev/provenance/packages/verification-go"}
    require(set(linked) == set(LICENSE_PINS) | local_names, "linked module policy differs")
    require(embedded.count("=>\t") == 1 and "=>\t../verification-go\t(devel)" in embedded,
            "local verifier replacement differs")
    source_sums = set(git(repository, "show", source + ":packages/cli-go/go.sum").decode().splitlines())
    require(contents["LICENSE"] == git(repository, "show", source + ":LICENSE") and contents["README.md"] == git(repository, "show", source + ":packages/cli-go/README.md"), "source document differs")
    components = manifest["components"]
    require(isinstance(components, list) and 4 < len(components) <= 100, "component bounds")
    ids, licensed = set(), set()
    for component in components:
        require(set(component) == ({"id", "name", "version", "kind", "sourceCommit", "goSum", "licenses", "sourceSha256"} if component["id"] == "regexpp" else {"id", "name", "version", "kind", "sourceCommit", "goSum", "licenses"}), "component shape differs")
        require(component["id"] not in ids, "duplicate component")
        ids.add(component["id"])
        require(component["licenses"], "license evidence absent")
        for license in component["licenses"]:
            require(set(license) == {"path", "sha256"} and license["path"].startswith("licenses/"), "license shape")
            require(license["path"] in contents and sha(contents[license["path"]]) == license["sha256"], "license missing or changed")
            licensed.add(license["path"])
        if component["kind"] == "repository-source":
            require(component["name"] in local_names, "unexpected repository component")
            require(component["sourceCommit"] == source and component["version"] == source and component["goSum"] is None, "local replacement mislabeled")
            pins = {"LICENSE": sha(contents["LICENSE"])}
        elif component["kind"] == "go-module":
            require(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", component["goSum"]), "module checksum absent")
            require(f"dep\t{component['name']}\t{component['version']}\t{component['goSum']}".encode() in module_info, "declared module not linked")
            require(f"{component['name']} {component['version']} {component['goSum']}" in source_sums, "module not source-pinned")
            require(component["sourceCommit"] is None, "external module mislabeled")
            pins = LICENSE_PINS[component["name"]]
        elif component["id"] == "go-toolchain":
            require(component["kind"] == "toolchain" and component["name"] == "Go" and component["version"] == "go1.25.13", "toolchain component differs")
            require(component["sourceCommit"] is None and component["goSum"] is None, "toolchain provenance differs")
            pins = LICENSE_PINS["golang.org/x/text"]
        elif component["id"] == "regexpp":
            require(component["kind"] == "vendored-javascript" and component["name"] == "@eslint-community/regexpp", "vendor component differs")
            require(component["sourceCommit"] is None and component["goSum"] is None, "vendor provenance differs")
            pins = {"LICENSE": "fcf6eabf68ca96988a6b506b4fdc6cc32535d80eb2e11c79724af5ac6f50262b"}
        else:
            raise ValueError("unknown component")
        if component["kind"] in ("go-module", "repository-source"):
            require(component["id"] == "module-" + sha(component["name"].encode())[:16], "module identifier differs")
        prefix = "licenses/" + ("go" if component["id"] == "go-toolchain" else component["id"]) + "/"
        require({item["path"]: item["sha256"] for item in component["licenses"]} == {prefix + path: value for path, value in pins.items()}, "complete pinned license inventory differs")
    require({c["name"] for c in components if c["kind"] in ("go-module", "repository-source")} == set(linked), "linked module omitted")
    require(len(components) == len(linked) + 2, "duplicate or extra component")
    require(set(contents) == licensed | {"provenance", "README.md", "LICENSE", "build-info.txt"}, "unclassified archive file")
    require({"go-toolchain", "regexpp"}.issubset(ids), "toolchain/vendor absent")
    regex = next(c for c in components if c["id"] == "regexpp")
    require(regex["sourceSha256"] == "8f9526195a26cb0d47a48528e61f0083596d397092296a44fc1c1ac470aba336" and regex["version"] == "4.12.2", "vendor source differs")
    sbom = parse(assets[sbom_name])
    require(set(sbom) == {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages", "files", "relationships"}, "SBOM shape differs")
    require(sbom["SPDXID"] == "SPDXRef-DOCUMENT" and sbom["name"] == f"provenance-cli-{version}" and sbom["creationInfo"] == {"created": created, "creators": ["Tool: provenance-cli-release"]}, "SBOM document differs")
    require(sbom["spdxVersion"] == "SPDX-2.3" and sbom["dataLicense"] == "CC0-1.0" and sbom["creationInfo"]["created"] == created, "SBOM identity differs")
    require(sbom["documentNamespace"] == f"https://github.com/bwmp-dev/provenance/cli/{version}/{source}", "SBOM source differs")
    require(len(sbom["packages"]) == len(components) + 1 and {p["SPDXID"] for p in sbom["packages"]} == {"SPDXRef-CLI"} | {"SPDXRef-" + c["id"] for c in components}, "SBOM package inventory differs")
    expected_packages = [{"SPDXID": "SPDXRef-CLI", "name": "provenance-cli-linux-amd64", "versionInfo": version,
                          "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
                          "packageVerificationCode": {"packageVerificationCodeValue": hashlib.sha1("".join(sorted(hashlib.sha1(data).hexdigest() for data in contents.values())).encode()).hexdigest()},
                          "licenseConcluded": "NOASSERTION", "licenseDeclared": "Apache-2.0", "copyrightText": "NOASSERTION"}]
    for component in components:
        comment = {key: component[key] for key in ("kind", "goSum", "licenses", "sourceCommit", "sourceSha256") if key in component}
        expected_packages.append({"SPDXID": "SPDXRef-" + component["id"], "name": component["name"], "versionInfo": component["version"],
                                  "downloadLocation": "git+https://github.com/bwmp-dev/provenance@" + source if component["kind"] == "repository-source" else "NOASSERTION",
                                  "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                                  "comment": json.dumps(comment, separators=(",", ":"))})
    require(sbom["packages"] == expected_packages, "SBOM package identity/license differs")
    require(len(sbom["files"]) == len(files), "SBOM file count differs")
    for index, item in enumerate(files):
        entry = sbom["files"][index]
        require(set(entry) == {"SPDXID", "fileName", "checksums", "licenseConcluded", "licenseInfoInFiles", "copyrightText"} and entry["licenseConcluded"] == "NOASSERTION" and entry["licenseInfoInFiles"] == ["NOASSERTION"] and entry["copyrightText"] == "NOASSERTION", "SBOM file license classification differs")
        require(entry["SPDXID"] == f"SPDXRef-File-{index}" and entry["fileName"] == f"./{root}/{item['path']}" and entry["checksums"] == [{"algorithm": "SHA256", "checksumValue": item["sha256"]}, {"algorithm": "SHA1", "checksumValue": hashlib.sha1(contents[item["path"]]).hexdigest()}], "SBOM file differs")
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-CLI"}]
    relationships += [{"spdxElementId": "SPDXRef-CLI", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-" + c["id"]} for c in components]
    relationships += [{"spdxElementId": "SPDXRef-CLI", "relationshipType": "CONTAINS", "relatedSpdxElement": f"SPDXRef-File-{index}"} for index in range(len(files))]
    require(sbom["relationships"] == relationships, "SBOM relationships differ")
    return {"version": version, "sourceCommit": source, "files": len(files), "components": len(components), "binarySha256": sha(binary), "verified": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.directory, args.version, args.source_sha, args.repository)))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit("CLI bundle verification failed: " + str(error))
