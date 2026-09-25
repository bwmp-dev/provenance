"""Offline `provenance verify` acceptance for a locally built CLI binary.

Portable across Linux, macOS and Windows. Uses only the released interop
attestation vectors; no network, credential store or platform origin is used.
"""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
if len(sys.argv) != 2:
    raise SystemExit("expected the CLI binary path")
binary = str(pathlib.Path(sys.argv[1]).resolve())
vectors = root / "schemas" / "fixtures" / "attestation" / "interop"


def cli(args, success):
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=60)
    if (result.returncode == 0) != success:
        raise SystemExit(f"verify {'accepted' if not success else 'rejected'} {args[1]}: {result.returncode} {result.stdout} {result.stderr}")


checked = []
with tempfile.TemporaryDirectory(prefix="cli-offline-verify-") as scratch:
    scratch = pathlib.Path(scratch)
    for name in ("small-artifact.json", "small-artifact-v2.json", "small-artifact-config-v2.json"):
        fixture = json.loads((vectors / name).read_text(encoding="utf-8"))
        jar, document, key = (scratch / (name + suffix) for suffix in (".jar", ".attestation.json", ".public-key"))
        jar.write_bytes(bytes.fromhex(fixture["artifactHex"]))
        document.write_text(json.dumps(fixture["document"], ensure_ascii=False), encoding="utf-8")
        key.write_text(base64.urlsafe_b64encode(bytes.fromhex(fixture["publicKeyHex"])).decode().rstrip("="), encoding="utf-8")
        args = ["verify", "--jar", str(jar), "--attestation", str(document), "--public-key", str(key),
                "--key-id", fixture["document"]["signature"]["keyId"]]
        cli(args, True)
        jar.write_bytes(jar.read_bytes() + b"tamper")
        cli(args, False)
        checked.append(name)
print(json.dumps({"offlineVerify": checked, "tamperedRejected": True}))
