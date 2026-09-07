"""Executes only the independently verified extracted CLI in an isolated bus.

No Node, repository checkout, host credential directory or network interface is
present. HTTP is synthetic loopback TLS; all credentials and keys are fixtures.
"""
import base64
import datetime
import http.server
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.parse

assert os.getuid() == 10001 and shutil.which("node") is None
binary = "/proof/provenance"
fixture = json.loads(pathlib.Path("/proof/vector.json").read_text())
scratch = pathlib.Path(tempfile.mkdtemp(prefix="cli-consumer-"))
jar, document, key = [scratch / name for name in ("fixture.jar", "document.json", "public-key")]
jar.write_bytes(bytes.fromhex(fixture["artifactHex"]))
document.write_text(json.dumps(fixture["document"], ensure_ascii=False))
key.write_text(base64.urlsafe_b64encode(bytes.fromhex(fixture["publicKeyHex"])).decode().rstrip("="))


def cli(*args, success=True):
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, (args[0], result.returncode, result.stdout, result.stderr)
    assert "fixture-session-credential" not in result.stdout + result.stderr
    return result


verify = ["verify", "--jar", str(jar), "--attestation", str(document), "--public-key", str(key), "--key-id", fixture["document"]["signature"]["keyId"]]
cli(*verify)
jar.write_bytes(jar.read_bytes() + b"tamper")
cli(*verify, success=False)
cert, private = scratch / "certificate.pem", scratch / "private.pem"
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(private), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True, timeout=20)
os.environ["SSL_CERT_FILE"] = str(cert)
counts = {"initiation": 0, "session": 0, "authenticatedReads": 0}
expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, code, body, cookie=None):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        assert int(self.headers["Content-Length"]) < 4096
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/auth/device-authorizations":
            assert body == {"clientName": "Provenance CLI"}
            counts["initiation"] += 1
            self.reply(201, {"deviceCode": "A" * 43, "userCode": "ABCD-EFGH", "verificationUri": "https://fixture.invalid/device", "expiresAt": expiry, "intervalSeconds": 1})
        elif self.path == "/v1/auth/device-authorizations/exchanges":
            assert body == {"deviceCode": "A" * 43}
            self.reply(200, {"exchangeToken": "B" * 42 + "A", "expiresAt": expiry})
        elif self.path == "/v1/auth/sessions":
            assert body == {"exchangeToken": "B" * 42 + "A"}
            counts["session"] += 1
            self.reply(201, {"id": "fixture-session", "userId": "fixture-user", "state": "active", "createdAt": "2026-01-01T00:00:00Z", "expiresAt": expiry}, "provenance_session=fixture-session-credential; Path=/; Secure; HttpOnly")
        else:
            self.reply(404, {})

    def do_GET(self):
        assert self.headers.get("Cookie") == "provenance_session=fixture-session-credential"
        counts["authenticatedReads"] += 1
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/v1/release-candidates/fixture-candidate":
            assert not url.query
            self.reply(200, {"id": "fixture-candidate", "state": "verified"})
        else:
            assert url.path in ["/v1/release-candidates/fixture-candidate/" + name for name in ("events", "executions")]
            assert urllib.parse.parse_qs(url.query) == {"limit": ["100"]}
            self.reply(200, {"items": [], "page": {"hasMore": False}})


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, private)
server.socket = context.wrap_socket(server.socket, server_side=True)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
origin = "https://127.0.0.1:" + str(server.server_port)
login = cli("auth", "login", "--origin", origin, "--timeout", "15s")
assert "ABCD-EFGH" in login.stdout and "A" * 43 not in login.stdout
cli("status", "--origin", origin, "--timeout", "15s", "--candidate", "fixture-candidate")
assert counts == {"initiation": 1, "session": 1, "authenticatedReads": 3}
# Exercise the actual native API lock, then require failure before issuance.
subprocess.run(["dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.secrets", "/org/freedesktop/secrets", "org.freedesktop.Secret.Service.Lock", "array:objpath:/org/freedesktop/secrets/collection/login"], check=True, capture_output=True, timeout=5)
cli("auth", "login", "--origin", origin, "--timeout", "3s", success=False)
assert counts == {"initiation": 1, "session": 1, "authenticatedReads": 3}
server.shutdown()
thread.join(timeout=5)
assert not thread.is_alive()
print(json.dumps({"extractedBinary": True, "nodeAbsent": True, "uid": os.getuid(), "signedFixture": "passed", "tamperedFixture": "rejected", "nativeSecretService": "actual", "storedSessionReadback": True, "lockedStorePreIssuance": True, "livePlatform": False}))
