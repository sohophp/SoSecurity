#!/usr/bin/env python3
"""Local TLS provider exercise for the exact StrictClient, with no external service."""
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def run(command, **kwargs):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError("Command failed: " + " ".join(str(part) for part in command[:3])
                           + "\n" + result.stderr.decode("utf-8", "replace")[:1200])
    return result.stdout


def signed_token(key, claims, corrupt=False, token_type="JWT"):
    header = b64(json.dumps({"typ": token_type, "alg": "RS256", "kid": "local-key"}, separators=(",", ":")).encode())
    body = b64(json.dumps(claims, separators=(",", ":")).encode())
    content = (header + "." + body).encode()
    signature = run(["openssl", "dgst", "-sha256", "-sign", str(key)], input=content)
    if corrupt:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    return content.decode() + "." + b64(signature)


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def answer(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/keys":
            self.server.key_requests += 1
            if self.server.key_mode == "redirect":
                self.send_response(302)
                self.send_header("Location", self.server.issuer + "/unapproved")
                self.end_headers()
                return
            if self.server.key_mode == "oversize":
                self.send_response(200)
                self.send_header("Content-Length", "131073")
                self.end_headers()
                self.wfile.write(b"x" * 131073)
                return
            self.answer(200, self.server.jwks)
        else:
            self.server.other_requests += 1
            self.answer(404, {"error": "unapproved endpoint"})

    def do_POST(self):
        if self.path != "/token":
            self.server.other_requests += 1
            self.answer(404, {"error": "unapproved endpoint"})
            return
        self.server.token_requests += 1
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            self.answer(413, {"error": "large request"})
            return
        fields = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
        expected_basic = "Basic " + base64.b64encode(("registered-client:" + "s" * 32).encode()).decode()
        if (self.headers.get("Authorization") != expected_basic
                or fields.get("code") != ["single-use-code"]
                or fields.get("code_verifier") != [self.server.verifier]
                or fields.get("grant_type") != ["authorization_code"]):
            self.answer(400, {"error": "invalid_grant"})
            return
        if self.server.token_mode == "redirect":
            self.send_response(302)
            self.send_header("Location", self.server.issuer + "/unapproved")
            self.end_headers()
            return
        if self.server.token_mode == "oversize":
            self.send_response(200)
            self.send_header("Content-Length", "131073")
            self.end_headers()
            self.wfile.write(b"x" * 131073)
            return
        self.answer(200, {"access_token": "local-access-token", "id_token": self.server.id_token})


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: tls_integration.py /path/to/vendor/autoload.php php72")
    autoload = Path(sys.argv[1]).resolve()
    runtime = sys.argv[2]
    runner = Path(__file__).with_name("tls-client.php")
    with tempfile.TemporaryDirectory(prefix="sosecurity-oidc-tls-") as directory:
        base = Path(directory)
        certificate = base / "cert.pem"
        key = base / "key.pem"
        sessions = base / "sessions"
        sessions.mkdir(mode=0o700)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
             "-keyout", str(key), "-out", str(certificate)])
        key_details = run([runtime, "-r", """
            $key = openssl_pkey_get_private(file_get_contents($argv[1]));
            $rsa = openssl_pkey_get_details($key)['rsa'];
            $encode = function ($v) { return rtrim(strtr(base64_encode($v), '+/', '-_'), '='); };
            echo json_encode(['n' => $encode($rsa['n']), 'e' => $encode($rsa['e'])]);
        """, str(key)])
        rsa = json.loads(key_details)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.jwks = {"keys": [{"kty": "RSA", "kid": "local-key", "alg": "RS256", "use": "sig", **rsa}]}
        server.token_requests = server.key_requests = server.other_requests = 0
        server.token_mode = server.key_mode = "normal"
        server.verifier = ""
        server.id_token = ""
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        issuer = "https://localhost:" + str(server.server_port)
        server.issuer = issuer
        environment = os.environ.copy()
        environment.update({"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"})
        checks = 0
        try:
            for case in ("valid", "wrong-state", "bad-signature", "wrong-nonce", "untrusted-cert",
                         "redirect-token", "oversize-token", "redirect-keys", "oversize-keys"):
                session_id = "oidc-" + os.urandom(8).hex()
                common = [runtime, "-d", "curl.cainfo=" + str(certificate), "-d", "openssl.cafile=" + str(certificate),
                          str(runner), str(autoload), issuer, str(sessions), session_id]
                begin = json.loads(run(common + ["begin", "-"], env=environment))
                if not all(isinstance(begin.get(field), str) and begin[field] for field in ("state", "nonce", "verifier")):
                    raise AssertionError("Authorization state was not persisted")
                checks += 1
                server.verifier = begin["verifier"]
                server.token_mode = case.split("-", 1)[0] if case.endswith("-token") else "normal"
                server.key_mode = case.split("-", 1)[0] if case.endswith("-keys") else "normal"
                claims = {"iss": issuer, "sub": "external-subject", "sid": "provider-session", "aud": "registered-client",
                          "nonce": begin["nonce"], "iat": int(__import__("time").time()), "exp": int(__import__("time").time()) + 300}
                if case == "wrong-nonce":
                    claims["nonce"] = "wrong-nonce"
                server.id_token = signed_token(key, claims, case == "bad-signature")
                before_tokens, before_keys, before_other = (server.token_requests, server.key_requests,
                                                             server.other_requests)
                callback = common + ["callback_fence" if case == "valid" else "callback",
                                     "wrong-state" if case == "wrong-state" else begin["state"]]
                logout_input = None
                if case == "valid":
                    logout_claims = {"iss": issuer, "sub": "external-subject", "sid": "provider-session",
                                     "aud": "registered-client", "iat": claims["iat"], "jti": "callback-fence",
                                     "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
                    logout_input = signed_token(key, logout_claims, token_type="logout+jwt").encode()
                if case == "untrusted-cert":
                    callback[2] = "curl.cainfo=" + str(base / "missing-ca.pem")
                    callback[4] = "openssl.cafile=" + str(base / "missing-ca.pem")
                result = json.loads(run(callback, env=environment, input=logout_input))
                if case == "valid":
                    if result != {"ok": True, "issuer": issuer, "subject": "external-subject",
                                  "sid": "provider-session", "issued_at": claims["iat"],
                                  "linked": "local-alice", "federated": True, "fenced": True}:
                        raise AssertionError("Valid signed callback did not create exact-client proof: " + str(result))
                    if server.token_requests != before_tokens + 1 or server.key_requests != before_keys + 2:
                        raise AssertionError("Valid callback and logout did not use token and key HTTPS endpoints")
                    replay = json.loads(run(callback, env=environment, input=logout_input))
                    if replay.get("ok") is not False or server.token_requests != before_tokens + 1:
                        raise AssertionError("Consumed callback state was reused")
                    checks += 1
                elif case in ("wrong-state", "untrusted-cert"):
                    if result.get("ok") is not False or server.token_requests != before_tokens:
                        raise AssertionError(case + " reached the token endpoint")
                elif case in ("redirect-token", "oversize-token", "redirect-keys", "oversize-keys"):
                    if result.get("ok") is not False or server.token_requests != before_tokens + 1:
                        raise AssertionError(case + " was accepted")
                    expected_keys = before_keys + (1 if case.endswith("-keys") else 0)
                    if server.key_requests != expected_keys:
                        raise AssertionError(case + " used the wrong number of key requests")
                elif result.get("ok") is not False or server.token_requests != before_tokens + 1:
                    raise AssertionError(case + " was not rejected after token exchange")
                if server.other_requests != before_other:
                    raise AssertionError("Implicit discovery or other unapproved endpoint was requested")
                checks += 3

            server.token_mode = server.key_mode = "normal"
            logout_cases = ("valid", "sid-only", "both-targets", "multi-audience", "bad-signature",
                            "wrong-issuer", "wrong-audience", "old-issued", "missing-target",
                            "null-sub", "null-sid", "wrong-azp", "null-azp",
                            "nonce", "wrong-event", "wrong-type", "oversize")
            for case in logout_cases:
                now = int(__import__("time").time())
                claims = {"iss": issuer, "sub": "external-subject", "aud": "registered-client",
                          "iat": now, "jti": "local-logout-id",
                          "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
                if case == "sid-only":
                    del claims["sub"]
                    claims["sid"] = "provider-session"
                if case == "both-targets":
                    claims["sid"] = "provider-session"
                if case == "multi-audience":
                    claims["aud"] = ["registered-client", "another-client"]
                    claims["azp"] = "registered-client"
                if case == "wrong-issuer":
                    claims["iss"] = "https://other.example.test"
                if case == "wrong-audience":
                    claims["aud"] = "other-client"
                if case == "old-issued":
                    claims["iat"] = now - 90000
                if case == "missing-target":
                    del claims["sub"]
                if case == "null-sub":
                    claims["sub"] = None
                    claims["sid"] = "provider-session"
                if case == "null-sid":
                    claims["sid"] = None
                if case == "wrong-azp":
                    claims["azp"] = "another-client"
                if case == "null-azp":
                    claims["azp"] = None
                if case == "nonce":
                    claims["nonce"] = "forbidden"
                if case == "wrong-event":
                    claims["events"] = {"other-event": {}}
                token = signed_token(key, claims, case == "bad-signature",
                                     "JWT" if case == "wrong-type" else "logout+jwt")
                if case == "oversize":
                    token += "a" * 16384
                before_keys = server.key_requests
                command = [runtime, "-d", "curl.cainfo=" + str(certificate), "-d", "openssl.cafile=" + str(certificate),
                           str(runner), str(autoload), issuer, str(sessions), "oidc-" + os.urandom(8).hex(),
                           "logout", "-"]
                result = json.loads(run(command, env=environment, input=token.encode()))
                if case in ("valid", "sid-only", "both-targets", "multi-audience"):
                    expected = {"ok": True, "issuer": issuer,
                                "subject": None if case == "sid-only" else "external-subject",
                                "sid": "provider-session" if case in ("sid-only", "both-targets") else None,
                                "jti": "local-logout-id"}
                    if result != expected or server.key_requests != before_keys + 1:
                        raise AssertionError("Valid Logout Token rejected: " + case + " " + str(result))
                elif result.get("ok") is not False:
                    raise AssertionError("Invalid Logout Token accepted: " + case)
                if server.other_requests:
                    raise AssertionError("Logout verification requested an unapproved endpoint")
                checks += 2

            for receipt_case in ("normal", "failed", "thrown", "interrupted"):
                now = int(__import__("time").time())
                claims = {"iss": issuer, "sub": "external-subject", "aud": "registered-client",
                          "iat": now, "jti": "receipt-" + receipt_case,
                          "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
                token = signed_token(key, claims, token_type="logout+jwt")
                base_command = [runtime, "-d", "curl.cainfo=" + str(certificate),
                                "-d", "openssl.cafile=" + str(certificate), str(runner), str(autoload),
                                issuer, str(sessions), "oidc-" + os.urandom(8).hex(), "logout_process"]

                def process(behavior):
                    return json.loads(run(base_command + [behavior], env=environment, input=token.encode()))

                if receipt_case == "normal":
                    if process("success") != {"ok": True, "calls": 1, "revoked": True}:
                        raise AssertionError("Initial durable logout failed")
                    checks += 1
                elif receipt_case in ("failed", "thrown"):
                    if process("throw" if receipt_case == "thrown" else "fail") != {"ok": False, "calls": 1, "revoked": False}:
                        raise AssertionError("Failed host revocation was acknowledged")
                    checks += 1
                    if process("success") != {"ok": True, "calls": 1, "revoked": True}:
                        raise AssertionError("Pending logout could not be retried")
                    checks += 1
                else:
                    aborted = subprocess.run(base_command + ["abort"], env=environment, input=token.encode(),
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                    if aborted.returncode != 7:
                        raise AssertionError("Local process was not interrupted after revocation")
                    checks += 1
                    if process("success") != {"ok": True, "calls": 1, "revoked": True}:
                        raise AssertionError("Interrupted logout was prematurely acknowledged")
                    checks += 1
                if process("success") != {"ok": True, "calls": 0, "revoked": True}:
                    raise AssertionError("Completed logout repeated the host revocation")
                checks += 1
                collision = dict(claims)
                collision["sid"] = "different-provider-session"
                other_token = signed_token(key, collision, token_type="logout+jwt")
                collided = json.loads(run(base_command + ["success"], env=environment, input=other_token.encode()))
                if collided["ok"] is not False or collided["calls"] != 0:
                    raise AssertionError("Same jti with different signed content was accepted")
                checks += 1
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        print("PASS exact-client local TLS OIDC callback/logout:", checks, "assertions", runtime)


if __name__ == "__main__":
    main()
