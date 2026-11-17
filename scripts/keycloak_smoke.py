#!/usr/bin/env python3
"""Run an isolated Keycloak 26.4.5 browser integration; generated credentials stay temporary."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright, expect

IMAGE = "quay.io/keycloak/keycloak:26.4.5"

def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]

def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/nullgate")
    parser.add_argument("--artifacts", default="/tmp/nullgate-keycloak-smoke")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.binary).resolve())
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    name = f"nullgate-keycloak-{os.getpid()}-{secrets.token_hex(4)}"
    process = None
    kc_port, web_port = port(), port()
    # Different sites exercise real Sec-Fetch-Site: cross-site provider returns.
    issuer = f"http://localhost:{kc_port}/realms/nullgate"
    origin = f"http://127.0.0.1:{web_port}"
    secret = secrets.token_urlsafe(32)
    passwords = {user: secrets.token_urlsafe(24) for user in ["admin", "viewer", "unmapped"]}
    try:
        with tempfile.TemporaryDirectory(prefix="keycloak-fixture-", dir=artifacts) as temp:
            temp = Path(temp)
            imports = temp / "import"
            imports.mkdir(mode=0o700)
            realm = {
                "realm": "nullgate", "enabled": True, "sslRequired": "none",
                "registrationAllowed": False, "loginWithEmailAllowed": False,
                "roles": {"realm": [{"name": "nullgate-admin"}, {"name": "nullgate-viewer"}]},
                "clients": [{
                    "clientId": "nullgate", "enabled": True, "protocol": "openid-connect",
                    "publicClient": False, "secret": secret, "standardFlowEnabled": True,
                    "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
                    "redirectUris": [origin + "/api/v1/auth/oidc/callback"], "webOrigins": [origin],
                    "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": origin + "/login"},
                    "protocolMappers": [{"name": "nullgate-id-token-roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper", "config": {"multivalued": "true", "claim.name": "realm_access.roles", "jsonType.label": "String", "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "false"}}],
                }],
                "users": [{"username": "oidc-" + user, "enabled": True, "emailVerified": True,
                           "email": user + "@fixture.invalid", "firstName": "Fixture", "lastName": user,
                           "requiredActions": [], "credentials": [{"type": "password", "value": password, "temporary": False}],
                           "realmRoles": [] if user == "unmapped" else ["nullgate-" + user]}
                          for user, password in passwords.items()],
            }
            private_json(imports / "realm.json", realm)
            subprocess.run(docker + ["create", "--name", name, "--memory=768m", "-p", f"127.0.0.1:{kc_port}:8080", IMAGE, "start-dev", "--hostname=" + f"http://localhost:{kc_port}", "--import-realm", "--log-level=warn"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(docker + ["cp", "-a", str(imports), name + ":/opt/keycloak/data/import"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(docker + ["start", name], check=True, stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + 240
            while True:
                try:
                    with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", timeout=2) as response:
                        metadata = json.load(response)
                    assert metadata["issuer"] == issuer
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Keycloak fixture did not become ready") from None
                    time.sleep(1)
            secret_file = temp / "client-secret"
            descriptor = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(secret)
            config = temp / "nullgate.toml"
            config.write_text(f'''schema_version = 1
data_dir = "data"
[dns]
udp_listen = "127.0.0.1:0"
tcp_listen = "127.0.0.1:0"
upstreams = ["127.0.0.1:9"]
[http]
listen = "127.0.0.1:0"
[web]
listen = "127.0.0.1:{web_port}"
public_origin = "{origin}"
[auth]
mode = "oidc"
[oidc]
issuer = "{issuer}"
client_id = "nullgate"
redirect_uri = "{origin}/api/v1/auth/oidc/callback"
client_secret_file = "client-secret"
role_claim = "/realm_access/roles"
administrator_values = ["nullgate-admin"]
viewer_values = ["nullgate-viewer"]
''')
            log_path = artifacts / "runtime.log"
            with log_path.open("w") as log:
                process = subprocess.Popen([binary, "--config", str(config)], stdout=subprocess.DEVNULL, stderr=log, env={**os.environ, "RUST_LOG": "info"})
                deadline = time.monotonic() + 30
                while "runtime ready" not in log_path.read_text():
                    if process.poll() is not None:
                        raise RuntimeError("NullGate exited before OIDC readiness")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("NullGate did not become ready")
                    time.sleep(0.1)
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=["--no-sandbox"])
                    for user, role in [("admin", "administrator"), ("viewer", "viewer"), ("unmapped", None)]:
                        context = browser.new_context()
                        page = context.new_page()
                        page.goto(origin + "/login")
                        page.get_by_role("button", name="Continue with identity provider", exact=True).click()
                        page.locator('input[name="username"]').fill("oidc-" + user)
                        page.locator('input[name="password"]').fill(passwords[user])
                        page.locator("#kc-login").click()
                        if role is None:
                            page.wait_for_url(lambda url: url.startswith(origin + "/api/v1/auth/oidc/callback"))
                            expect(page.locator("body")).to_contain_text("Access denied")
                            assert context.request.get(origin + "/api/v1/auth/me").status == 401
                            context.close()
                            continue
                        page.wait_for_url(origin + "/")
                        me = context.request.get(origin + "/api/v1/auth/me")
                        assert me.status == 200 and me.json()["role"] == role
                        proof = context.request.get(origin + "/api/v1/auth/csrf").json()["csrf"]
                        saved = context.request.post(origin + "/api/v1/lists", headers={"Origin": origin, "X-CSRF-Token": proof}, data={"expected_revision": 0, "name": "Keycloak smoke"})
                        assert saved.status == (200 if user == "admin" else 403)
                        page.reload()
                        if user == "admin":
                            page.screenshot(path=str(artifacts / "keycloak-admin.png"), full_page=True)
                        page.get_by_role("button", name="Sign out", exact=True).click()
                        # No stored id_token_hint: Keycloak can require explicit logout confirmation.
                        deadline = time.monotonic() + 20
                        while not page.url.startswith(origin + "/login"):
                            confirm = page.locator("#kc-logout")
                            if confirm.count() and confirm.is_visible():
                                confirm.click()
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Provider logout did not return to NullGate")
                            page.wait_for_timeout(100)
                        assert context.request.get(origin + "/api/v1/auth/me").status == 401
                        context.close()
                    browser.close()
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=15) == 0
                process = None
            runtime = log_path.read_text()
            assert secret not in runtime and all(password not in runtime for password in passwords.values())
            assert "PRIVATE KEY" not in runtime and "nullgate_session=" not in runtime
        print(json.dumps({"result": "passed", "provider": IMAGE, "checks": ["authorization code with S256 PKCE", "confidential client", "explicit Administrator and Viewer mapping", "direct Viewer write denial", "unmapped denial", "RP-initiated provider logout", "cross-site callback and logout return", "credential-free logs", "clean shutdown"]}))
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        subprocess.run(docker + ["logs", name], stdout=(artifacts / "keycloak.log").open("w"), stderr=subprocess.STDOUT)
        subprocess.run(docker + ["rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    main()
