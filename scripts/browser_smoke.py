#!/usr/bin/env python3
"""Real Chromium smoke test against local DNS/HTTP fixtures and a temporary NullGate."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from playwright.sync_api import sync_playwright, expect, Error as BrowserError

class Origin(BaseHTTPRequestHandler):
    requests = 0
    def do_GET(self):
        Origin.requests += 1
        body = b"<h1>Local upstream fixture</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/nullgate")
    parser.add_argument("--artifacts", default="/tmp/nullgate-browser-smoke")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.binary).resolve())
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("127.0.0.1", 0))
    target = f"http://127.0.0.1:{origin.server_address[1]}"
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="fixture-", dir=artifacts) as temp:
            temp = Path(temp)
            config = temp / "nullgate.toml"
            config.write_text(f'''schema_version = 1
data_dir = "data"
[dns]
udp_listen = "127.0.0.1:0"
tcp_listen = "127.0.0.1:0"
upstreams = ["127.0.0.1:{dns.getsockname()[1]}"]
[http]
listen = "127.0.0.1:0"
[web]
listen = "127.0.0.1:0"
''')
            password = "unique browser fixture password"
            secret = temp / "password.txt"
            descriptor = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(password)
            provision = subprocess.run([binary, "provision-admin", "--config", str(config), "--username", "browser-admin", "--password-file", str(secret)], capture_output=True, text=True, timeout=30)
            assert provision.returncode == 0, "Fixture administrator provisioning failed"
            secret.unlink()
            log_path = artifacts / "runtime.log"
            with log_path.open("w") as output:
                process = subprocess.Popen([binary, "--config", str(config)], stdout=subprocess.DEVNULL, stderr=output, env={**os.environ, "RUST_LOG": "info"})
                deadline = time.monotonic() + 30
                while True:
                    log = log_path.read_text()
                    ready = next((line for line in log.splitlines() if "runtime ready" in line), None)
                    if ready:
                        fields = dict(re.findall(r"\b(dns_udp|dns_tcp|http|web|web_origin)=([^\s]+)", ready))
                        break
                    assert process.poll() is None, "Runtime failed before readiness"
                    assert time.monotonic() < deadline, "Runtime readiness timed out"
                    time.sleep(.02)
                def filtered(path):
                    connection = http.client.HTTPConnection(fields["http"], timeout=5)
                    connection.request("GET", target + path, headers={"Host": target.split("://")[1]})
                    response = connection.getresponse()
                    status, body = response.status, response.read()
                    connection.close()
                    return status, body
                assert filtered("/ads")[0] == 200
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=["--no-sandbox", "--disable-background-networking", "--disable-component-update", "--no-first-run"])
                    native_context = browser.new_context(java_script_enabled=False)
                    native = native_context.new_page()
                    native.goto(fields["web_origin"] + "/login")
                    native.get_by_label("Username", exact=True).fill("browser-admin")
                    native.get_by_label("Password", exact=True).fill(password)
                    with native.expect_request(lambda request: "/api/v1/auth/login" in request.url) as submitted:
                        native.get_by_role("button", name="Sign in", exact=True).click()
                    assert submitted.value.method == "POST"
                    assert "?" not in submitted.value.url
                    native_context.close()
                    context = browser.new_context(viewport={"width": 1360, "height": 1000})
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(fields["web_origin"])
                    expect(page.get_by_role("heading", name="Welcome back")).to_be_visible()
                    page.get_by_label("Username", exact=True).fill("browser-admin")
                    page.get_by_label("Password", exact=True).fill(password)
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    expect(page.get_by_role("heading", name="Blocklists", exact=True)).to_be_visible(timeout=15000)
                    page.get_by_label("New blocklist", exact=True).fill("Browser smoke")
                    page.get_by_role("button", name="Create list", exact=True).click()
                    expect(page.get_by_role("heading", name="Browser smoke", exact=True)).to_be_visible()
                    page.get_by_label("One domain or URL per line", exact=True).fill(target + "/ads\nbad rule\nblocked.invalid")
                    page.get_by_role("button", name="Add rules", exact=True).click()
                    expect(page.locator("#feedback")).to_contain_text("Line 2:")
                    assert filtered("/ads?ignored=1") == (403, b"")
                    assert filtered("/sibling")[0] == 200
                    # Verify the effect through a second real browser context as well.
                    filtered_context = browser.new_context(proxy={"server": "http://" + fields["http"], "bypass": "<-loopback>"})
                    filtered_page = filtered_context.new_page()
                    try:
                        response = filtered_page.goto(target + "/ads", wait_until="domcontentloaded")
                        assert response.status == 403
                    except BrowserError as error:
                        # Chromium may render its own network error for an empty 403.
                        assert "ERR_HTTP_RESPONSE_CODE_FAILURE" in str(error)
                        assert filtered("/ads") == (403, b"")
                    filtered_page.close()
                    filtered_page = filtered_context.new_page()
                    response = filtered_page.goto(target + "/sibling")
                    assert response.status == 200
                    filtered_context.close()
                    upload = temp / "rules.txt"
                    upload.write_text("*.tracking.invalid\nhttps://news.invalid/ads\nbad file entry\n")
                    page.locator('input[type="file"]').set_input_files(upload)
                    page.get_by_role("button", name="Import file", exact=True).click()
                    expect(page.locator("#feedback")).to_contain_text("Line 3:")
                    expect(page.get_by_role("link", name=re.compile("rules.txt"))).to_be_visible()
                    page.screenshot(path=str(artifacts / "blocklists.png"), full_page=True)
                    row = page.locator("tbody tr").filter(has_text=target + "/ads")
                    # Capture the expected revision before the application's successful-save reload.
                    revision = int(row.locator('input[name="expected_revision"]').input_value()) + 1
                    with page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/remove")) as removed:
                        row.get_by_role("button", name="Remove", exact=True).click()
                    assert removed.value.status == 200
                    expect(page.locator("#feedback")).to_contain_text(f"Saved revision {revision}.")
                    assert filtered("/ads")[0] == 200
                    with page.expect_download() as downloaded:
                        page.get_by_role("link", name="Download public CA", exact=True).click()
                    download = downloaded.value
                    assert download.suggested_filename == "nullgate-inspection-ca.pem"
                    certificate = Path(download.path()).read_bytes()
                    assert certificate.count(b"-----BEGIN CERTIFICATE-----") == 1
                    assert b"PRIVATE KEY" not in certificate
                    private_bundle = (temp / "data" / "inspection-ca" / "material.bin").read_bytes()
                    cert_size = int.from_bytes(private_bundle[8:12], "big")
                    private_key = private_bundle[16 + cert_size:]
                    assert private_key not in certificate
                    (artifacts / "inspection-ca.pem").write_bytes(certificate)
                    # Production fetch policy must deny the local origin before any HTTP access.
                    before = Origin.requests
                    page.locator('input[name="url"]').fill(target + "/remote-list")
                    with page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/remote")) as attempted:
                        page.get_by_role("button", name="Fetch remote rules", exact=True).click()
                    assert attempted.value.status == 502
                    result = attempted.value.json()
                    assert result["code"] == "destination_denied" and result["revision"] > revision
                    expect(page.locator("#feedback")).to_contain_text("Attempt recorded")
                    assert Origin.requests == before
                    page.reload()
                    page.get_by_role("link", name="Remote: " + target).click()
                    with page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/refresh")) as refreshed:
                        page.get_by_role("button", name="Refresh remote source", exact=True).click()
                    assert refreshed.value.status == 502
                    assert refreshed.value.json()["code"] == "destination_denied"
                    expect(page.locator("#feedback")).to_contain_text("Attempt recorded")
                    assert Origin.requests == before
                    page.screenshot(path=str(artifacts / "remote-refresh.png"), full_page=True)
                    assert not errors, "Browser JavaScript error"
                    context.close()
                    browser.close()
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=15) == 0
                process = None
            log = log_path.read_text()
            assert password not in log and "nullgate_session=" not in log
            assert "PRIVATE KEY" not in log
            assert private_key not in log.encode()
            assert "runtime stopped" in log
        print(json.dumps({"result": "passed", "checks": ["local Administrator login", "list creation", "mixed manual import diagnostics", "browser and HTTP proxy 200->403", "file import diagnostics", "rule removal 403->200", "remote import/refresh denies private destination before fetch", "Administrator public-CA download without private key", "clean shutdown"], "screenshot": str(artifacts / "blocklists.png")}))
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        origin.shutdown()
        origin.server_close()
        dns.close()

if __name__ == "__main__":
    main()
