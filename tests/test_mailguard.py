import json
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from mailguard.analyzer import MAX_BYTES, analyze, public_url
from mailguard.cli import main
from mailguard.sandbox import Cuckoo, SandboxError


def sample():
    msg = EmailMessage()
    msg["From"] = "Support <support@example.org>"
    msg["To"] = "you@example.net"
    msg["Reply-To"] = "elsewhere@example.com"
    msg["Subject"] = "Hesap bildirimi"
    msg["Date"] = "Sat, 03 Oct 2026 12:00:00 +0300"
    msg["Message-ID"] = "<demo@example.org>"
    msg["Authentication-Results"] = "mx.example.net; spf=fail; dkim=fail; dmarc=fail"
    msg.set_content("https://example.org/login ve http://127.0.0.1/private")
    msg.add_attachment(b"inert test data", maintype="application", subtype="octet-stream", filename="../../sample.exe")
    return msg.as_bytes()


class AnalyzerTests(unittest.TestCase):
    def test_forged_auth_is_not_trusted(self):
        report, _ = analyze(sample())
        self.assertFalse(any(f["code"] == "authentication_failure" for f in report["findings"]))
        self.assertTrue(all(not x["trusted"] for x in report["authentication"]))

    def test_trusted_auth_failures_and_safe_attachment_name(self):
        report, targets = analyze(sample(), ["mx.example.net"])
        self.assertEqual(3, sum(f["code"] == "authentication_failure" for f in report["findings"]))
        self.assertEqual("yüksek", report["verdict"])
        file = next(t for t in targets if t["kind"] == "file")
        self.assertEqual("sample.exe", file["name"])
        self.assertEqual(b"inert test data", file["data"])
        self.assertEqual(64, len(report["attachments"][0]["sha256"]))

    def test_local_and_invalid_urls_rejected(self):
        for url in ["file:///etc/passwd", "http://localhost/x", "http://10.0.0.1", "http://[::1]", "https://user:pass@example.org", "http://host.internal", "http://[bad", "http://example.org:bad"]:
            self.assertFalse(public_url(url), url)
        self.assertTrue(public_url("https://example.org/a"))
        _, targets = analyze(sample())
        self.assertEqual(["https://example.org/login"], [t["url"] for t in targets if t["kind"] == "url"])

    def test_html_links_and_unknown_charset(self):
        raw = b'From: a@example.org\nContent-Type: text/html; charset=not-a-charset\n\n<a href="https://example.org/a?x=1&amp;y=2">Click</a>'
        report, targets = analyze(raw)
        self.assertTrue(any(t.get("url") == "https://example.org/a?x=1&y=2" for t in targets))

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            analyze(b"a" * (MAX_BYTES + 1))

    def test_lower_auth_header_is_not_trusted(self):
        raw = b'From: a@example.org\nAuthentication-Results: attacker.example; spf=pass\nAuthentication-Results: mx.example.net; spf=fail\n\nhello'
        report, _ = analyze(raw, ["mx.example.net"])
        self.assertFalse(any(f["code"] == "authentication_failure" for f in report["findings"]))
        self.assertFalse(report["authentication"][0]["trusted"])

    def test_cli_offline_json(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mail.eml"
            output = Path(directory) / "report.json"
            source.write_bytes(sample())
            self.assertEqual(0, main([str(source), "-o", str(output)]))
            report = json.loads(output.read_text())
            self.assertEqual("not_requested", report["sandbox"]["status"])


class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                cls.requests.append((self.path, self.headers.get("Authorization"), body))
                self.respond({"task_id": 7})

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/leaked")
                    self.end_headers()
                elif self.path.startswith("/tasks/view/"):
                    self.respond({"task": {"status": "reported"}})
                else:
                    self.respond({"info": {"score": 8}, "signatures": [{"name": "mock_detection"}]})

            def respond(self, data):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_multipart_submit_poll_report(self):
        result = Cuckoo(self.base, "test-token").run([{"kind": "file", "name": "sample.bin", "data": b"inert data", "sha256": "abc"}], 5)
        self.assertEqual("finished", result["status"])
        self.assertEqual(8, result["tasks"][0]["result"]["info"]["score"])
        path, auth, body = self.requests[-1]
        self.assertEqual("/tasks/create/file", path)
        self.assertEqual("Bearer test-token", auth)
        self.assertIn(b"inert data", body)

    def test_submission_only_is_pending(self):
        result = Cuckoo(self.base).run([{"kind": "url", "url": "https://example.org"}], 0)
        self.assertEqual("incomplete", result["status"])
        self.assertEqual("pending", result["tasks"][0]["status"])

    def test_redirect_token_not_forwarded(self):
        with self.assertRaises(SandboxError):
            Cuckoo(self.base, "secret").request("/redirect")

    def test_remote_http_rejected(self):
        with self.assertRaises(ValueError):
            Cuckoo("http://sandbox.example.org")

    def test_failed_submission_does_not_look_clean(self):
        client = Cuckoo(self.base)
        def unavailable(target):
            raise SandboxError("Sandbox unavailable")
        client.submit = unavailable
        result = client.run([{"kind": "url", "url": "https://example.org"}], 0)
        self.assertEqual("incomplete", result["status"])
        self.assertEqual("error", result["tasks"][0]["status"])


if __name__ == "__main__":
    unittest.main()
