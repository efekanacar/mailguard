import json
from email.message import EmailMessage
from pathlib import Path
import tempfile
import unittest
from mailguard.analyzer import MAX_BYTES, analyze, public_url
from mailguard.cli import main


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


if __name__ == "__main__":
    unittest.main()
