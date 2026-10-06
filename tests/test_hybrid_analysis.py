import contextlib
import io
import json
from email.message import EmailMessage
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from mailguard.sandbox import API_BASE, HybridAnalysis, MAX_RESPONSE, NoRedirect, SandboxError
from mailguard.cli import main

HASH = "a" * 64
FILE = {"kind": "file", "name": "sample.bin", "data": b"inert data", "sha256": HASH}
URL = {"kind": "url", "url": "https://example.org/a?x=1&y=two"}


class FakeAPI:
    """Capture real urllib Request objects; no external traffic or live keys."""
    def __init__(self, state="SUCCESS", errors=None, overrides=None):
        self.calls = []
        self.state = state
        self.errors = errors or {}
        self.overrides = overrides or {}

    def open(self, request, timeout):
        self.calls.append(request)
        path = urlsplit(request.full_url).path.removeprefix("/api/v2")
        if path in self.errors:
            raise HTTPError(request.full_url, self.errors[path], "error", {"Retry-After": "30"}, None)
        if path in self.overrides:
            value = self.overrides[path]
        elif path.startswith("/submit/"):
            value = {"job_id": "job-123", "sha256": HASH, "environment_id": 160}
        elif path.endswith("/state"):
            value = {"state": self.state}
        elif path.endswith("/summary"):
            value = {"state": "SUCCESS", "job_id": "job-123", "verdict": "malicious", "threat_score": 90}
        elif path == "/system/environments":
            value = [{"environment_id": 160, "description": "Windows 10 64 bit"}]
        else:
            raise AssertionError(path)
        return io.BytesIO(json.dumps(value).encode())


class HybridAnalysisTests(unittest.TestCase):
    def client(self, api=None):
        return HybridAnalysis("fake-test-key", opener=api or FakeAPI())

    def test_file_multipart_headers_and_report(self):
        api = FakeAPI()
        result = self.client(api).run([FILE], 5)
        self.assertEqual("finished", result["status"])
        self.assertEqual("malicious", result["tasks"][0]["verdict"])
        self.assertEqual(90, result["tasks"][0]["threat_score"])
        req = api.calls[0]
        self.assertEqual(API_BASE + "/submit/file", req.full_url)
        self.assertEqual("fake-test-key", req.get_header("Api-key"))
        self.assertEqual("Falcon Sandbox", req.get_header("User-agent"))
        self.assertIn(b'name="environment_id"\r\n\r\n160', req.data)
        self.assertIn(b'filename="sample.bin"', req.data)
        self.assertIn(b"inert data", req.data)
        self.assertNotIn("fake-test-key", json.dumps(result))

    def test_url_uses_current_endpoint_and_form_encoding(self):
        api = FakeAPI()
        self.client(api).submit(URL)
        req = api.calls[0]
        self.assertEqual(API_BASE + "/submit/url", req.full_url)
        self.assertEqual({"url": [URL["url"]], "environment_id": ["160"]}, parse_qs(req.data.decode()))

    def test_wait_zero_keeps_job_id_pending(self):
        api = FakeAPI()
        result = self.client(api).run([URL], 0)
        self.assertEqual(1, len(api.calls))
        self.assertEqual("pending", result["tasks"][0]["status"])
        self.assertEqual("job-123", result["tasks"][0]["job_id"])
        self.assertEqual("incomplete", result["status"])

    def test_error_state_is_not_reported_as_clean(self):
        result = self.client(FakeAPI(state="ERROR")).run([FILE], 5)
        self.assertEqual("failed", result["tasks"][0]["status"])
        self.assertEqual("incomplete", result["status"])

    def test_unknown_state_is_pending(self):
        result = self.client(FakeAPI(state="QUEUED")).report("job-123")
        self.assertEqual("pending", result["status"])

    def test_rate_limit_stops_further_submissions(self):
        api = FakeAPI(errors={"/submit/file": 429})
        result = self.client(api).run([FILE, URL], 5)
        self.assertEqual(1, len(api.calls))
        self.assertEqual(1, result["skipped_targets"])
        self.assertEqual(30, result["tasks"][0]["retry_after_seconds"])
        self.assertEqual("incomplete", result["status"])

    def test_polling_rate_limit_keeps_remaining_jobs_pending(self):
        api = FakeAPI(errors={"/report/job-123/state": 429})
        result = self.client(api).run([FILE, URL], 5)
        self.assertEqual(["error", "pending"], [t["status"] for t in result["tasks"]])
        self.assertEqual(3, len(api.calls))

    def test_auth_failure_is_actionable(self):
        for status in (401, 403):
            api = FakeAPI(errors={"/submit/file": status})
            result = self.client(api).run([FILE, URL], 5)
            self.assertEqual(1, len(api.calls))
            self.assertEqual(status, result["tasks"][0]["http_status"])

    def test_duplicate_and_capped_targets(self):
        result = self.client().run([FILE, FILE, URL], 5, max_targets=1)
        self.assertEqual(1, result["duplicate_targets"])
        self.assertEqual(1, result["skipped_targets"])
        self.assertEqual("incomplete", result["status"])

    def test_missing_and_invalid_credentials(self):
        for key in ("", "key\nsecret", "key with spaces"):
            with self.assertRaises(ValueError):
                HybridAnalysis(key)

    def test_malformed_submission_response(self):
        for value in ([], {"job_id": "../evil"}, {}, {"job_id": 123}):
            with self.assertRaises(SandboxError):
                self.client(FakeAPI(overrides={"/submit/file": value})).submit(FILE)

    def test_malformed_state_and_summary(self):
        for path, value in [("/report/job-123/state", []), ("/report/job-123/state", {"state": None}),
                            ("/report/job-123/summary", {"state": None}), ("/report/job-123/summary", {"state": "QUEUED"})]:
            with self.assertRaises(SandboxError):
                self.client(FakeAPI(overrides={path: value})).report("job-123")

    def test_summary_410_is_not_success(self):
        result = self.client(FakeAPI(errors={"/report/job-123/summary": 410})).run([FILE], 5)
        self.assertEqual("error", result["tasks"][0]["status"])
        self.assertEqual(410, result["tasks"][0]["http_status"])

    def test_local_url_rejected_before_request(self):
        api = FakeAPI()
        with self.assertRaises(SandboxError):
            self.client(api).submit({"kind": "url", "url": "http://127.0.0.1/a"})
        self.assertEqual([], api.calls)

    def test_filename_header_injection_rejected(self):
        api = FakeAPI()
        with self.assertRaises(SandboxError):
            self.client(api).submit({**FILE, "name": 'x"\r\nInjected: bad'})
        self.assertEqual([], api.calls)

    def test_redirect_handler_refuses_credentials_forwarding(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))

    def test_invalid_json_and_large_response(self):
        class RawAPI:
            def __init__(self, raw):
                self.raw = raw
            def open(self, request, timeout):
                return io.BytesIO(self.raw)
        for raw in (b"not json", b"a" * (MAX_RESPONSE + 1)):
            with self.assertRaises(SandboxError):
                self.client(RawAPI(raw)).environments()

    def test_list_environments(self):
        self.assertEqual(160, self.client().environments()[0]["environment_id"])

    def test_cli_requires_explicit_upload_acceptance(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main(["mail.eml", "--submit"])
        self.assertEqual(2, exc.exception.code)

    def test_cli_missing_key_no_file_read(self):
        with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(1, main(["missing.eml", "--submit", "--accept-upload"]))
        self.assertIn("HYBRID_ANALYSIS_API_KEY", err.getvalue())

    def test_cli_existing_job_does_not_submit(self):
        api = FakeAPI()
        with patch("mailguard.cli.HybridAnalysis", return_value=self.client(api)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(["--job-id", "job-123"]))
        self.assertTrue(all(req.get_method() == "GET" for req in api.calls))

    def test_cli_eml_to_sandbox_report_with_environment_key(self):
        api = FakeAPI()
        mail = EmailMessage()
        mail["From"] = "sender@example.org"
        mail.set_content("https://example.org/login")
        mail.add_attachment(b"inert content", maintype="application", subtype="octet-stream", filename="test.exe")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mail.eml"
            output = Path(directory) / "report.json"
            source.write_bytes(mail.as_bytes())
            with patch.dict("os.environ", {"HYBRID_ANALYSIS_API_KEY": "test-env-key"}), \
                    patch("mailguard.sandbox.build_opener", return_value=api), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = main([str(source), "--submit", "--accept-upload", "--environment-id", "330", "-o", str(output)])
            report = json.loads(output.read_text())
            self.assertEqual(0, code)
            self.assertEqual("finished", report["sandbox"]["status"])
            self.assertEqual(2, len(report["sandbox"]["tasks"]))
            self.assertNotIn("test-env-key", output.read_text())
            self.assertTrue(all(req.get_header("Api-key") == "test-env-key" for req in api.calls))
            self.assertIn(b'name="environment_id"\r\n\r\n330', api.calls[0].data)
            self.assertEqual(["330"], parse_qs(api.calls[1].data.decode())["environment_id"])


if __name__ == "__main__":
    unittest.main()
