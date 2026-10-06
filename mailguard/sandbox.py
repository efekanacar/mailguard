"""Hybrid Analysis API v2. Samples are executed by the hosted sandbox."""
import json
import re
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from .analyzer import MAX_TARGETS, defang, public_url

API_BASE = "https://hybrid-analysis.com/api/v2"
DEFAULT_ENVIRONMENT = 160
DEFAULT_MAX_TARGETS = 5
MAX_RESPONSE = 10 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SandboxError(Exception):
    def __init__(self, message, http_status=None, retry_after=None):
        super().__init__(message)
        self.http_status = http_status
        self.retry_after = retry_after


class HybridAnalysis:
    def __init__(self, api_key, environment_id=DEFAULT_ENVIRONMENT, request_timeout=15, *, opener=None):
        if not api_key or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise ValueError("Hybrid Analysis API anahtarı eksik/geçersiz. HYBRID_ANALYSIS_API_KEY ayarlayın.")
        if type(environment_id) is not int or environment_id <= 0:
            raise ValueError("environment_id pozitif bir sayı olmalı.")
        self.api_key = api_key
        self.environment_id = environment_id
        self.timeout = request_timeout
        # Fixed official host, verified TLS, no proxy or credential-bearing redirects.
        self.opener = opener if opener is not None else build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path, data=None, content_type=None):
        headers = {"Accept": "application/json", "api-key": self.api_key, "User-Agent": "Falcon Sandbox"}
        if content_type:
            headers["Content-Type"] = content_type
        req = Request(API_BASE + path, data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise SandboxError("Hybrid Analysis yanıtı 10 MiB sınırını aştı.")
                return json.loads(raw)
        except HTTPError as exc:
            messages = {
                400: "Gönderim reddedildi: dosya/URL türünü ve environment-id değerini kontrol edin.",
                401: "Hybrid Analysis API anahtarı kabul edilmedi.",
                403: "API anahtarının bu işleme yetkisi yok; hesap/anahtar izinlerini kontrol edin.",
                404: "Hybrid Analysis görevi/uç noktası bulunamadı.",
                410: "Bu hedefin tek raporu yok; ilgili alt raporları Hybrid Analysis panelinde inceleyin.",
                429: "Hybrid Analysis API kotası/hız sınırı aşıldı; daha sonra tekrar sorgulayın."
            }
            retry = exc.headers.get("Retry-After", "") if exc.headers else ""
            retry = min(int(retry), 3600) if retry.isdigit() and len(retry) < 8 else None
            raise SandboxError(messages.get(exc.code, f"Hybrid Analysis HTTP {exc.code}."), exc.code, retry) from None
        except (URLError, TimeoutError, OSError, ValueError):
            # Never echo remote payloads, credentials, or exception URLs.
            raise SandboxError("Hybrid Analysis bağlantısı/JSON yanıtı başarısız.") from None

    def environments(self):
        result = self.request("/system/environments")
        if not isinstance(result, list) or any(not isinstance(x, dict) for x in result):
            raise SandboxError("Hybrid Analysis ortam listesi geçersiz.")
        return result

    @staticmethod
    def job_id(value):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise SandboxError("Hybrid Analysis job_id geçersiz veya eksik.")
        return value

    def submit(self, target):
        if target["kind"] == "file":
            boundary = "mailguard" + secrets.token_hex(16)
            name = target["name"]
            if not re.fullmatch(r"sample(?:\.[a-zA-Z0-9]{1,8})?", name):
                raise SandboxError("Ek gönderim adı güvenli değil.")
            fields = (
                f'--{boundary}\r\nContent-Disposition: form-data; name="environment_id"\r\n\r\n{self.environment_id}\r\n'
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n'
            ).encode()
            body = fields + target["data"] + f"\r\n--{boundary}--\r\n".encode()
            result = self.request("/submit/file", body, "multipart/form-data; boundary=" + boundary)
        elif target["kind"] == "url" and public_url(target["url"]):
            body = urlencode({"url": target["url"], "environment_id": self.environment_id}).encode()
            result = self.request("/submit/url", body, "application/x-www-form-urlencoded")
        else:
            raise SandboxError("Uygun dosya veya genel HTTP/HTTPS URL hedefi bulunamadı.")
        if not isinstance(result, dict):
            raise SandboxError("Hybrid Analysis gönderim yanıtı geçersiz.")
        return {"job_id": self.job_id(result.get("job_id")), "sha256": result.get("sha256"),
                "environment_id": result.get("environment_id", self.environment_id)}

    def report(self, job_id):
        job_id = self.job_id(job_id)
        state = self.request(f"/report/{job_id}/state")
        if not isinstance(state, dict) or not isinstance(state.get("state"), str):
            raise SandboxError("Hybrid Analysis görev durumu yanıtı geçersiz.")
        remote_state = state["state"].upper()
        if remote_state == "SUCCESS":
            summary = self.request(f"/report/{job_id}/summary")
            if not isinstance(summary, dict) or not isinstance(summary.get("state"), str) or summary["state"].upper() != "SUCCESS":
                raise SandboxError("Hybrid Analysis tamamlanmış raporu henüz hazır değil/geçersiz.")
            return {"status": "reported", "remote_status": remote_state,
                    "verdict": summary.get("verdict"), "threat_score": summary.get("threat_score"), "result": summary}
        if remote_state in {"ERROR", "FAILED", "CANCELLED", "CANCELED"}:
            return {"status": "failed", "remote_status": remote_state,
                    "error": "Hybrid Analysis analizi başarısız; panelde job_id ile inceleyin."}
        return {"status": "pending", "remote_status": remote_state}

    def run(self, targets, wait_seconds=120, max_targets=DEFAULT_MAX_TARGETS, poll_interval=15):
        if type(max_targets) is not int or not 1 <= max_targets <= MAX_TARGETS:
            raise ValueError("max-targets 1 ile 20 arasında olmalı.")
        if not 0 <= wait_seconds <= 3600 or poll_interval < 1:
            raise ValueError("Bekleme 0-3600 saniye; sorgu aralığı en az 1 saniye olmalı.")
        unique, seen = [], set()
        for target in targets:
            identity = (target["kind"], target.get("sha256") or target.get("url"))
            if identity not in seen:
                unique.append(target)
                seen.add(identity)
        tasks = []
        stop_polling = False
        for target in unique[:max_targets]:
            label = target.get("sha256") if target["kind"] == "file" else defang(target["url"])
            item = {"kind": target["kind"], "target": label}
            tasks.append(item)
            try:
                item.update(self.submit(target), status="submitted")
                digest = item.get("sha256")
                if isinstance(digest, str) and re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                    item["report_url"] = "https://hybrid-analysis.com/sample/" + digest
            except SandboxError as exc:
                item.update(status="error", error=str(exc), http_status=exc.http_status)
                if exc.retry_after is not None:
                    item["retry_after_seconds"] = exc.retry_after
                if exc.http_status in {401, 403, 429}:
                    stop_polling = True
                    break
        deadline = time.monotonic() + wait_seconds
        pending = [x for x in tasks if x["status"] == "submitted"]
        while pending and not stop_polling and time.monotonic() < deadline:
            for item in pending[:]:
                if time.monotonic() >= deadline:
                    break
                try:
                    item.update(self.report(item["job_id"]))
                    if item["status"] != "pending":
                        pending.remove(item)
                except SandboxError as exc:
                    item.update(status="error", error=str(exc), http_status=exc.http_status)
                    pending.remove(item)
                    if exc.retry_after is not None:
                        item["retry_after_seconds"] = exc.retry_after
                    if exc.http_status in {401, 403, 429}:
                        stop_polling = True
                        break
            if pending and not stop_polling:
                time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))
        for item in pending:
            item["status"] = "pending"
        skipped = len(unique) - len(tasks)
        complete = tasks and all(x["status"] == "reported" for x in tasks) and skipped == 0
        return {"provider": "hybrid_analysis",
                "status": "finished" if complete else "incomplete" if tasks else "no_targets",
                "tasks": tasks, "skipped_targets": skipped, "duplicate_targets": len(targets) - len(unique)}
