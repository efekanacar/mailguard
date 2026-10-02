"""Parse mail as data. Never open URLs, execute attachments, or render HTML."""
import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_BYTES = 25 * 1024 * 1024
MAX_TARGETS = 20
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".lnk", ".msi", ".docm", ".xlsm", ".iso"}


def defang(value):
    return value.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def domain(value):
    addresses = getaddresses([value or ""])
    return addresses[0][1].rsplit("@", 1)[-1].lower() if addresses and "@" in addresses[0][1] else ""


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.urls.extend(v for k, v in attrs if k.lower() == "href" and v)


def public_url(url):
    """Reject obvious local targets; sandbox operator must also enforce DNS/network isolation."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return False
        _ = parsed.port
        if "." not in host or host.lower().endswith((".local", ".localhost", ".internal")):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return True
    except ValueError:
        return False


def analyze(raw, trusted_authserv=()):
    if len(raw) > MAX_BYTES:
        raise ValueError("Mail en fazla 25 MiB olabilir.")
    mail = BytesParser(policy=policy.default).parsebytes(raw)
    findings = []

    def add(code, message, points):
        findings.append({"code": code, "message": message, "points": points})

    headers = {name: [str(v) for v in mail.get_all(name, [])] for name in
               ("From", "To", "Subject", "Reply-To", "Return-Path", "Date", "Message-ID", "Received", "Authentication-Results", "Received-SPF")}
    for name in ("From", "Date", "Message-ID"):
        if not headers[name]:
            add("missing_header", f"{name} başlığı eksik.", 5)
    for name in ("From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"):
        if len(mail.get_all(name, [])) > 1:
            add("duplicate_header", f"Birden çok {name} başlığı var.", 15)
    sender = domain(str(mail.get("From", "")))
    for name in ("Reply-To", "Return-Path"):
        other = domain(str(mail.get(name, "")))
        if sender and other and sender != other:
            add("domain_mismatch", f"From ve {name} alan adları farklı; meşru yönlendirmelerde de görülebilir.", 10)
    trusted = {s.lower() for s in trusted_authserv}
    auth = []
    # Use only the top Authentication-Results header: lower ones can be injected.
    values = headers["Authentication-Results"]
    if values:
        first = values[0]
        authserv = first.split(";", 1)[0].strip().split()[0] if first.split(";", 1)[0].strip() else ""
        is_trusted = authserv.lower() in trusted
        for method, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", first, re.I):
            auth.append({"method": method.lower(), "result": result.lower(), "trusted": is_trusted, "authserv_id": authserv})
            if is_trusted and result.lower() in {"fail", "softfail", "permerror"}:
                add("authentication_failure", f"Güvenilir alıcı sunucusu {method.upper()}={result} bildirmiş.", 20)
    if not auth or not any(x["trusted"] for x in auth):
        add("authentication_unknown", "SPF/DKIM/DMARC doğrulanamadı; güvenilir authserv-id ayarı veya sonuç eksik.", 0)
    received = headers["Received"]
    hops = []
    for value in received:
        try:
            date = parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
            hops.append(date.isoformat())
        except (ValueError, IndexError, TypeError, OverflowError):
            hops.append(None)
    if not received:
        add("no_received", "Received zinciri bulunamadı.", 5)
    urls, attachments, targets = set(), [], []
    for part in mail.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            # Never use the supplied filename as an on-disk path or HTTP header.
            name = filename or "attachment.bin"
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            digest = hashlib.sha256(payload).hexdigest()
            attachments.append({"name": name, "size": len(payload), "sha256": digest, "content_type": part.get_content_type()})
            targets.append({"kind": "file", "name": "sample" + (ext if re.fullmatch(r"\.[a-z0-9]{1,8}", ext) else ".bin"), "data": payload, "sha256": digest})
            if ext in RISKY_EXTENSIONS:
                add("risky_attachment", f"Çalıştırılabilir veya aktif içerikli ek: {name}", 25)
            elif ext in {".zip", ".rar", ".7z"}:
                add("archive", f"Arşiv eki mevcut: {name}; içerik yerelde açılmaz.", 5)
            continue
        if part.get_content_type() in {"text/plain", "text/html"}:
            try:
                body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                body = payload.decode("utf-8", errors="replace")
            urls.update(re.findall(r"https?://[^\s<>\"']+", body, re.I))
            if part.get_content_type() == "text/html":
                parser = Links()
                parser.feed(body)
                urls.update(parser.urls)
    url_items = []
    for url in sorted(urls):
        if not url.lower().startswith(("http://", "https://")):
            continue
        url = url.rstrip(".,);]")
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        eligible = public_url(url)
        url_items.append({"url": defang(url), "sandbox_eligible": eligible})
        if eligible:
            targets.append({"kind": "url", "url": url})
        else:
            add("blocked_url", f"Sandbox gönderimi için uygunsuz/yerel URL: {defang(url)}", 5)
        if host.startswith("xn--") or ".xn--" in host:
            add("idn", f"Punycode alan adı: {defang(host)}", 10)
        try:
            ipaddress.ip_address(host)
            add("ip_url", f"Alan adı yerine IP kullanan bağlantı: {defang(host)}", 10)
        except ValueError:
            pass
    if mail.defects:
        add("malformed_mail", "Mail biçiminde ayrıştırma kusurları var.", 5)
    score = min(100, sum(f["points"] for f in findings))
    report = {"schema_version": 1, "sha256": hashlib.sha256(raw).hexdigest(),
              "subject": str(mail.get("Subject", "")), "headers": headers, "received_dates": hops,
              "authentication": auth, "findings": findings, "urls": url_items, "attachments": attachments,
              "score": score, "verdict": "yüksek" if score >= 50 else "orta" if score >= 20 else "düşük",
              "limitations": ["Sezgisel ön inceleme puanı; düşük puan güvenli demek değildir.",
                              "SPF/DKIM/DMARC yeniden doğrulanmaz. Başlıklar yalnızca alıcı MTA sanitizasyonuna güvenilerek yorumlanır.",
                              "Received zinciri gönderici tarafından kısmen taklit edilebilir."],
              "sandbox": {"status": "not_requested", "tasks": []}}
    return report, targets
