import argparse
import json
import os
from pathlib import Path
import sys
from .analyzer import MAX_BYTES, analyze
from .sandbox import DEFAULT_ENVIRONMENT, DEFAULT_MAX_TARGETS, HybridAnalysis, SandboxError


def inspect_file(path, trusted=(), submit=False, wait=120, environment_id=DEFAULT_ENVIRONMENT,
                 api_key=None, max_targets=DEFAULT_MAX_TARGETS):
    # Validate credentials before external submissions.
    client = HybridAnalysis(api_key if api_key is not None else os.environ.get("HYBRID_ANALYSIS_API_KEY", ""), environment_id) if submit else None
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    report, targets = analyze(raw, trusted)
    report["sandbox"]["provider"] = "hybrid_analysis"
    if client:
        report["sandbox"] = client.run(targets, wait, max_targets)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="MailGuard — .eml başlık analizi ve Hybrid Analysis sandbox")
    parser.add_argument("mail", nargs="?", help="İncelenecek .eml dosyası")
    parser.add_argument("--output", "-o", type=Path, help="JSON raporu yolu")
    parser.add_argument("--trusted-authserv", action="append", default=[], help="Alıcı MTA authserv-id; tekrar edilebilir")
    parser.add_argument("--submit", action="store_true", help="Ek/URL'leri Hybrid Analysis'e gönder")
    parser.add_argument("--accept-upload", action="store_true", help="Üçüncü taraf gönderimini ve örnek/raporların paylaşılabileceğini kabul et")
    parser.add_argument("--environment-id", type=int, default=DEFAULT_ENVIRONMENT, help="Hybrid Analysis analiz ortamı ID (varsayılan: 160)")
    parser.add_argument("--max-targets", type=int, default=DEFAULT_MAX_TARGETS, help="Mail başına hedef sınırı: 1-20 (varsayılan: 5)")
    parser.add_argument("--wait", type=int, default=120, help="Gönderim sonrası bekleme, saniye: 0-3600 (varsayılan: 120)")
    parser.add_argument("--list-environments", action="store_true", help="API'deki güncel analiz ortamlarını listele; mail göndermez")
    parser.add_argument("--job-id", help="Yeni gönderim yapmadan mevcut Hybrid Analysis görevini sorgula")
    parser.add_argument("--gui", action="store_true", help="Dosya seçme penceresi (Tkinter gerekir)")
    args = parser.parse_args(argv)
    if not 0 <= args.wait <= 3600:
        parser.error("--wait 0 ile 3600 arasında olmalı.")
    if not 1 <= args.max_targets <= 20 or args.environment_id <= 0:
        parser.error("--max-targets 1-20; --environment-id pozitif olmalı.")
    if sum([bool(args.gui), bool(args.list_environments), bool(args.job_id)]) > 1:
        parser.error("--gui, --list-environments ve --job-id birlikte kullanılamaz.")
    if (args.list_environments or args.job_id or args.gui) and (args.mail or args.submit or args.accept_upload):
        parser.error("Bu modda mail/--submit/--accept-upload kullanmayın; GUI'de gönderimi kutudan seçin.")
    if args.submit and not args.accept_upload:
        parser.error("Hybrid Analysis'e ek/URL aktarımı için --accept-upload gerekir. Özel verileri göndermeyin.")
    try:
        if args.gui:
            try:
                from .gui import launch
            except ImportError:
                print("Tkinter eksik. Ubuntu: sudo apt install python3-tk", file=sys.stderr)
                return 1
            launch(args.trusted_authserv, args.environment_id, args.wait, args.max_targets)
            return 0
        if args.list_environments or args.job_id:
            client = HybridAnalysis(os.environ.get("HYBRID_ANALYSIS_API_KEY", ""), args.environment_id)
            result = client.environments() if args.list_environments else client.report(args.job_id)
            exit_code = 2 if isinstance(result, dict) and result.get("status") != "reported" else 0
        else:
            if not args.mail:
                parser.error("Bir .eml dosyası veya --gui belirtin.")
            result = inspect_file(args.mail, args.trusted_authserv, args.submit, args.wait,
                                  args.environment_id, max_targets=args.max_targets)
            print(f'Risk: {result["verdict"]} ({result["score"]}/100) | Sandbox: {result["sandbox"]["status"]}', file=sys.stderr)
            exit_code = 2 if result["sandbox"]["status"] == "incomplete" else 0
        rendered = json.dumps(result, ensure_ascii=True, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        return exit_code
    except (OSError, ValueError, SandboxError) as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
