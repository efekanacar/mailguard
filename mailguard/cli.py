import argparse
import json
import os
from pathlib import Path
import sys
from .analyzer import MAX_BYTES, analyze, defang
from .sandbox import Cuckoo


def inspect_file(path, trusted=(), sandbox_url=None, wait=120):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    report, targets = analyze(raw, trusted)
    if sandbox_url:
        client = Cuckoo(sandbox_url, os.environ.get("CUCKOO_API_TOKEN", ""))
        report["sandbox"] = client.run(targets, wait)
        for task in report["sandbox"]["tasks"]:
            if task["kind"] == "url":
                task["target"] = defang(task["target"])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="MailGuard — şüpheli .eml başlık analizi ve sandbox")
    parser.add_argument("mail", nargs="?", help="İncelenecek .eml dosyası")
    parser.add_argument("--output", "-o", type=Path, help="JSON raporu yolu")
    parser.add_argument("--trusted-authserv", action="append", default=[], help="Alıcı MTA authserv-id; tekrar edilebilir")
    parser.add_argument("--sandbox-url", help="Cuckoo 2 REST API adresi")
    parser.add_argument("--submit", action="store_true", help="Bağlantı ve ekleri yapılandırılmış sandbox'a gönder")
    parser.add_argument("--wait", type=int, default=120, help="Gönderimden sonra raporlar için bekleme süresi, saniye (0: sadece gönder)")
    parser.add_argument("--gui", action="store_true", help="Dosya seçme penceresini aç (Tkinter gerekir)")
    args = parser.parse_args(argv)
    if args.gui:
        from .gui import launch
        launch(args.trusted_authserv, args.sandbox_url)
        return 0
    if not args.mail:
        parser.error("Bir .eml dosyası veya --gui belirtin.")
    if args.wait < 0 or args.wait > 3600:
        parser.error("--wait 0 ile 3600 arasında olmalı.")
    if args.submit and not args.sandbox_url:
        parser.error("--submit için --sandbox-url gerekir.")
    try:
        report = inspect_file(args.mail, args.trusted_authserv, args.sandbox_url if args.submit else None, args.wait)
        rendered = json.dumps(report, ensure_ascii=True, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        print(f'Risk: {report["verdict"]} ({report["score"]}/100) | Sandbox: {report["sandbox"]["status"]}', file=sys.stderr)
        return 2 if report["sandbox"]["status"] == "incomplete" else 0
    except (OSError, ValueError) as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
