"""Optional local file picker. Suspicious HTML is never displayed."""
import json
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from .cli import inspect_file


def launch(trusted=(), default_sandbox=None):
    root = tk.Tk()
    root.title("MailGuard | Şüpheli mail analizi")
    root.geometry("900x650")
    panel = ttk.Frame(root, padding=18)
    panel.pack(fill="both", expand=True)
    ttk.Label(panel, text="MailGuard", font=("Segoe UI", 23, "bold")).pack(anchor="w")
    ttk.Label(panel, text=".eml seç → başlıkları incele → isteğe bağlı sandbox testi").pack(anchor="w", pady=(0, 14))
    ttk.Label(panel, text="Güvenilir authserv-id (virgülle ayır):").pack(anchor="w")
    auth = tk.StringVar(value=",".join(trusted))
    ttk.Entry(panel, textvariable=auth).pack(fill="x")
    ttk.Label(panel, text="Cuckoo REST API adresi:").pack(anchor="w", pady=(10, 0))
    url = tk.StringVar(value=default_sandbox or "http://127.0.0.1:8090")
    ttk.Entry(panel, textvariable=url).pack(fill="x")
    submit = tk.BooleanVar(value=False)
    ttk.Checkbutton(panel, text="Ekleri ve bağlantıları bu sandbox'a gönder (mail verisi paylaşılır)", variable=submit).pack(anchor="w", pady=10)
    status = tk.StringVar(value="Bir .eml dosyası seçin. Ekler yerelde çalıştırılmaz.")
    ttk.Label(panel, textvariable=status).pack(anchor="w")
    text = scrolledtext.ScrolledText(panel, wrap="word", font=("Consolas", 10))
    text.pack(fill="both", expand=True, pady=10)
    events = queue.Queue()
    current = [None]

    def choose():
        path = filedialog.askopenfilename(filetypes=[("Email", "*.eml"), ("All files", "*")])
        if not path:
            return
        if submit.get() and not messagebox.askyesno("Sandbox gönderimi", "Maildeki ekler ve URL'ler belirtilen sandbox'a gönderilecek. Devam edilsin mi?"):
            return
        selected_auth = [s.strip() for s in auth.get().split(",") if s.strip()]
        selected_url = url.get() if submit.get() else None
        button.config(state="disabled")
        status.set("Analiz sürüyor… Sandbox raporları için en fazla 120 saniye beklenir.")

        def worker():
            try:
                events.put((inspect_file(path, selected_auth, selected_url), None))
            except Exception as exc:
                events.put((None, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            report, error = events.get_nowait()
            button.config(state="normal")
            if error:
                status.set("Analiz başarısız.")
                messagebox.showerror("Hata", error)
            else:
                current[0] = report
                text.delete("1.0", "end")
                text.insert("end", json.dumps(report, ensure_ascii=False, indent=2))
                status.set(f'Risk: {report["verdict"]} ({report["score"]}/100) | Sandbox: {report["sandbox"]["status"]}')
        except queue.Empty:
            pass
        root.after(100, poll)

    def save():
        if current[0] is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            try:
                Path(path).write_text(json.dumps(current[0], ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Kaydetme hatası", str(exc))

    actions = ttk.Frame(panel)
    actions.pack(fill="x")
    button = ttk.Button(actions, text="Mail seç ve analiz et", command=choose)
    button.pack(side="left")
    ttk.Button(actions, text="JSON raporunu kaydet", command=save).pack(side="right")
    poll()
    root.mainloop()
