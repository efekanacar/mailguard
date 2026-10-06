"""Local file picker for offline triage and optional Hybrid Analysis submission."""
import json
import os
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from .cli import inspect_file
from .sandbox import HybridAnalysis


def launch(trusted=(), environment_id=160, wait=120, max_targets=5):
    root = tk.Tk()
    root.title("MailGuard 0.2 | Hybrid Analysis")
    root.geometry("920x740")
    root.minsize(620, 580)
    panel = ttk.Frame(root, padding=16)
    panel.pack(fill="both", expand=True)
    panel.columnconfigure(0, weight=1)
    panel.rowconfigure(12, weight=1)

    ttk.Label(panel, text="MailGuard", font=("Sans", 23, "bold")).grid(row=0, column=0, sticky="w")
    ttk.Label(panel, text=".eml seç → başlıkları incele → Hybrid Analysis sandbox").grid(row=1, column=0, sticky="w", pady=(0, 12))
    ttk.Label(panel, text="Güvenilir authserv-id (bilmiyorsan boş bırak):").grid(row=2, column=0, sticky="w")
    auth = tk.StringVar(value=",".join(trusted))
    ttk.Entry(panel, textvariable=auth).grid(row=3, column=0, sticky="ew")
    ttk.Label(panel, text="Hybrid Analysis API anahtarı (yalnızca bu oturumda tutulur):").grid(row=4, column=0, sticky="w", pady=(10, 0))
    key = tk.StringVar(value=os.environ.get("HYBRID_ANALYSIS_API_KEY", ""))
    ttk.Entry(panel, textvariable=key, show="*").grid(row=5, column=0, sticky="ew")
    options = ttk.Frame(panel)
    options.grid(row=6, column=0, sticky="ew", pady=10)
    ttk.Label(options, text="Analiz ortamı ID:").pack(side="left")
    environment = tk.StringVar(value=str(environment_id))
    ttk.Entry(options, textvariable=environment, width=8).pack(side="left", padx=8)
    ttk.Label(options, text="160: Windows 10 | Ubuntu'da çalışman bu seçimi değiştirmez.").pack(side="left")
    submit = tk.BooleanVar(value=False)
    ttk.Checkbutton(panel, text="Ekleri ve URL'leri Hybrid Analysis'e gönder", variable=submit).grid(row=7, column=0, sticky="w")
    ttk.Label(panel, text="Gönderilen içerik/raporlar paylaşılabilir. Gizli mail eklerini veya özel URL'leri göndermeyin.",
              wraplength=850).grid(row=8, column=0, sticky="w", pady=(4, 10))
    status = tk.StringVar(value="Yerel analiz için sandbox kutusunu kapalı bırakıp mail seçin.")
    ttk.Label(panel, textvariable=status, wraplength=850).grid(row=9, column=0, sticky="w")
    # Reserve action space before allocating the expandable report area.
    actions = ttk.Frame(panel)
    actions.grid(row=10, column=0, sticky="ew", pady=10)
    ttk.Label(panel, text="Analiz raporu:").grid(row=11, column=0, sticky="w")
    text = scrolledtext.ScrolledText(panel, wrap="word", font=("Monospace", 10), height=6)
    text.grid(row=12, column=0, sticky="nsew")
    events = queue.Queue()
    current = [None]

    def choose():
        should_submit = submit.get()
        try:
            selected_environment = int(environment.get())
            if selected_environment <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Ayar hatası", "Analiz ortamı ID pozitif bir sayı olmalı.")
            return
        selected_key = key.get().strip()
        if should_submit:
            try:
                HybridAnalysis(selected_key, selected_environment)
            except ValueError as exc:
                messagebox.showerror("API anahtarı", str(exc))
                return
        path = filedialog.askopenfilename(filetypes=[("Email", "*.eml"), ("All files", "*")])
        if not path:
            return
        if should_submit and not messagebox.askyesno(
                "Hybrid Analysis gönderimi",
                "Bu mailin ekleri ve uygun URL'leri hybrid-analysis.com'a gönderilecek.\n"
                "Gönderilen içerik ve raporlar topluluk/ortaklarla paylaşılabilir; gizlilik garantisi verilmez.\n"
                f"En fazla {max_targets} farklı hedef gönderilir. Devam edilsin mi?"):
            return
        selected_auth = [s.strip() for s in auth.get().split(",") if s.strip()]
        current[0] = None
        text.delete("1.0", "end")
        button.config(state="disabled")
        save_button.config(state="disabled")
        status.set("Analiz sürüyor… Hybrid Analysis kuyruğu ve kota sınırı nedeniyle bekleyebilir.")

        def worker():
            try:
                report = inspect_file(path, selected_auth, should_submit, wait,
                                      selected_environment, selected_key, max_targets)
                events.put((report, None))
            except Exception as exc:
                events.put((None, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            report, error = events.get_nowait()
            button.config(state="normal")
            if error:
                status.set("Analiz başarısız. Önceki rapor temizlendi.")
                messagebox.showerror("Hata", error)
            else:
                current[0] = report
                save_button.config(state="normal")
                text.insert("end", json.dumps(report, ensure_ascii=False, indent=2))
                sandbox_status = report["sandbox"]["status"]
                labels = {"not_requested": "istenmedi (kutu kapalı)", "no_targets": "gönderilecek hedef yok",
                          "finished": "raporlar alındı", "incomplete": "eksik/hatalı; görevleri incele"}
                status.set(f'Risk: {report["verdict"]} ({report["score"]}/100) | Hybrid Analysis: {labels.get(sandbox_status, sandbox_status)}')
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

    button = ttk.Button(actions, text="Mail seç ve analiz et", command=choose)
    button.pack(side="left")
    save_button = ttk.Button(actions, text="JSON raporunu kaydet", command=save, state="disabled")
    save_button.pack(side="right")
    poll()
    root.mainloop()
