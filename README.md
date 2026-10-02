# 🛡️ MailGuard

**Şüpheli e-postayı açmadan incele. Başlıkları analiz et, ekleri ve bağlantıları sandbox'a gönder, JSON raporunu al.**

MailGuard, `.eml` dosyaları için küçük bir Python savunma aracıdır. Yerel analiz internet bağlantısı veya üçüncü taraf Python paketi gerektirmez. Masaüstü dosya seçici ve komut satırı aynı analiz motorunu kullanır.

```text
.eml → Başlık + MIME analizi → Risk bulguları → JSON raporu
                           ↘ Cuckoo REST API → VM analizi → Sandbox raporu
```

## Neler yapar?

| Özellik | Davranış |
| --- | --- |
| Başlık analizi | From, Reply-To, Return-Path farklarını, eksik/tekrarlı başlıkları gösterir |
| SPF / DKIM / DMARC | Belirtilen güvenilir alıcı MTA'nın üstteki Authentication-Results başlığını yorumlar |
| Received zinciri | Ham başlıkları ve ayrıştırılabilen hop tarihlerini raporlar |
| Bağlantılar | Düz metin ve HTML bağlantılarını çıkarır; görüntüleme listesinde etkisizleştirir |
| Ekler | Dosya adı, MIME türü, boyut, SHA-256 ve riskli uzantıları inceler |
| Sandbox | Cuckoo 2 REST API ile ek/URL gönderir, görevleri izler, tamamlanan JSON raporunu alır |
| Risk özeti | Açıklamalı sezgisel puan: 0–19 düşük, 20–49 orta, 50–100 yüksek |

## Hızlı başlangıç

Python **3.10+** gerekir. Repoyu indirdikten sonra repo klasöründe:

```bash
python -m mailguard.cli examples/suspicious.eml --trusted-authserv mx.example.net -o reports/demo.json
```

Örnekteki tüm mail adresleri ve bağlantı sentetiktir. Gerçek mailini mail istemcisinden **orijinali indir / .eml olarak kaydet** ile dışarı aktar; dosyayı `samples/` klasörüne koy.

```bash
python -m mailguard.cli samples/supheli.eml -o reports/analiz.json
```

İstersen sanal ortama kurup `mailguard` komutunu kullanabilirsin:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
# source .venv/bin/activate
python -m pip install -e .
mailguard --gui
```

Kurulum yapmadan pencereyi açmak da mümkün:

```bash
python -m mailguard.cli --gui
```

Pencerede `.eml` seç ve **Mail seç ve analiz et** düğmesine bas. JSON raporunu kaydedebilirsin. GUI için Tkinter gerekir; Windows Python kurulumunda genellikle bulunur, Linux dağıtımlarında `python3-tk` ayrıca gerekebilir. Tkinter yoksa CLI kullanılabilir.

## Gerçek sandbox testi

MailGuard bir VM sandbox kurmaz. **Çalışan, ayrı ve izole bir Cuckoo 2 sandbox + REST API** gerekir. Sandbox yönetimi, VM imajı, analiz paketleri ve güvenli ağ politikası operatörün sorumluluğundadır. Desteklenen uç noktalar [Cuckoo'nun resmi API kaynağındaki](https://github.com/cuckoosandbox/cuckoo/blob/master/docs/book/usage/api.rst) `/tasks/create/file`, `/tasks/create/url`, `/tasks/view/{id}` ve `/tasks/report/{id}/json` uç noktalarıdır. CAPE apiv2, VirusTotal ve diğer servisler bu sürümde desteklenmez.

API token'ını komut satırına veya repoya yazma; ortam değişkeninde tut:

```powershell
$env:CUCKOO_API_TOKEN = 'KENDI_SANDBOX_TOKENIN'
python -m mailguard.cli samples/supheli.eml `
  --trusted-authserv mx.sirketin.example `
  --sandbox-url https://sandbox.sirketin.example `
  --submit --wait 120 -o reports/analiz.json
```

```bash
export CUCKOO_API_TOKEN='KENDI_SANDBOX_TOKENIN'
python -m mailguard.cli samples/supheli.eml --sandbox-url https://sandbox.sirketin.example --submit -o reports/analiz.json
```

Yerel API için `http://127.0.0.1:8090` kullanılabilir. Uzak sunucularda HTTPS zorunludur; TLS doğrulaması kapatılmaz. API yönlendirmeleri takip edilmez. `--submit` verilerin seçtiğin sunucuya aktarılmasına izin verir. GUI'de ayrıca sandbox kutusunu işaretlemek ve gönderimi onaylamak gerekir.

Her mailde en fazla **20 hedef** gönderilir; kalanların sayısı raporda bulunur. İstek başına 15 saniye ağ zaman aşımı vardır. `--wait` gönderim aşamasından **sonraki** rapor bekleme süresidir; toplam çalışma süresi gönderimler ve ağ istekleri nedeniyle daha uzun olabilir. `--wait 0` yalnızca gönderim yapar. Gönderilen ama bitmeyen görevler `pending`, başarısız istekler `error` olarak kalır; temiz sonucu üretilmez. Rapor alınmayan görevleri task ID ile sandbox panelinde incele.

## Güven ve gizlilik sınırları

- Bu araç phishing tespiti için ön inceleme yapar. Düşük puan, SPF pass veya sandbox'ta bulgu olmaması mailin güvenli olduğunu kanıtlamaz. Statik risk puanı ve dinamik sandbox raporu ayrı alanlardır; sandbox sonucu otomatik olarak güvenli/güvensiz kararına çevrilmez.
- SPF/DKIM/DMARC yerelde kriptografik/DNS doğrulamasıyla yeniden hesaplanmaz. `--trusted-authserv` yalnızca kendi alıcı mail sunucunun authserv-id değeri olmalı. Alıcı MTA sahte Authentication-Results başlıklarını temizlemiyorsa gönderici aynı değeri taklit edebilir. Alt Authentication-Results başlıkları değerlendirmeye alınmaz.
- Header/body içeriği veri olarak ele alınır. HTML işlenerek ekrana render edilmez; bağlantılar açılmaz ve ekler yerel diske çıkarılmaz veya çalıştırılmaz. Arşivler açılmaz; URL yönlendirmeleri ve marka benzerliği analizi yapılmaz.
- Özel/yerel IP'ler, localhost ve bazı yerel alan adları URL gönderiminden çıkarılır. Bu kontrol DNS çözmez ve DNS rebinding'i önlemez; sandbox ağında özel ağ erişimini ayrıca engelle.
- Mail sınırı **25 MiB**. Dosyadan alınan ek adları disk yolu olarak kullanılmaz. Orijinal mailin bütünü sandbox'a gönderilmez; çıkarılan ekler ve uygun URL'ler gönderilir. Bunlar da özel veri veya erişim token'ları içerebilir.
- Tam JSON raporu başlıkları, mail adreslerini ve sandbox'ın döndürdüğü hassas bilgileri içerebilir. Mail ve raporları GitHub'a yükleme. `.gitignore`, `samples/`, `reports/`, `.env` ve gerçek `.eml` dosyalarını dışarıda tutar.
- Defang yalnızca çıkarılan URL listesine ve sandbox hedef etiketlerine uygulanır; ham mail başlıkları ve sandbox raporları özgün veri içerir.

## Rapor ve çıkış kodları

```json
{
  "score": 60,
  "verdict": "yüksek",
  "findings": [{"code": "authentication_failure", "message": "...", "points": 20}],
  "sandbox": {"status": "not_requested", "tasks": []}
}
```

Örnek sadeleştirilmiştir. Tam raporda SHA-256, başlıklar, auth sonuçları, ekler, URL'ler, sınırlamalar ve sandbox görevleri bulunur. `finished`, tüm gönderilen görevlerin raporlandığı anlamına gelir; güvenli oldukları anlamına gelmez. `no_targets`, sandbox'a gönderilecek hedef olmadığını belirtir.

| Kod | Anlam |
| --- | --- |
| 0 | Analiz tamamlandı; phishing verdictinden bağımsız |
| 1 | Dosya/ayar hatası |
| 2 | Eksik sandbox sonucu veya CLI kullanım hatası |

## Geliştirme ve test

```bash
python -m unittest discover -s tests -v
```

Testler sahte HTTP sandbox üzerinden multipart gönderim, token kullanımı, durum sorgusu, rapor alma ve redirect engellemesini; ayrıca sahte auth başlıklarını, dosya boyutu sınırını ve yerel URL engellemeyi kontrol eder. GitHub Actions farklı Python sürümlerinde testleri çalıştırır. **Gerçek VM detonasyonu test paketinin parçası değildir.**

## Lisans

MIT. Yetkili güvenlik incelemeleri için hazırlanmıştır.
