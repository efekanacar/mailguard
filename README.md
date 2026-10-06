# 🛡️ MailGuard 0.2

**Şüpheli .eml dosyasının başlıklarını yerelde incele; eklerini ve bağlantılarını API anahtarınla Hybrid Analysis sandbox'ında test et.**

Python 3.10+ gerekir. Yerel analiz internet veya üçüncü taraf Python paketi gerektirmez. Grafik arayüz ve CLI aynı analiz motorunu kullanır. Sandbox hizmetini [Hybrid Analysis API v2](https://hybrid-analysis.com/docs/api/v2) sağlar.

## Ubuntu'da başlat

Yeni kurulum:

```bash
sudo apt update
sudo apt install python3 python3-tk git
git clone https://github.com/efekanacar/mailguard.git mailguard-ha
cd mailguard-ha
python3 -m mailguard.cli --gui
```

ZIP indirdiysen çıkartıp **README.md ve pyproject.toml bulunan ana klasörde** terminal aç. mailguard/ alt klasörüne girme. mailguard.cli, mailguard/cli.py Python modülünün adıdır; noktalı isimle ayrı dosya arama.

```bash
cd ~/Downloads/mailguard-main
python3 -m mailguard.cli --gui
```

Önceki sürümü ZIP olarak indirdiysen güncel ZIP'i ayrı klasöre çıkart. Git ile klonladıysan repo kökünde `git pull --ff-only` kullanabilirsin. Pencere başlığında **MailGuard 0.2 | Hybrid Analysis** görünmeli.

## Arayüzle .eml ve sandbox kullanımı

1. Mail istemcisinde mesajı **orijinali indir / .eml olarak kaydet** ile dışarı aktar. Ekleri açma.
2. **Güvenilir authserv-id** alanını bilmiyorsan boş bırak. Bu alan mail adresin veya API anahtarın değildir; kendi alıcı mail sunucunun Authentication-Results kimliğidir.
3. **Hybrid Analysis API anahtarı** alanına kendi anahtarını yapıştır. Alan maskelidir; program anahtarı dosyaya veya JSON raporuna kaydetmez. Anahtarında dosya/URL gönderme yetkisi olmalı; yalnızca arama yetkisi yeterli değildir.
4. **Analiz ortamı ID** başlangıçta 160 olur: uzak sandbox'ın Windows 10 ortamıdır. MailGuard'ı Ubuntu'da çalıştırman uzak ortam seçimini değiştirmez. Başka ortam için aşağıdaki listeleme komutunu kullan.
5. **Ekleri ve URL'leri Hybrid Analysis'e gönder** kutusunu işaretle.
6. **Mail seç ve analiz et** düğmesine bas; .eml dosyasını seç ve gönderim onayını kabul et. Ekler ve uygun HTTP/HTTPS bağlantıları gönderilir; bütün .eml gönderilmez.
7. Sonuçları incele; **JSON raporunu kaydet** ile kaydet. Sandbox görevlerinde job_id, varsa report_url, verdict ve threat_score bulunur.

Yerel başlık analizi için kutuyu kapalı bırak; anahtar gerekmez. **not_requested**, sandbox testi istenmedi demektir.

Hybrid Analysis'e gönderilen içerik ve raporlar topluluk veya ortaklarla paylaşılabilir; bu araç özel analiz garantisi vermez. Gizli ekleri, özel URL'leri ve erişim token'larını göndermeyin. API anahtarını GitHub'a veya sohbete yazmanız gerekmez.

## Komut satırı: python3

Yerel örnek analiz; dışarı gönderim yok:

```bash
python3 -m mailguard.cli examples/suspicious.eml -o reports/demo.json
```

Örnek mail sentetiktir. Gerçek mailini yerel samples/ klasörüne koyabilirsin:

```bash
mkdir -p samples
python3 -m mailguard.cli samples/supheli.eml -o reports/analiz.json
```

CLI sandbox için anahtarı Bash'te gizli girişle oku; anahtar komut geçmişine veya süreç argümanlarına girmez:

```bash
read -rsp 'Hybrid Analysis API KEY: ' HYBRID_ANALYSIS_API_KEY
echo
export HYBRID_ANALYSIS_API_KEY
python3 -m mailguard.cli samples/supheli.eml \
  --submit --accept-upload --environment-id 160 \
  --max-targets 5 --wait 300 -o reports/analiz.json
```

--submit gönderimi açar; --accept-upload üçüncü tarafa veri aktarımını kabul eder. İkisi de gereklidir. Anahtarı CLI argümanı olarak alan seçenek yoktur. Ortam değişkeni GUI alanını da doldurur. İşin bitince `unset HYBRID_ANALYSIS_API_KEY` ile mevcut kabuktan kaldırabilirsin.

Güncel analiz ortamlarını listele; mail gönderilmez:

```bash
python3 -m mailguard.cli --list-environments
```

Kuyrukta kalan analiz için rapordaki gerçek job_id değerini kullanarak **yeniden yüklemeden** sonra sorgula. GERCEK_JOB_ID bir yer tutucudur:

```bash
python3 -m mailguard.cli --job-id GERCEK_JOB_ID -o reports/sandbox-sonuc.json
```

Bu komut tek durum kontrolü yapar; tamamlandıysa analiz özetini alır. Bekliyorsa sonra tekrar çalıştır. İlk mail raporunu değiştirmez; ayrı sandbox sonucu kaydeder.

Kendi alıcı MTA kimliğini biliyorsan analiz komutuna `--trusted-authserv mx.sirketin.example` ekleyebilirsin. Birden fazla değer için seçeneği tekrarla.

## Neler analiz edilir?

| Özellik | Davranış |
| --- | --- |
| Başlıklar | From, Reply-To, Return-Path farkları; eksik/tekrarlı alanlar |
| SPF / DKIM / DMARC | Güvenilir alıcı MTA'nın üstteki Authentication-Results başlığını yorumlar |
| Received zinciri | Ham başlıkları ve ayrıştırılabilen hop tarihlerini raporlar |
| URL'ler | Düz metin ve HTML bağlantılarını çıkarır; görüntüleme listesinde etkisizleştirir |
| Ekler | Dosya adı, MIME türü, boyut, SHA-256 ve riskli uzantıları inceler |
| Sandbox | Hybrid Analysis dosya/URL gönderimi, durum sorgusu ve JSON analiz özeti |
| Yerel risk | Açıklamalı sezgisel puan: 0–19 düşük, 20–49 orta, 50–100 yüksek |

Sabit resmi HTTPS adresi https://hybrid-analysis.com/api/v2 kullanılır. Uç noktalar /submit/file, /submit/url, /report/{job_id}/state, /report/{job_id}/summary ve /system/environments olur. TLS doğrulaması açıktır; yönlendirmeler takip edilmez. Cuckoo kurman veya yerel sandbox VM çalıştırman gerekmez.

## Durumlar ve sorun giderme

| Durum | Anlamı / yapılacak işlem |
| --- | --- |
| sandbox.status: not_requested | Gönderim kapalı; GUI kutusunu aç veya CLI'de iki gönderim seçeneğini kullan |
| no_targets | Mailde gönderilebilecek ek veya uygun genel URL yok |
| incomplete | Bekleyen/başarısız görev veya gönderilmeyen hedef var; tasks ve skipped_targets alanlarını incele |
| finished | Tüm farklı hedeflerin raporları alındı; mailin güvenli olduğu anlamına gelmez |
| Görev pending | Kuyrukta veya işlemde; aynı job_id ile sonra sorgula |
| Görev reported | Özet alındı; verdict, threat_score ve result alanlarını incele |
| Görev failed / error | Analiz/API isteği başarısız; temiz sonucu üretilmez |
| HTTP 401 | API anahtarı kabul edilmedi |
| HTTP 403 | Anahtarın işleme yetkisi yok; hesap/API izinlerini kontrol et |
| HTTP 429 | Kota/hız sınırı; sonra sorgula, aynı maili tekrar yükleme |
| HTTP 410 | İlgili alt raporları Hybrid Analysis panelinde incele |
| No module named tkinter | sudo apt install python3-tk |
| No module named mailguard | README.md bulunan ana klasöre dön |

Varsayılan en fazla **5 farklı hedef**, seçenekle en fazla **20** hedef gönderilir. Aynı SHA-256 ekler ve aynı URL'ler tek kez gönderilir. Hedef sınırı/API hatasıyla gönderilmeyenler skipped_targets, tekrarlar duplicate_targets alanında sayılır. 401/403/429 sonrasında yeni gönderim ve sorgular durdurulur.

Varsayılan bekleme **120 saniye**, en çok 3600 saniyedir. --wait 0 yalnızca gönderim yapar. Bekleme gönderimden sonra başlar; ağ istekleri nedeniyle toplam süre daha uzun olabilir. İstek zaman aşımı 15 saniye; durum sorgu döngüleri arası 15 saniyedir. Kuyruk ve hesap kotası sonucu etkiler. Aynı maili tekrar çalıştırmak yeni gönderimler yapabilir; bekleyen iş için --job-id kullan.

Çıkış kodları: **0** yerel analiz veya tamamlanmış sonuç; **1** dosya/ayar/API hatası; **2** eksik sandbox sonucu veya CLI kullanım hatası. Yerel risk seviyesi çıkış koduna çevrilmez.

## Güven sınırları

- Düşük puan, SPF pass veya sandbox'ta bulgu olmaması güvenli mail kanıtı değildir. Yerel risk puanı ve uzak sandbox verdict'i ayrı alanlardır.
- SPF/DKIM/DMARC kriptografik/DNS doğrulamasıyla yeniden hesaplanmaz. Authserv-id kendi alıcı sunucuna ait olmalı. MTA sahte Authentication-Results başlıklarını temizlemiyorsa kimlik taklit edilebilir; alttaki başlıklar değerlendirilmez.
- HTML render edilmez; bağlantılar açılmaz, ekler yerelde çalıştırılmaz veya diske çıkarılmaz. Arşivler açılmaz; URL yönlendirme/marka benzerliği analizi yapılmaz.
- Yerel/özel IP'ler, localhost ve bazı yerel alan adları URL gönderiminden çıkarılır. Kontrol DNS çözmez ve DNS rebinding'i önlemez.
- Mail sınırı **25 MiB**; API yanıt sınırı 10 MiB. Eklerin özgün adları disk yolu veya HTTP başlığı olarak kullanılmaz.
- JSON raporları mail başlıklarını, adresleri ve uzak analiz ayrıntılarını içerir. Gerçek maili, raporları ve anahtarı repoya yükleme. .gitignore yerel samples/, reports/, .env ve gerçek .eml dosyalarını dışarıda tutar.
- URL etkisizleştirme çıkarılan listeye ve hedef etiketlerine uygulanır; ham başlıklar ve uzak raporlar özgün veriyi içerebilir.

## Geliştirme ve sürüm geçişi

```bash
python3 -m unittest discover -s tests -v
```

Testler sahte API ile dosya/URL gönderimi, anahtar başlığı, rapor alma, kota/yetki hataları, yönlendirme engelleme ve CLI onayını kontrol eder. Başlık güveni, dosya boyutu ve yerel URL engelleme de test edilir. Gerçek API anahtarıyla sandbox çalıştırma test paketinin parçası değildir. GitHub Actions Python 3.10, 3.12 ve 3.13 kullanır.

0.2'de --sandbox-url ve CUCKOO_API_TOKEN kaldırıldı. Yerine HYBRID_ANALYSIS_API_KEY, --environment-id ve açık gönderim kabulü kullanılır. Eski Cuckoo PDF kitapçığı bu sürümün sandbox ayarlarını anlatmaz; güncel kullanım bu README'dedir.

## Lisans

MIT. Yetkili güvenlik incelemeleri için hazırlanmıştır.
