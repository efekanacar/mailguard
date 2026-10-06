# Değişiklikler

## 0.2.0

- Cuckoo yerine Hybrid Analysis API v2 ile dosya/URL sandbox gönderimi ve analiz özeti.
- Maskeli GUI API anahtarı alanı ve CLI için HYBRID_ANALYSIS_API_KEY desteği.
- CLI'de --accept-upload; GUI'de gönderim onayı ve paylaşım açıklaması.
- Analiz ortamı seçimi, ortam listeleme ve mevcut job_id ile yeniden yüklemeden sorgulama.
- Kota/yetki hatalarında durma; bekleyen veya hatalı işlere temiz sonucu vermeme.
- SHA-256/URL tekrarlarını ayıklama ve varsayılan 5 hedef sınırı.
- Dosya seçme/kaydetme düğmelerini genişleyen rapor alanının üstüne taşıma.
- Ubuntu python3 yönergeleri ve sahte API ile entegrasyon testleri.

Geçiş: --sandbox-url ve CUCKOO_API_TOKEN artık kullanılmaz. README'deki Hybrid Analysis ayarlarını kullanın.
