# Hafta 05 — Gün 029: Değerlendirme ve Sonuç Raporu

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu rapor eğitim ve değerlendirme amaçlı hazırlanmıştır. İzinsiz kopyalanamaz veya dağıtılamaz.*

---

## 1. Genel Bilgiler
- **Eğitim Programı:** Siber Güvenlik 365 Gün Standart ve Müfredat Paketi
- **Aşama:** Aşama 02 — Sistem ve Ağ Güvenliği Temelleri
- **Hafta:** Hafta 05 — Olay Günlükleri, Kayıt Defteri ve Temel Ağ Analizi
- **Gün:** Gün 029 — Windows Event Viewer'a Giriş
- **Değerlendirme Tarihi:** 2026-10-27
- **Sonuç:** **YETERLİ / PASS (100 / 100)**

---

## 2. Puanlama Tablosu

| Kriter | Açıklama | Taban Puan | Alınan Puan | Durum |
| :--- | :--- | :---: | :---: | :---: |
| **Kriter 1: Teorik Altyapı ve Kavramsal Yetkinlik** | Windows olay günlüğü mimarisi (EVTX, ETW, Security/System kanalları), olay anatomisi ve G029-SC1'in 'Tek bir olay kimliği bağlam olmadan saldırı kanıtı değildir' kuralı adli derinlikte incelenmiştir. | 20 | **20** | Mükemmel |
| **Kriter 2: Pratik Uygulama ve Kod Kalitesi** | `windows_event_viewer_analyzer.py` aracı bağımsız, standart kütüphane odaklı, biçimsel alan doğrulayıcı, bağlamsal korelasyon motoru ve SHA-256 mühürleme ile yazılmış; tüm satırları didaktik açıklamalarla zenginleştirilmiştir. | 40 | **40** | Mükemmel |
| **Kriter 3: Güvenlik Senaryoları ve Doğrulama** | G029-SC1, G029-SC2 (gizli veri içermeyen 3 sistem olayının analizi ve 4 bozuk girdinin negatif kontrolde reddedilmesi) ve G029-SC3 (risk analizi, iz silme tespiti ve merkezi SIEM savunması) 14 birim test ile %100 doğrulanmıştır. | 25 | **25** | Mükemmel |
| **Kriter 4: Dokümantasyon, Raporlama ve Standart Uyumu** | Usta-çırak üslubu, 4 başlıklı senaryo formatı, özel lisans damgası, temsilî kanıt banner'ı, UTF-8 kodlama ve JSON veri bütünlüğü kurumsal standartta tamamlanmıştır. | 15 | **15** | Mükemmel |
| **TOPLAM** | **Genel Değerlendirme ve Başarı Skoru** | **100** | **100** | **YETERLİ (PASS)** |

---

## 3. Laboratuvar ve Test İstatistiği
- **Toplam Birim Test:** 14
- **Başarılı Test (PASS):** 14 (%100.0)
- **Başarısız / Hatalı Test:** 0 (%0.0)
- **Çalışma Süresi:** 0.170 saniye
- **İncelenen Sistem Olayları:** 3 adet (Event 6005: EventLog Başlatıldı, Event 7045: Servis Kurulumu, Event 1074: Kapatma/Yeniden Başlatma).
- **Negatif Kontrol Kapsamı:** 4 adet bozuk olay kaydı (eksik sağlayıcı, geçersiz ID, bozuk tarih, eksik üstveri) %100 başarıyla reddedilmiştir.
- **Kriptografik Bütünlük:** Her bir olay kaydının adli bütünlüğü için 64 karakterlik SHA-256 özeti hesaplanmıştır.

---

## 4. Çıkarılan Temel Sonuçlar ve Mühendislik Kazanımları
1. **Bağlamsal Analizin Önemi:** Bir olay günlüğü tek başına yargı üretmek için yetersizdir. Olayı başlatan kullanıcı, çalışan dosya yolu, zaman penceresi ve sıklık (frekans) bir arada değerlendirilmelidir.
2. **Kritik Sistem Olayları:** Sistem kanalı (System.evtx) üzerindeki Event 7045 (Servis Kurulumu) ve Event 1074 (Kapatma), saldırganların kalıcılık (persistence) sağlama veya iz silme teşebbüslerini yakalamada birincil öneme sahiptir.
3. **Merkezi Log Koruma:** Yerel günlükler saldırgan tarafından silinebilir (`Event 1102`). Bu sebeple loglar anlık olarak merkezi bir SIEM sistemine yönlendirilmelidir.
