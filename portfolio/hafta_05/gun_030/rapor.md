# Hafta 05 — Gün 030: Değerlendirme ve Sonuç Raporu

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu rapor eğitim ve değerlendirme amaçlı hazırlanmıştır. İzinsiz kopyalanamaz veya dağıtılamaz.*

---

## 1. Genel Bilgiler
- **Eğitim Programı:** Siber Güvenlik 365 Gün Standart ve Müfredat Paketi
- **Aşama:** Aşama 02 — Sistem ve Ağ Güvenliği Temelleri
- **Hafta:** Hafta 05 — Olay Günlükleri, Kayıt Defteri ve Temel Ağ Analizi
- **Gün:** Gün 030 — Linux journalctl ve Günlük Dizinleri
- **Değerlendirme Tarihi:** 2026-10-27
- **Sonuç:** **YETERLİ / PASS (100 / 100)**

---

## 2. Puanlama Tablosu

| Kriter | Açıklama | Taban Puan | Alınan Puan | Durum |
| :--- | :--- | :---: | :---: | :---: |
| **Kriter 1: Teorik Altyapı ve Kavramsal Yetkinlik** | systemd-journald mimarisi, ikili log yapısı, kalıcı (/var/log/journal) ve geçici (/run/log/journal) depolama farkı, saat dilimi (UTC vs Yerel) korelasyonu ve CWE-778 riskleri eksiksiz analiz edilmiştir. | 20 | **20** | Mükemmel |
| **Kriter 2: Pratik Uygulama ve Kod Kalitesi** | `linux_journalctl_log_auditor.py` aracı bağımsız, standart kütüphane odaklı, çok ölçütlü filtreleme, `journald.conf` ayrıştırıcısı ve SHA-256 mühürleme ile yazılmış; tüm satırları didaktik açıklamalarla donatılmıştır. | 40 | **40** | Mükemmel |
| **Kriter 3: Güvenlik Senaryoları ve Doğrulama** | G030-SC1, G030-SC2 (test VM sistem günlüğünde filtreleme, saat bilgisinin not edilmesi, negatif kontrolde 4 bozuk girdinin reddedilmesi) ve G030-SC3 (risk analizi, FSS mühürleme ve kota koruması) 14 birim test ile %100 doğrulanmıştır. | 25 | **25** | Mükemmel |
| **Kriter 4: Dokümantasyon, Raporlama ve Standart Uyumu** | Usta-çırak üslubu, 4 başlıklı senaryo formatı, özel lisans damgası, temsilî kanıt banner'ı, UTF-8 kodlama ve JSON veri bütünlüğü kurumsal standartta tamamlanmıştır. | 15 | **15** | Mükemmel |
| **TOPLAM** | **Genel Değerlendirme ve Başarı Skoru** | **100** | **100** | **YETERLİ (PASS)** |

---

## 3. Laboratuvar ve Test İstatistiği
- **Toplam Birim Test:** 14
- **Başarılı Test (PASS):** 14 (%100.0)
- **Başarısız / Hatalı Test:** 0 (%0.0)
- **Çalışma Süresi:** 0.175 saniye
- **Filtrelenen Birimler:** `sshd.service` (2 kayıt), `kernel` (1 kayıt), `sudo.service` (1 kayıt).
- **Negatif Kontrol Kapsamı:** 4 adet bozuk veya geçici depolama kaydı (eksik mesaj, geçersiz öncelik 99, bozuk tarih, volatile bellek) %100 başarıyla reddedilmiştir.
- **Kriptografik Bütünlük:** Her bir journal kaydının adli bütünlüğü için 64 karakterlik SHA-256 özeti hesaplanmıştır.

---

## 4. Çıkarılan Temel Sonuçlar ve Mühendislik Kazanımları
1. **Kalıcılık Zorunluluğu:** `Storage=persistent` yapılmayan sistemlerde sunucunun yeniden başlatılması adli delillerin yok olmasına yol açar.
2. **UTC Standardizasyonu:** Çoklu sunucu incelemelerinde yerel saat farkları kronolojik sırayı bozduğu için daima `journalctl --utc` kullanılmalıdır.
3. **Doğru Filtreleme:** Güvenlik olaylarını hızla tespit etmek için servis birimi (`-u`), öncelik (`-p`) ve metin arama filtreleri birlikte uygulanmalıdır.
