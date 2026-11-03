# GÜN 020: Değerlendirme Raporu — Linux Dosya Ağacı ve FHS

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu rapor Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## 1. Genel Değerlendirme ve İlerleme Durumu

- **Öğrenci / Aday:** Seydi Eryılmaz (@seydivakkas)
- **Tarih:** 2026-10-27
- **Aşama:** 02 (Sistem ve Ağ Temelleri)
- **Hafta:** 03 (İşletim Sistemi Temelleri ve Güvenliği)
- **Gün:** 020 (Linux Dosya Ağacı ve FHS)
- **Excel Satır Numarası:** 24
- **Genel Karar:** **100 / 100 — TAM BAŞARILI (YETERLİ / PASS)**

---

## 2. Puanlama Kriterleri ve Başarım Detayları

### Kriter 1: Teorik Altyapı ve Kavramsal Derinlik (20 Puan)
- **Alınan Puan:** **20 / 20**
- **Değerlendirme Notu:** 
  - Linux dosya sisteminin tek kök (`/`) felsefesi ve Filesystem Hierarchy Standard (FHS 3.0) standartları eksiksiz açıklanmıştır.
  - En az 6 çekirdek dizin (`/etc`, `/var`, `/home`, `/tmp`, `/dev`, `/proc`) için statik/değişken, paylaşılabilir/paylaşılamaz nitelikleri, kullanım amaçları ve güvenlik sınırları derinlemesine incelenmiştir.
  - Sticky Bit (+t) ve mount bayraklarının (`nodev`, `nosuid`, `noexec`, `hidepid`) güvenlik mekanizması detaylandırılmıştır.

### Kriter 2: Laboratuvar ve Kodlama Kalitesi (40 Puan)
- **Alınan Puan:** **40 / 40**
- **Değerlendirme Notu:**
  - `linux_fhs_hierarchy_auditor.py` aracı modüler mimaride, type hinting ve zengin Türkçe açıklama satırlarıyla yazılmıştır.
  - Bağımsız JSON girdi ve güvenlik referans dosyaları (`linux_fhs_sample_map.json`, `linux_fhs_security_baseline.json`) hazırlanmıştır.
  - Birim test suite (`test_linux_fhs_hierarchy_auditor.py`) 14 farklı test senaryosu içermekte olup **14/14 test 0.239 saniyede başarıyla (%100 PASS)** tamamlanmıştır.
  - Pozitif senaryoların yanı sıra 4 adet negatif test (`FileNotFoundError`, eksik FHS dizini, eksik Sticky Bit, güvensiz `/etc/shadow` izni) eksiksiz doğrulanmıştır.

### Kriter 3: Güvenlik, Risk Analizi ve Tehdit Modellemesi (25 Puan)
- **Alınan Puan:** **25 / 25**
- **Değerlendirme Notu:**
  - CWE-732 (Yanlış İzin Yönetimi) ve CWE-377 (Güvensiz Geçici Dosya Oluşturma) zafiyetleri kod düzeyinde ele alınmıştır.
  - SUID backdoor barındırma, log taşkını ile kök dizin tüketimi ve `/etc/shadow` hash sızıntısı saldırı senaryoları modellenmiştir.
  - CIS Linux Benchmark 1.1 / 6.1 ve NIST SP 800-53 tabanlı mount sertleştirme ve FIM kontrolleri formüle edilmiştir.

### Kriter 4: Kanıt Bütünlüğü, Raporlama ve Standart Uyumu (15 Puan)
- **Alınan Puan:** **15 / 15**
- **Değerlendirme Notu:**
  - Gerçek komut çalıştırma kanıtı (`kanit/gercek/komut_ve_cikis.txt`) ve birim test çıktısı (`kanit/gercek/test_sonuclari.txt`) eksiksiz kaydedilmiştir.
  - Temsili mimari görselleştirmesi (`kanit/temsili/linux_fhs_mimarisi.txt`) zorunlu uyarı başlığı (`TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL`) ile üretilmiştir.
  - Soru bankası soruları (`G020-SC1`, `G020-SC2`, `G020-SC3`) 4 zorunlu alt başlık altında yanıtlanmıştır.

---

## 3. Puan Özeti Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Kazanılan Puan | Durum |
|---|:---:|:---:|:---:|
| 1. Teorik Altyapı ve Kavramsal Derinlik | 20 | 20 | Başarılı |
| 2. Laboratuvar ve Kodlama Kalitesi | 40 | 40 | Başarılı |
| 3. Güvenlik, Risk Analizi ve Tehdit Modellemesi | 25 | 25 | Başarılı |
| 4. Kanıt Bütünlüğü, Raporlama ve Standart Uyumu | 15 | 15 | Başarılı |
| **TOPLAM** | **100** | **100** | **YETERLİ / PASS** |

---

## 4. Sonuç ve Sonraki Gün Planı

Gün 020 "Linux dosya ağacı ve FHS" modülü 100/100 tam puanla başarıyla tamamlanmıştır. Yarın **Gün 021** (Aşama 02, Hafta 03, Gün 21) kapsamında **"Linux izin yapısı ve erişim denetimi"** konusu işlenecektir.
