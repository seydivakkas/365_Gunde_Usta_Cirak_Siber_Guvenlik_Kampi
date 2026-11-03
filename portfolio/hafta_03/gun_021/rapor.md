# GÜN 021: Değerlendirme Raporu — Mini Proje 2: İşletim Sistemi Envanteri

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu rapor Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## 1. Genel Değerlendirme ve İlerleme Durumu

- **Öğrenci / Aday:** Seydi Eryılmaz (@seydivakkas)
- **Tarih:** 2026-10-27
- **Aşama:** 02 (Sistem ve Ağ Temelleri)
- **Hafta:** 03 (İşletim Sistemi Temelleri ve Güvenliği)
- **Gün:** 021 (Mini Proje 2: İşletim Sistemi Envanteri)
- **Excel Satır Numarası:** 25
- **Genel Karar:** **100 / 100 — TAM BAŞARILI (YETERLİ / PASS)**

---

## 2. Puanlama Kriterleri ve Başarım Detayları

### Kriter 1: Teorik Altyapı ve Kavramsal Derinlik (20 Puan)
- **Alınan Puan:** **20 / 20**
- **Değerlendirme Notu:** 
  - CIS Control 1-2, NIST SP 800-53 CM-8 ve ISO 27001 A.8.1 standartları doğrultusunda kurumsal envanter felsefesi detaylıca incelenmiştir.
  - Soru bankası G021-SC1 gereğince 5 temel güvenlik boyutu (sürüm/çekirdek, donanım/depolama, hesaplar, servisler, güncellemeler) teorik ve metodolojik olarak ayrıştırılmıştır.
  - Windows (WMI, Registry, PowerShell) ve Linux (procfs, systemd, os-release) envanter toplama mimarilerinin farkları ve veri normalizasyonu açıklanmıştır.

### Kriter 2: Laboratuvar ve Kodlama Kalitesi (40 Puan)
- **Alınan Puan:** **40 / 40**
- **Değerlendirme Notu:**
  - `os_security_inventory_collector.py` aracı canlı sistemden (`--live`) telemetri toplayabilen ve bağımsız JSON haritalarından denetim yapabilen esnek bir yapıda geliştirilmiştir.
  - Tüm kod satırları didaktik açıklamalarla zenginleştirilmiş; tip ipuçları (type hints) ve modüler fonksiyonlar kullanılmıştır.
  - Birim test suite (`test_os_security_inventory_collector.py`) 14 farklı test senaryosu içermekte olup **14/14 test 0.250 saniyede (%100 PASS)** başarıyla tamamlanmıştır.
  - 4 adet negatif test (`FileNotFoundError`, `ValueError` bozuk JSON, eksik kategori şeması, çalışan güvensiz Telnet tespiti) eksiksiz doğrulanmıştır.

### Kriter 3: Güvenlik, Risk Analizi ve Tehdit Modellemesi (25 Puan)
- **Alınan Puan:** **25 / 25**
- **Değerlendirme Notu:**
  - Şifresiz/eski servisler (Telnet, FTP, SMBv1) için karaliste denetimi ve `KRITIK` risk sınıflandırması kodlanmıştır.
  - Varsayılan konuk (Guest) hesaplarının açık bırakılması ve geciken kritik güvenlik yamaları `YUKSEK` risk seviyesinde tespit edilmiştir.
  - BitLocker ve LUKS tam disk şifreleme denetimi ile durağan veri (Data at Rest) koruması ele alınmıştır.
  - Soru bankası G021-SC2 gereğince Windows ve Linux'u yan yana kıyaslayan 5 kolonlu karşılaştırmalı CSV raporu (`karsilastirmali_os_envanter.csv`) üretilmiştir.

### Kriter 4: Kanıt Bütünlüğü, Raporlama ve Standart Uyumu (15 Puan)
- **Alınan Puan:** **15 / 15**
- **Değerlendirme Notu:**
  - Gerçek komut ve çıktı kanıtı (`kanit/gercek/komut_ve_cikis.txt`), birim test kanıtı (`kanit/gercek/test_sonuclari.txt`) ve üretilen gerçek CSV dosyası eksiksiz sunulmuştur.
  - Temsili mimari akış diyagramı (`kanit/temsili/os_envanter_mimarisi.txt`) zorunlu uyarı başlığı (`TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL`) ile hazırlanmıştır.
  - Soru bankası soruları (`G021-SC1`, `G021-SC2`, `G021-SC3`) 4 zorunlu alt başlık altında eksiksiz yanıtlanmıştır.

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

## 4. Sonuç ve Hafta Kapanışı

Gün 021 Mini Proje 2 başarıyla tamamlanmış ve böylece **Aşama 02 / Hafta 03 (İşletim Sistemi Temelleri ve Güvenliği)** 100/100 tam puanla kapatılmıştır. Gelecek hafta **Hafta 04 / Gün 022** ile birlikte **"Ağ Temelleri, TCP/IP ve Protokol Güvenliği"** konusuna geçilecektir.
