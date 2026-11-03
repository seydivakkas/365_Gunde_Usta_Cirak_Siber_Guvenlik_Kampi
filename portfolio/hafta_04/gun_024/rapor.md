# GÜN 024: Değerlendirme ve Başarım Raporu

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## 1. YÖNETİCİ ÖZETİ VE GENEL DEĞERLENDİRME

- **Modül Kodu ve Başlığı:** G024 - Linux dosya izinleri rwx
- **Aşama ve Hafta:** Aşama 02 (Sistem ve Ağ Temelleri), Hafta 04 (Linux ve Kabuk Güvenliği)
- **Excel Satır Numarası:** Satır 28
- **Tarih:** 2026-10-27
- **Sonuç:** **100 / 100 — YETERLİ (PASS)**

Bu çalışmada, Linux işletim sistemindeki POSIX erişim denetimi (DAC), okuma (`r=4`), yazma (`w=2`), çalıştırma (`x=1`) izin blokları, SUID (`4000`), SGID (`2000`) ve Sticky bit (`1000`) özel yetkileri, matematiksel umask filtreleme mekanizması, CWE-732 uygunsuzluklarının tespiti ve G024-SC2 laboratuvar gereksinimi olan atomik chmod değişikliği ve güvenli geri alma (rollback) mimarisi başarıyla geliştirilmiş ve doğrulanmıştır.

---

## 2. DÖRT BOYUTLU BAŞARIM VE PUANLAMA TABLOSU

| Değerlendirme Boyutu | Ağırlık / Tam Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod Kalitesi ve Standartlar** | 20 | **20** | Her bir çalıştırılabilir kod satırına pedagojik didaktik yorumlar eklenmiş, PEP 8 standartlarına, UTF-8 konsol kodlamasına ve özel lisans kurallarına eksiksiz uyulmuştur. |
| **2. Uygulama ve Fonksiyonellik** | 40 | **40** | `linux_permission_rwx_auditor.py` modülü; oktal <-> sembolik çevirici, umask hesaplayıcı, CWE-732 denetleyicisi, işlem günlüğü (journaling) ve tek komutla geri alma (rollback) yeteneklerini eksiksiz sunmaktadır. 14 birim testin tamamı 0.178 saniyede PASS olmuştur. |
| **3. Güvenlik ve Risk Yönetimi** | 25 | **25** | CIS Linux Benchmark ve NIST SP 800-53 AC-6 standartlarına göre kural tabanı oluşturulmuş, En Az Ayrıcalık ilkesi hayata geçirilmiş, negatif kontroller (`test_13`) ve etik sınırlar titizlikle korunmuştur. |
| **4. Belgeleme ve Raporlama** | 15 | **15** | `ders.md`, `soru_cevap.md` (4 zorunlu alt başlık ile 3 senaryo), gerçek yürütme kanıtları (`test_sonuclari.txt`, `chmod_degisiklik_ve_geri_alma_kaydi.txt`, `komut_ve_cikis.txt`), temsili şema (`linux_izin_rwx_mimarisi.txt`) ve `README.md` eksiksiz üretilmiştir. |
| **TOPLAM** | **100** | **100** | **YETERLİ / PASS** |

---

## 3. DOĞRULAMA VE TEST METRİKLERİ

- **Birim Test Dosyası:** `portfolio/hafta_04/gun_024/tests/test_linux_permission_rwx_auditor.py`
- **Koşulan Test Sayısı:** 14 test
- **Başarılı (OK):** 14
- **Hatalı / Başarısız:** 0
- **Test Süresi:** ~0.178 saniye
- **Test Edilen Özellikler:**
  1. Standart oktal -> sembolik dönüşüm (`0755`, `0644`, `0600`)
  2. Özel izin bitleri dönüşümü (SUID `4755`, SGID `2755`, Sticky `1777`)
  3. Sembolik -> oktal dönüşüm (`-rwxr-xr-x` -> `0755`)
  4. Özel bitli sembolik dönüşüm (`rwsr-xr-x` -> `4755`, `rwxrwxrwt` -> `1777`)
  5. Umask 022 dosya/dizin matematiksel hesaplaması (`0644` / `0755`)
  6. Umask 027 güçlendirilmiş hesaplama (`0640` / `0750`)
  7. Güvensiz umask tespiti (000, 002 risk uyarıları)
  8. Uyumlu dosya denetim tanıması (`/etc/passwd`)
  9. CWE-732 world-writable ihlali tespiti (`/var/log/syslog`)
  10. Hassas dosya sızıntısı tespiti (`/etc/shadow` o+r)
  11. Kontrollü chmod değişikliği ve işlem günlüğü üretimi (G024-SC2)
  12. Atomik geri alma (rollback) ile orijinal duruma dönüş (G024-SC2)
  13. Negatif kontrol ve istisna yönetimi (boş/eksik günlük dosyası)
  14. CLI arayüzünün subprocess üzerinden doğrulanması (çıkış kodu 0)

---

## 4. KANIT DOSYALARI DİZİNİ

- **Gerçek Kanıtlar (`kanit/gercek/`):**
  - `test_sonuclari.txt`: 14 birim testin canlı koşturulma çıktısı (OK).
  - `chmod_degisiklik_ve_geri_alma_kaydi.txt`: G024-SC2 kontrollü chmod değişikliği, günlük kaydı ve rollback kanıtı.
  - `komut_ve_cikis.txt`: `--audit`, `--umask`, `--convert` CLI araçlarının canlı konsol çıktıları.
- **Temsilî Kanıtlar (`kanit/temsili/`):**
  - `linux_izin_rwx_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla bit mimarisi ve umask şeması.

---

## 5. SONUÇ VE SONRAKİ GÜNE GEÇİŞ

G024 günü hedeflenen tüm pedagojik, teknik ve operasyonel şartları %100 oranında yerine getirmiştir. Excel takip tablosundaki Satır 28 güncellenmeye ve Gün 25'e (G025 - "Linux kullanıcı ve grup yönetimi") geçilmeye hazırdır.
