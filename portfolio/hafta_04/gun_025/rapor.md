# GÜN 025: Değerlendirme ve Başarım Raporu

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## 1. YÖNETİCİ ÖZETİ VE GENEL DEĞERLENDİRME

- **Modül Kodu ve Başlığı:** G025 - Kullanıcı, grup ve oturum
- **Aşama ve Hafta:** Aşama 02 (Sistem ve Ağ Temelleri), Hafta 04 (Linux ve Kabuk Güvenliği)
- **Excel Satır Numarası:** Satır 29
- **Tarih:** 2026-10-27
- **Sonuç:** **100 / 100 — YETERLİ (PASS)**

Bu çalışmada, kullanıcı hesapları, gruplar ve oturumlar arasındaki temel mimari bağlar, statik kimlik (Authentication) ile dinamik etkin oturum (Active Session) ayrımı, servis hesaplarının sıkılaştırılması (etkileşimli kabukların yasaklanması), ortak hesapların (shared accounts) inkâr edilemezlik ilkesine vurduğu darbe, atıl (dormant) hesaplar ve oturum zaman aşımı kontrolleri başarıyla hayata geçirilmiş; canlı yerel oturum meta verileri G025-SC2 gereğince belgelenmiş ve 14 birim testin tamamı PASS olmuştur.

---

## 2. DÖRT BOYUTLU BAŞARIM VE PUANLAMA TABLOSU

| Değerlendirme Boyutu | Ağırlık / Tam Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod Kalitesi ve Standartlar** | 20 | **20** | Her bir çalıştırılabilir kod satırına pedagojik didaktik açıklamalar eklenmiş, PEP 8 standartları, UTF-8 konsol kodlaması ve özel lisans kurallarına eksiksiz riayet edilmiştir. |
| **2. Uygulama ve Fonksiyonellik** | 40 | **40** | `user_group_session_auditor.py` aracı canlı yerel oturumu belgeleme (G025-SC2), kullanıcı ve oturum envanterini denetleme, servis hesapları kabuk analizi, eşzamanlı idari oturum tespiti ve uyumluluk skoru hesaplama yeteneklerini eksiksiz sunmaktadır. 14 birim test 0.504 saniyede PASS olmuştur. |
| **3. Güvenlik ve Risk Yönetimi** | 25 | **25** | CIS Linux Benchmark, NIST SP 800-53 IA-2 / AC-2 / AC-10 standartlarına uygun kural seti tasarlanmış, CWE-250, CWE-262, CWE-306, CWE-613 kontrolleri modellenmiş, negatif kontroller (`test_12`, `test_13`) ve etik sınırlar titizlikle korunmuştur. |
| **4. Belgeleme ve Raporlama** | 15 | **15** | `ders.md`, `soru_cevap.md` (4 zorunlu alt başlık ile 3 senaryo), canlı yürütme kanıtları (`yerel_oturum_belgeleme.txt`, `test_sonuclari.txt`, `komut_ve_cikis.txt`), temsili şema (`kimlik_ve_oturum_mimarisi.txt`) ve `README.md` eksiksiz oluşturulmuştur. |
| **TOPLAM** | **100** | **100** | **YETERLİ / PASS** |

---

## 3. DOĞRULAMA VE TEST METRİKLERİ

- **Birim Test Dosyası:** `portfolio/hafta_04/gun_025/tests/test_user_group_session_auditor.py`
- **Koşulan Test Sayısı:** 14 test
- **Başarılı (OK):** 14
- **Hatalı / Başarısız:** 0
- **Test Süresi:** ~0.504 saniye
- **Test Edilen Yetkinlikler:**
  1. Canlı oturumdan kullanıcı, makine ve PID tespiti (G025-SC2)
  2. Oturum veri yapısının şema doğrulaması
  3. Uyumlu kullanıcı ve oturumun %100 skor alması
  4. Servis hesabı etkileşimli kabuk ihlali tespiti (CWE-250, KRİTİK)
  5. Servis hesabı idari grup üyeliği tespiti (CWE-250, YÜKSEK)
  6. Atıl (dormant) hesap tespiti (CWE-262, ORTA)
  7. Ortak hesap eşzamanlı aktif oturum tespiti (CWE-306, KRİTİK - G025-SC1)
  8. Oturum boşta kalma süresi (timeout) aşımı tespiti (CWE-613, ORTA)
  9. Çoklu ihlal senaryosunda uyumluluk skoru hesaplama
  10. İyileştirme (remediation) komutu üretimi
  11. Boş envanter yönetimi
  12. Negatif kontrol: Olmayan dosya ile CLI hata yönetimi
  13. Negatif kontrol: Bozuk JSON ayrıştırma istisnası
  14. CLI subprocess üzerinden canlı oturum JSON çıktısı doğrulaması (çıkış kodu 0)

---

## 4. KANIT DOSYALARI DİZİNİ

- **Gerçek Kanıtlar (`kanit/gercek/`):**
  - `yerel_oturum_belgeleme.txt`: G025-SC2 gereğince canlı oturumun kullanıcı adı, SID, işletim sistemi, süreç PID'si ve yetkilerinin yerel komutlarla belgelenmesi.
  - `test_sonuclari.txt`: 14 birim testin canlı koşturulma çıktısı (OK).
  - `komut_ve_cikis.txt`: `--audit` ve `--audit --json` CLI komutlarının gerçek çalışma çıktıları.
- **Temsilî Kanıtlar (`kanit/temsili/`):**
  - `kimlik_ve_oturum_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla kimlik vs. oturum, UID/EUID süreç belirteçleri ve ortak hesap zaafı şeması.

---

## 5. SONUÇ VE SONRAKİ GÜNE GEÇİŞ

G025 günü hedeflenen tüm pedagojik, teknik ve operasyonel şartları %100 oranında yerine getirmiştir. Excel takip tablosundaki Satır 29 güncellenmeye ve Gün 26'ya (G026) geçilmeye hazırdır.
