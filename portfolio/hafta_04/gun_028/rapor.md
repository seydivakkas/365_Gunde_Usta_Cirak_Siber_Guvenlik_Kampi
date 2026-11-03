# Hafta 04 — Gün 028: Değerlendirme ve Sonuç Raporu (Mini Proje 3)

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu rapor eğitim ve değerlendirme amaçlı hazırlanmıştır. İzinsiz kopyalanamaz veya dağıtılamaz.*

---

## 1. Genel Bilgiler
- **Eğitim Programı:** Siber Güvenlik 365 Gün Standart ve Müfredat Paketi
- **Aşama:** Aşama 02 — Sistem ve Ağ Güvenliği Temelleri
- **Hafta:** Hafta 04 — İşletim Sistemi Güvenliği: Temel Mekanizmalar
- **Gün:** Gün 028 — Mini Proje 3: Komut Satırı Çalışma Defteri
- **Proje Kodu:** MP-04
- **Değerlendirme Tarihi:** 2026-10-27
- **Sonuç:** **YETERLİ / PASS (100 / 100)**

---

## 2. Puanlama Tablosu

| Kriter | Açıklama | Taban Puan | Alınan Puan | Durum |
| :--- | :--- | :---: | :---: | :---: |
| **Kriter 1: Teorik Altyapı ve Kavramsal Yetkinlik** | Komut satırı keşif felsefesi, adli gözlemlerin yeniden üretilebilirliği, salt-okunur denetim ilkeleri, MITRE ATT&CK Discovery teknikleri ve CWE-78/250 riskleri eksiksiz analiz edilmiştir. | 20 | **20** | Mükemmel |
| **Kriter 2: Pratik Uygulama ve Kod Kalitesi** | `command_line_notebook_engine.py` aracı çift aşamalı güvenlik kapısı (Blacklist RegEx + Whitelist), SHA-256 kriptografik mühürleme ve 380 satırlık Markdown defter üretimi ile geliştirilmiş; tüm satırları didaktik açıklamalarla donatılmıştır. | 40 | **40** | Mükemmel |
| **Kriter 3: Güvenlik Senaryoları ve Doğrulama** | G028-SC1, G028-SC2 (en az on salt-okunur komutun açıklamalı defteri ve negatif kontrolde 8 yıkıcı komutun %100 engellenmesi) ve G028-SC3 (risk analizi ve en az ayrıcalık savunması) 14 birim test ile %100 doğrulanmıştır. | 25 | **25** | Mükemmel |
| **Kriter 4: Dokümantasyon, Raporlama ve Standart Uyumu** | Usta-çırak üslubu, 4 başlıklı senaryo formatı, kırmızı lisans rozeti, temsilî kanıt banner'ı, UTF-8 karakter desteği ve JSON veri bütünlüğü kurumsal standartta tamamlanmıştır. | 15 | **15** | Mükemmel |
| **TOPLAM** | **Genel Değerlendirme ve Başarı Skoru** | **100** | **100** | **YETERLİ (PASS)** |

---

## 3. Laboratuvar ve Test İstatistiği
- **Toplam Birim Test:** 14
- **Başarılı Test (PASS):** 14 (%100.0)
- **Başarısız / Hatalı Test:** 0 (%0.0)
- **Çalışma Süresi:** 0.176 saniye
- **İncelenen Salt-Okunur Komut Sayısı:** 12 (Müfredat asgari şartı: 10)
- **Negatif Kontrol Kapsamı:** 8 tehlikeli komut (`rm -rf /`, `del /f /s /q`, `mkfs`, `dd`, `kill -9 1`, `chmod 777`, `curl | bash`, `useradd`) istisnasız engellenmiştir (8/8 %100 engelleme).
- **Kriptografik Bütünlük:** Her bir komut çıktısı için 64 karakterlik SHA-256 bütünlük özeti hesaplanmıştır.

---

## 4. Hafta 04 Mini Proje 3 Kazanımları ve Değerlendirme
1. **İşletim Sistemi Temelleri Başarıyla Tamamlandı:** Hafta 04 boyunca PowerShell, Linux kabuk/terminal, dosya izinleri (rwx), kullanıcı ve oturum yönetimi, PATH ve ortam değişkenleri ile paket yöneticileri konuları uygulamalı laboratuvarlarla tescillenmiştir.
2. **Adli Çalışma Defteri Standardı:** Güvenlik analistlerinin ve denetçilerin sisteme zarar vermeden durum tespiti yapabilmesi, bulguları kriptografik kanıtlarla mühürleyebilmesi ve denetlenebilir raporlar üretebilmesi için otonom bir altyapı kazanılmıştır.
3. **Gelecek Aşamaya Hazırlık:** Aşama 02 Hafta 05 itibarıyla ağ güvenliği, paket analizi ve OSI/TCP-IP protokol yığını incelemelerine geçilmeye hazır olunmuştur.
