# Gün 144: Kerberos Temel Bilet Akışı — Değerlendirme Raporu

**Tarih:** 2026-11-03  
**Modül:** Hafta 21 — Gün 144 (Excel Satır 148)  
**Konu:** Kerberos v5 Temel Bilet Akışı, KDC Mimarisi ve Güvenlik Denetimi  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında RFC 4120 Kerberos v5 bilet yaşam döngüsü; Authentication Service (AS-REQ/AS-REP), Ticket Granting Service (TGS-REQ/TGS-REP) ve Application Service (AP-REQ/AP-REP) takasları uçtan uca simüle edilmiş ve kurumsal güvenlik kontrolleri doğrulanmıştır.

Bilet döngüsünde Kanıtlayıcı (Authenticator) zaman damgası ve mikrosaniye ayrıştırması, 300 saniyelik saat sapması (clock skew) sınırı, Replay Cache önbellek koruması, PAC (Privilege Attribute Certificate) HMAC Server ve KDC çift imza doğrulaması, şifreleme algoritması düşürme (RC4/DES downgrade) koruması ve bilet sahteciliği (Golden & Silver Ticket) tespit mantığı endüstriyel kalitede geliştirilmiştir.

Tüm denetim motoru harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş; 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla icra edilmiştir.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama, didaktik yorumlar) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (RFC 4120, RFC 3962 AES256, PAC HMAC, MITRE ATT&CK T1558) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 144: TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.003 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/kerberos_denetim_raporu.json
  - kanit/gercek/kerberos_sertlestirme_betigi.ps1
  - kanit/gercek/kerberos_hardening_matrix.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/kerberos_bilet_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Uygulanan Çözüm / Savunma | Durum |
|---------------|-------------------|---------------------------|-------|
| **Saat Sapması** | KDC ile istemci arasında >300s fark | `CLOCK_SKEW` kuralı ile anında reddetme; NTP senkronizasyonu | Doğrulandı |
| **Yeniden Oynatma** | Aynı kanıtlayıcının 5 dk içinde tekrar sunulması | Replay Cache tablosu ile `REPLAY_ATTACK_DETECTED` tespiti | Doğrulandı |
| **Bilet Süresi** | 10 saatlik geçerlilik süresini aşan TGT | `TGT_EXPIRED` hatası ile servis bileti verilmemesi | Doğrulandı |
| **Şifreleme Düşürme** | RC4-HMAC veya DES talebiyle Kerberoasting | Yalnızca AES-128 ve AES-256 zorlaması (`0x18`) | Doğrulandı |
| **Ön Kimlik Doğrulama** | `DONT_REQ_PREAUTH` bayrağı ile AS-REP Roasting | Pre-Auth zaman damgası zorunluluğu ve GPO düzeltmesi | Doğrulandı |
| **Golden Ticket** | Sahte KRBTGT anahtarıyla üretilen TGT | KDC imza bütünlük denetimi (`GOLDEN_TICKET_DETECTED`) | Doğrulandı |
| **Silver Ticket** | Servis anahtarıyla doğrudan üretilen sahte TGS | Sunucu anahtarı şifre çözümü (`SILVER_TICKET_DETECTED`) | Doğrulandı |
| **PAC Tahrifatı** | Bilet içine izinsiz yönetici SID ekleme | PAC Server ve KDC HMAC-SHA256 doğrulaması | Doğrulandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
