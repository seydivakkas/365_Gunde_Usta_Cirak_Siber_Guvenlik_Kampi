# Gün 165: CORS ile Güvenlik Sınırı — Günlük Değerlendirme ve İlerleme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Genel Bilgiler

- **Tarih:** 2026-11-08
- **Eğitim Programı:** 365 Günde Usta-Çırak Siber Güvenlik Kampı
- **Aşama:** Aşama 07: Web Güvenliği
- **Hafta:** Hafta 24: Enjeksiyon ve İstek Güvenliği
- **Konu Başlığı:** CORS ile Güvenlik Sınırı (Gün 165 - Excel Satır No: 169)
- **Durum:** Tamamlandı (100/100 PASS)

---

## 2. 100/100 Başarı ve Değerlendirme Puan Kartı

| Kriter Kategorisi | Hedef / Standart | Gerçekleşen | Ağırlık | Alınan Puan | Durum |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Birim Testler (tests/)** | 15/15 Kapsamlı Test, 0 Hata | 15/15 PASS (0.001s) | %20 | 20 | MÜKEMMEL |
| **Uygulama & Mimari (uygulama/)** | CORS Savunma Motoru, CLI, Didaktik Yorumlar | Tam teşekküllü motor & CLI, %100 yorum | %40 | 40 | MÜKEMMEL |
| **Kanıt & Negatif Kontroller (kanit/)** | 9 Negatif Kontrol, Gerçek & Temsili Kanıtlar | 9/9 Savunuldu, Tüm kanıtlar üretildi | %25 | 25 | MÜKEMMEL |
| **Dokümantasyon (ders, soru_cevap)** | Usta-Çırak anlatımı, 3 mülakat sorusu | Eksiksiz ders, soru-cevap ve rapor | %15 | 15 | MÜKEMMEL |
| **GENEL TOPLAM** | **100 Puan Standardı** | **100/100** | **%100** | **100** | **TAM BAŞARI (PASS)** |

---

## 3. Yapılan Çalışmaların Özeti

1. **Uygulama Geliştirme (`uygulama/cors_engine.py` & `cors_cli.py`):**
   - Aynı Köken İlkesi'ni (SOP) ve CORS'un izin mekanizmasını modelleyen çekirdek savunma motoru kodlandı.
   - Sıkça yapılan tehlikeli hatalar (Arbitrary Origin Reflection, `null` Origin kabulü, gevşek regex alt alan adı atlatmaları, kaçılmamış nokta hataları) simüle edildi.
   - Kurumsal düzeyde katı beyaz liste (`EnterpriseCORSPolicy`) ile şema, ana makine ve port izolasyonu uygulandı.
   - Preflight (OPTIONS) mekanizması doğrulanarak izinli metotlar (`Access-Control-Allow-Methods`) ve izinli başlıklar (`Access-Control-Allow-Headers`) denetlendi.
   - Önbellek zehirlenmesine (Cache Poisoning) karşı `Vary: Origin` başlığı zorunlu kılındı.
   - CLI aracı ile köken değerlendirme, preflight testi ve zafiyet simülasyonu sağlandı.
   - Her bir çalıştırılabilir satıra didaktik Türkçe yorumlar eklendi.

2. **Birim Test Paketi (`tests/test_cors_engine.py`):**
   - İzinli kökenler, `Vary: Origin` varlığı, yabancı kökenlerin 403 ile engellenmesi, `null` origin reddi, preflight onay/red mekanizmaları, regex hatalarının saptanması, port ve şema izolasyonu gibi kritik kontrolleri içeren 15 birim test 0.001 saniyede %100 başarıyla tamamlandı.

3. **Örnek Veri ve Kurumsal Politikalar (`ornek_veri/`):**
   - `enterprise_cors_policy.json`: Kurumsal CORS güvenlik standardı JSON şemasıyla tanımlandı.
   - `invalid_cors_payloads.json`: 9 negatif saldırı kontrol senaryosu oluşturuldu.

4. **Kanıt Üretimi ve Doğrulama (`kanit/`):**
   - `kanit_uretici.py` ile gerçek test sonuçları, negatif kontrol raporu (9/9 savunuldu), denetim JSON çıktısı, karşılaştırmalı CORS istek/yanıt dökümleri ve CLI günlükleri üretildi.
   - `kanit/temsili/cors_guvenlik_siniri_mimarisi.txt` dosyası zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII formatında kaydedildi.

---

## 4. Negatif Kontrol Saldırı Senaryoları Tablosu

| Senaryo ID | Saldırı Türü | Hedef Yol | Gönderilen Origin / İstek | Beklenen Kod | Savunma Durumu |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **SCN-CORS-01** | UNAUTHORIZED_FOREIGN_ORIGIN | /api/finansal-rapor | `Origin: https://evil-attacker.com` | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-02** | NULL_ORIGIN_ALLOWED | /api/kullanici/bakiye | `Origin: null` (Sandbox iframe / data URI) | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-03** | LOOSE_REGEX_SUBDOMAIN | /api/gizli-veriler | `Origin: https://evil-portal.kurum.internal` | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-04** | LOOSE_REGEX_SUBDOMAIN | /api/gizli-veriler | `Origin: https://portal.kurum.internal.evil-attacker.com` | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-05** | UNESCAPED_DOT_REGEX | /api/gizli-veriler | `Origin: https://portalxkurumxinternal` | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-06** | INSECURE_HTTP_SCHEME | /api/kullanici/profil | `Origin: http://portal.kurum.internal` (Düz metin HTTP) | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-07** | PORT_ISOLATION_VIOLATION | /api/kullanici/profil | `Origin: https://portal.kurum.internal:8080` (Farklı Port) | 403 Forbidden | SAVUNULDU |
| **SCN-CORS-08** | PREFLIGHT_DISALLOWED_METHOD | /api/transfer | Preflight Metot Talebi: `TRACE` | 405 Method Not Allowed | SAVUNULDU |
| **SCN-CORS-09** | PREFLIGHT_DISALLOWED_HEADER | /api/transfer | Preflight Başlık: `x-malicious-exploit-header` | 403 Forbidden | SAVUNULDU |

---

## 5. Sonuç

Gün 165 müfredat gereksinimleri, kod standartları, test kapsamı ve dokümantasyon gereksinimleri eksiksiz olarak tamamlanmıştır. Müfredat takip tablosunda Gün 165 satırı **100/100 PASS** olarak tescillenmiştir.
