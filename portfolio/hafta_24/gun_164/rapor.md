# Gün 164: CSRF ve Oturum Bağlamı — Günlük Değerlendirme ve İlerleme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Genel Bilgiler

- **Tarih:** 2026-11-08
- **Eğitim Programı:** 365 Günde Usta-Çırak Siber Güvenlik Kampı
- **Aşama:** Aşama 07: Web Güvenliği
- **Hafta:** Hafta 24: Enjeksiyon ve İstek Güvenliği
- **Konu Başlığı:** CSRF ve Oturum Bağlamı (Gün 164 - Excel Satır No: 168)
- **Durum:** Tamamlandı (100/100 PASS)

---

## 2. 100/100 Başarı ve Değerlendirme Puan Kartı

| Kriter Kategorisi | Hedef / Standart | Gerçekleşen | Ağırlık | Alınan Puan | Durum |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Birim Testler (tests/)** | 15/15 Kapsamlı Test, 0 Hata | 15/15 PASS (0.001s) | %20 | 20 | MÜKEMMEL |
| **Uygulama & Mimari (uygulama/)** | Anti-CSRF Motoru, CLI, Didaktik Yorumlar | Tam teşekküllü motor & CLI, %100 yorum | %40 | 40 | MÜKEMMEL |
| **Kanıt & Negatif Kontroller (kanit/)** | 9 Negatif Kontrol, Gerçek & Temsili Kanıtlar | 9/9 Savunuldu, Tüm kanıtlar üretildi | %25 | 25 | MÜKEMMEL |
| **Dokümantasyon (ders, soru_cevap)** | Usta-Çırak anlatımı, 3 mülakat sorusu | Eksiksiz ders, soru-cevap ve rapor | %15 | 15 | MÜKEMMEL |
| **GENEL TOPLAM** | **100 Puan Standardı** | **100/100** | **%100** | **100** | **TAM BAŞARI (PASS)** |

---

## 3. Yapılan Çalışmaların Özeti

1. **Uygulama Geliştirme (`uygulama/csrf_engine.py` & `csrf_cli.py`):**
   - Tarayıcıların Ambient Authority (ortam yetkisi) davranışını ve zafiyetli uç noktaların nasıl istismar edildiğini simüle eden çekirdek motor kodlandı.
   - Kriptografik HMAC-SHA256 tabanlı, oturuma özel, zaman damgalı ve tek kullanımlık nonce içeren `AntiCSRFTokenManager` (Synchronizer Token Pattern) geliştirildi.
   - Katı köken denetimi yapan `OriginRefererValidator` (allowlist, null origin engeli, referer fallback) bileşeni inşa edildi.
   - Kritik bankacılık işlemleri (>= 5.000 TL transfer) için Step-Up Re-Authentication mekanizması modellendi.
   - `SameSite=Strict/Lax`, `HttpOnly`, `Secure` bayraklı kurumsal çerez başlıkları oluşturuldu.
   - CLI aracı ile belirteç üretimi, CSRF simülasyonu ve çerez analizi komut satırına taşındı.
   - Her bir çalıştırılabilir kod satırına didaktik Türkçe yorumlar eklendi.

2. **Birim Test Paketi (`tests/test_csrf_engine.py`):**
   - Belirteç formatı, imza tahrifatı, oturum uyuşmazlığı, TTL süre dolumu, replay koruması, Origin/Referer doğrulaması, HTTP metot kısıtlaması ve güvenli transferleri doğrulayan 15 birim test 0.001 saniyede %100 başarıyla tamamlandı.

3. **Örnek Veri ve Kurumsal Politikalar (`ornek_veri/`):**
   - `enterprise_csrf_policy.json`: Kurumsal Anti-CSRF ve oturum standardı JSON şemasıyla tanımlandı.
   - `invalid_csrf_payloads.json`: 9 negatif saldırı kontrol senaryosu oluşturuldu.

4. **Kanıt Üretimi ve Doğrulama (`kanit/`):**
   - `kanit_uretici.py` ile gerçek test sonuçları, negatif kontrol raporu (9/9 savunuldu), denetim JSON raporu, karşılaştırmalı HTTP işlem dökümleri ve CLI günlükleri üretildi.
   - `kanit/temsili/csrf_savunma_mimarisi.txt` dosyası zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII formatında kaydedildi.

---

## 4. Negatif Kontrol Saldırı Senaryoları Tablosu

| Senaryo ID | Saldırı Türü | Hedef Yol | Saldırı Yöntemi / Yükü | Beklenen Kod | Savunma Durumu |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **SCN-CSRF-01** | CLASSIC_CROSS_SITE_REQUEST | /api/transfer | Belirteçsiz POST (evil-attacker.site kökeni) | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-02** | STATE_MUTATING_GET | /api/transfer?target=3&amount=1500 | Durum değiştiren GET isteği | 405 Method Not Allowed | SAVUNULDU |
| **SCN-CSRF-03** | TAMPERED_TOKEN_SIGNATURE | /api/transfer | İmzası tahrif edilmiş Anti-CSRF belirteci | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-04** | CROSS_SESSION_TOKEN_REUSE | /api/transfer | Başka kullanıcının geçerli belirteci | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-05** | EXPIRED_TOKEN_REPLAY | /api/transfer | Süresi dolmuş belirteç (TTL > 1800s) | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-06** | CONSUMED_NONCE_REPLAY | /api/transfer | Daha önce harcanmış tek kullanımlık nonce | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-07** | NULL_ORIGIN_BYPASS | /api/transfer | Sandbox iframe kaynaklı 'null' Origin | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-08** | SUBDOMAIN_SPOOFING | /api/transfer | Alt alan adı taklidi (foreign origin) | 403 Forbidden | SAVUNULDU |
| **SCN-CSRF-09** | STEP_UP_REAUTH_BYPASS | /api/transfer | 12.000 TL transferinde re-auth süresi aşımı | 403 Forbidden | SAVUNULDU |

---

## 5. Sonuç

Gün 164 müfredat gereksinimleri, kod standartları, test kapsamı ve dokümantasyon gereksinimleri eksiksiz olarak tamamlanmıştır. Müfredat takip tablosunda Gün 164 satırı **100/100 PASS** olarak tescillenmiştir.
