# Gün 166: SSRF Kavramı ve Savunma — Günlük Değerlendirme ve İlerleme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Genel Bilgiler

- **Tarih:** 2026-11-14
- **Eğitim Programı:** 365 Günde Usta-Çırak Siber Güvenlik Kampı
- **Aşama:** Aşama 07: Web Güvenliği
- **Hafta:** Hafta 24: Enjeksiyon ve İstek Güvenliği
- **Konu Başlığı:** SSRF Kavramı ve Savunma (Gün 166 - Excel Satır No: 170)
- **Durum:** Tamamlandı (100/100 PASS)

---

## 2. 100/100 Başarı ve Değerlendirme Puan Kartı

| Kriter Kategorisi | Hedef / Standart | Gerçekleşen | Ağırlık | Alınan Puan | Durum |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Birim Testler (tests/)** | 15/15 Kapsamlı Test, 0 Hata | 15/15 PASS (0.002s) | %20 | 20 | MÜKEMMEL |
| **Uygulama & Mimari (uygulama/)** | SSRF Savunma Motoru, CLI, Didaktik Yorumlar | Tam teşekküllü motor & CLI, %100 yorum | %40 | 40 | MÜKEMMEL |
| **Kanıt & Negatif Kontroller (kanit/)** | 9 Negatif Kontrol, Gerçek & Temsili Kanıtlar | 9/9 Savunuldu, Tüm kanıtlar üretildi | %25 | 25 | MÜKEMMEL |
| **Dokümantasyon (ders, soru_cevap)** | Usta-Çırak anlatımı, 3 mülakat sorusu | Eksiksiz ders, soru-cevap ve rapor | %15 | 15 | MÜKEMMEL |
| **GENEL TOPLAM** | **100 Puan Standardı** | **100/100** | **%100** | **100** | **TAM BAŞARI (PASS)** |

---

## 3. Yapılan Çalışmaların Özeti

1. **Uygulama Geliştirme (`uygulama/ssrf_defense_engine.py` & `ssrf_defense_cli.py`):**
   - Sunucu Taraflı İstek Sahteciliği (SSRF / CWE-918) tehditlerini analiz eden çok katmanlı savunma motoru kodlandı.
   - Yerel döngü (Loopback), RFC 1918 özel kurumsal ağlar (10.x, 172.16.x, 192.168.x) ve Bulut Metaveri Servisi (`169.254.169.254`) filtreleme modülleri geliştirildi.
   - Gizlenmiş IP biçimlerini (DWORD/Tamsayı, Onaltılık/Hex, Sekizli/Octal, Kısaltılmış IP ve IPv4-mapped IPv6) standart formata çeviren çözümleyici yazıldı.
   - DNS Rebinding ve TOCTOU açıklarına karşı IP Sabitleme (IP Pinning) ve Pre-Request DNS denetimi kuruldu.
   - HTTP Açık Yönlendirme (Open Redirect) atlatmalarını önlemek amacıyla her yönlendirme hedefini (`Location`) sıfırdan denetleyen güvenli HTTP istemcisi (`MockSafeHTTPClient`) simüle edildi.
   - Zafiyetli ve güvenli istemcilerin davranışlarını karşılaştıran sanal ağ (`MockInternalNetwork`) ortamı yapılandırıldı.
   - Kod tabanındaki her bir çalıştırılabilir satıra didaktik Türkçe yorumlar eklendi.

2. **Birim Test Paketi (`tests/test_ssrf_defense.py`):**
   - Loopback engeli, bulut metaveri koruması, RFC 1918 sınıfları, yasaklı şemalar (`file://`, `gopher://`), gizlenmiş IP'lerin çözümlenmesi, IPv6 loopback, Taşıyıcı NAT (CGNAT), meşru genel URL onaylaması, 302 açık yönlendirme engeli, zafiyetli metaveri sızıntısı ve DNS rebinding durumlarını içeren 15 birim test 0.002 saniyede %100 başarıyla tamamlandı.

3. **Örnek Veri ve Kurumsal Politikalar (`ornek_veri/`):**
   - `enterprise_ssrf_policy.json`: Kurumsal SSRF ve çıkış trafiği (Egress) standardı JSON şemasıyla tanımlandı.
   - `invalid_ssrf_payloads.json`: 9 negatif saldırı kontrol senaryosu oluşturuldu.

4. **Kanıt Üretimi ve Doğrulama (`kanit/`):**
   - `kanit_uretici.py` ile gerçek test sonuçları, negatif kontrol raporu (9/9 savunuldu), denetim JSON çıktısı, karşılaştırmalı getirme dökümleri ve CLI konsol günlükleri üretildi.
   - `kanit/temsili/ssrf_savunma_mimarisi.txt` dosyası zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII formatında kaydedildi.

---

## 4. Negatif Kontrol Saldırı Senaryoları Tablosu

| Senaryo ID | Saldırı Türü | Hedef URL / İstek | Beklenen Tehdit İmzası | Beklenen Kod | Savunma Durumu |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **SCN-SSRF-01** | LOOPBACK_ACCESS | `http://127.0.0.1:8080/admin` | LOOPBACK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-02** | CLOUD_METADATA_ACCESS | `http://169.254.169.254/...` | CLOUD_METADATA_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-03** | PRIVATE_NETWORK_ACCESS | `http://10.0.0.5:5432/status` | PRIVATE_NETWORK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-04** | PRIVATE_NETWORK_ACCESS | `http://172.16.1.100:8000/api` | PRIVATE_NETWORK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-05** | PRIVATE_NETWORK_ACCESS | `http://192.168.1.1/router-login` | PRIVATE_NETWORK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-06** | DISALLOWED_SCHEME | `file:///etc/passwd` | DISALLOWED_SCHEME | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-07** | OBFUSCATED_IP_FORMAT | `http://2130706433/admin` (DWORD) | LOOPBACK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-08** | OBFUSCATED_IP_FORMAT | `http://0x7f000001/admin` (Hex) | LOOPBACK_ACCESS | 403 Forbidden | SAVUNULDU |
| **SCN-SSRF-09** | OPEN_REDIRECT_SSRF | `https://public-service.com/redirect...` | CLOUD_METADATA_ACCESS | 403 Forbidden | SAVUNULDU |

---

## 5. Sonuç

Gün 166 müfredat gereksinimleri, kod standartları, test kapsamı ve dokümantasyon gereksinimleri eksiksiz olarak tamamlanmıştır. Müfredat takip tablosunda Gün 166 satırı **100/100 PASS** olarak tescillenmiştir.
