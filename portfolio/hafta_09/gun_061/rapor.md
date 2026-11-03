# G061: Proxy, NAT ve Güvenlik Duvarı — Günlük Değerlendirme ve Teknik Sonuç Raporu

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Yönetici Özeti ve Rubrik Değerlendirmesi

Bu çalışma; Siber Güvenlik 365 Gün Müfredat Paketi'nin **Aşama 03 (Ağ Temelleri ve Protokoller)**, **Hafta 09 (Web Protokolleri ve Web Güvenliğine Giriş)** kapsamındaki **61. Gün (G061)** konusudur. "Proxy, NAT ve Güvenlik Duvarı" başlığı altında RFC 793, RFC 1918, RFC 3022 ve RFC 7239 standartları temelinde kapsamlı bir ağ simülasyon, filtreleme ve güvenlik motoru geliştirilmiştir.

Tüm kodlar, birim testler, negatif sınır testleri ve kanıtlar yerel çalışma ortamında Python 3.14 üzerinde sıfırdan ve bağımsızlık kuralına tam uyumlu olarak üretilmiştir.

### Değerlendirme ve Puanlama Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Alınan Puan | Açıklama ve Durum |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 20 | **20** | G061-SC1, SC2, SC3 soruları 4 zorunlu alt başlıkla derinlemesine yanıtlandı. |
| **Gerçek Uygulama / Simülasyon** | 40 | **40** | `proxy_nat_firewall_engine.py` modülü; Conntrack, PAT havuzu, Forward/Reverse proxy ve XFF savunması. |
| **Doğrulanabilir Kanıt** | 25 | **25** | 14 birim test + 9 negatif test %100 başarılı; gerçek terminal çıktıları arşivlendi. |
| **Teknik Rapor & Dokümantasyon** | 15 | **15** | Dürüst, kaynaklı, RFC referanslı ders, rapor ve mimari çizimler tamamlandı. |
| **TOPLAM PUAN** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 2. Geliştirilen Uygulama ve Teknik Mimari

### 2.1. `proxy_nat_firewall_engine.py`
Uygulama motoru, modern kurumsal ağ sınır savunmasını modelleyen şu temel modüllerden oluşmaktadır:
1. **Durum Takipli Güvenlik Duvarı (`StatefulFirewall`):**
   - 5'li demet bağlantı takip tablosu (Conntrack) tutar (`NEW`, `ESTABLISHED`, `CLOSED`).
   - Yalnızca izin verilen erişim kuralı olan portlara gelen `SYN` paketlerine `NEW` oturumu açar.
   - Karşı taraftan dönen `SYN-ACK` veya devam eden `ACK` veri akışlarını durum tablosu üzerinden `ESTABLISHED` olarak otomatik geçirir.
   - Durum tablosunda bulunmayan, önceden başlatılmamış sahte `ACK` veya beklenmedik paketleri `FirewallDropError` ile engeller.
   - Conntrack tablosu kapasite aşımını denetleyerek tablo taşmasını (`ConntrackOverflowError`) engeller.
2. **Port Adres Dönüşümü Motoru (`PATEngine`):**
   - RFC 3022 uyumlu dinamik port havuzu (`10000-65535`) yönetir.
   - İç ağ paketlerini kaynak genel IP ve tahsis edilen dönüştürülmüş porta çevirir (SNAT).
   - Dış dünyadan gelen yanıtları NAT eşleme tablosundan bularak iç istemciye teslim eder (DNAT).
   - Port havuzu tükendiğinde `NATExhaustionError` fırlatır.
3. **Vekil Sunucu Motoru (`ProxyEngine`):**
   - **Ters Vekil (Reverse Proxy):** Gelen istekleri doğrular, güvenilmeyen istemcilerden gelen `X-Forwarded-For: 127.0.0.1` gibi sahte başlıkları tespit edip `ProxySecurityViolationError` fırlatır; meşru isteklerde gerçek soket IP'sini başlığa güvenle işler ve Round-Robin ile arka uca yönlendirir.
   - **İleri Vekil (Forward Proxy):** HTTPS tünelleme için gelen `CONNECT` metotlarını denetler; yalnızca izin verilen güvenli portlara (443) izin verir, yasaklı portlara (ör. 22) erişimi `ProxyAccessDeniedError` ile engeller.
4. **TCP Bayrak Anomali Denetçisi (`validate_tcp_flags`):**
   - RFC 793 kural dışı taramaları denetler: `Flags = 0` (Null Scan), `SYN + FIN` taraması ve `FIN+PSH+URG` (Xmas Scan) paketlerini tespit ederek `InvalidPacketFlagsError` üretir.

---

## 3. Doğrulanabilir Kanıtlar ve Test Sonuçları

### 3.1. Birim Testleri (`test_proxy_nat_firewall_engine.py`)
- **Toplam Test:** 14
- **Başarılı:** 14 (%100)
- **Hatalı / Başarısız:** 0
- **Çalışma Süresi:** 0.002 saniye
- **Kanıt Dosyası:** `kanit/gercek/test_sonuclari.txt` ve `kanit/gercek/komut_ve_cikis.txt`

### 3.2. Negatif ve Sınır Değer Testleri (`invalid_traffic_inputs.json`)
- **Toplam Negatif Senaryo:** 9
- **Başarılı Engelleme:** 9 (%100)
- **Kanıt Dosyası:** `kanit/gercek/negatif_kontrol_sonuclari.txt`

| Senaryo ID | Test Tanımı | Beklenen İstisna | Alınan Sonuç |
| :--- | :--- | :--- | :--- |
| `NEG_01` | RFC 793 İhlali SYN+FIN Gizli Tarama | `InvalidPacketFlagsError` | Başarıyla Yakalandı |
| `NEG_02` | Güvenilmeyen İstemciden XFF Sahteciliği | `ProxySecurityViolationError` | Başarıyla Yakalandı |
| `NEG_03` | Durumsuz Sızma (Oturumsuz ACK Paketi) | `FirewallDropError` | Başarıyla Yakalandı |
| `NEG_04` | Yasaklı Porta (23 Telnet) Gelen SYN | `FirewallDropError` | Başarıyla Yakalandı |
| `NEG_05` | PAT Dinamik Port Havuzu Tükenmesi | `NATExhaustionError` | Başarıyla Yakalandı |
| `NEG_06` | Biçimsiz IPv4 Adresi (999.999.999.999) | `NetworkValidationError` | Başarıyla Yakalandı |
| `NEG_07` | Forward Proxy CONNECT ile Yasaklı Port (22) | `ProxyAccessDeniedError` | Başarıyla Yakalandı |
| `NEG_08` | Conntrack Durum Tablosu Taşması | `ConntrackOverflowError` | Başarıyla Yakalandı |
| `NEG_09` | Bayraksız Null Scan Paketi (Flags = 0) | `InvalidPacketFlagsError` | Başarıyla Yakalandı |

---

## 4. Akademik ve Sektörel Standart Referansları

1. **RFC 793:** Transmission Control Protocol (TCP Protokolü ve Bayrak Tanımları)
2. **RFC 1918:** Address Allocation for Private Internets (Özel IP Blokları)
3. **RFC 3022:** Traditional IP Network Address Translator (Traditional NAT / PAT)
4. **RFC 7239:** Forwarded HTTP Extension (X-Forwarded-For Standartlaştırılması)
5. **RFC 6598:** IANA-Reserved IPv4 Prefix for Shared Address Space (CGNAT 100.64.0.0/10)
6. **RFC 4987:** TCP SYN Flooding Attacks and Common Mitigations (SYN Cookies)

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Günlük değerlendirme raporu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
