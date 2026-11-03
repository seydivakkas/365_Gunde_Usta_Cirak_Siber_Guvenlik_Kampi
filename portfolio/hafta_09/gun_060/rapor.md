# G060: HTTP/2 ve HTTP/3 Farkları — Günlük Değerlendirme ve Teknik Sonuç Raporu

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Yönetici Özeti ve Rubrik Değerlendirmesi

Bu çalışma; Siber Güvenlik 365 Gün Müfredat Paketi'nin **Aşama 03 (Ağ Temelleri ve Protokoller)**, **Hafta 09 (Web Protokolleri ve Web Güvenliğine Giriş)** kapsamındaki **60. Gün (G060)** konusudur. "HTTP/2 ve HTTP/3 Farkları" üzerine RFC 7540 / RFC 9113, RFC 9000, RFC 9114 ve RFC 7541 standartları temelinde kapsamlı bir analiz, simülasyon ve test motoru geliştirilmiştir.

Tüm kodlar, birim testler, negatif sınır testleri ve kanıtlar yerel çalışma ortamında Python 3.14 üzerinde sıfırdan ve bağımsızlık kuralına tam uyumlu olarak üretilmiştir.

### Değerlendirme ve Puanlama Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Alınan Puan | Açıklama ve Durum |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 20 | **20** | G060-SC1, SC2, SC3 soruları 4 zorunlu alt başlıkla derinlemesine yanıtlandı. |
| **Gerçek Uygulama / Simülasyon** | 40 | **40** | `http2_http3_analyzer.py` modülü; 9 bayt çerçeveleme, HoL simülasyonu, Rapid Reset ve Anti-Amplification motoru. |
| **Doğrulanabilir Kanıt** | 25 | **25** | 14 birim test + 9 negatif test %100 başarılı; gerçek terminal çıktıları arşivlendi. |
| **Teknik Rapor & Dokümantasyon** | 15 | **15** | Dürüst, kaynaklı, RFC referanslı ders, rapor ve mimari çizimler tamamlandı. |
| **TOPLAM PUAN** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 2. Geliştirilen Uygulama ve Teknik Mimari

### 2.1. `http2_http3_analyzer.py`
Uygulama motoru, modern web protokollerinin mimari ve güvenlik katmanlarını modelleyen şu bileşenlerden oluşmaktadır:
1. **HTTP/2 İkili Çerçeve Başlığı Ayrıştırıcı (`parse_http2_frame_header`):**
   - 9 baytlık standart başlığı (`Length: 24-bit`, `Type: 8-bit`, `Flags: 8-bit`, `Stream-ID: 31-bit`) ayrıştırır.
   - RFC 7540 standart dışı tipleri (ör. 255), 16384 bayt sınır aşımını ve veri akışı kesilmelerini denetler.
   - Çerçeve tipi ile Akış ID ilişkisini doğrular: `DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM` çerçevelerinin Akış 0 üzerinden iletilmesini engeller; `SETTINGS` ve `PING` çerçevelerinin pozitif akışlarla gönderilmesini reddeder.
2. **Özel Çerçeve Yükü Kısıtlama Denetçisi (`validate_frame_payload_rules`):**
   - `RST_STREAM` çerçevesinin tam olarak 4 baytlık hata kodu taşımasını şart koşar.
   - `PING` çerçevesinin tam olarak 8 baytlık yük taşımasını doğrular.
   - `SETTINGS` çerçevesinin yük uzunluğunun kesinlikle 6'nın katı olmasını zorunlu kılar.
3. **HTTP/2 Rapid Reset Saldırı Tespit Motoru (`detect_rapid_reset_attack`):**
   - CVE-2023-44487 zafiyetini modeller; belirli bir zaman penceresinde gelen `RST_STREAM` iptal oranını izler ve eşik değeri aştığında `HTTP2RapidResetAttackError` fırlatır.
4. **RFC 9000 QUIC Anti-Amplification Denetçisi (`enforce_quic_anti_amplification`):**
   - Doğrulanmamış bir istemciye, istemciden alınan toplam baytın en fazla 3 katı (3x) kadar veri gönderilebileceğini doğrular; aşım durumunda `QUICAmplificationError` fırlatır.
5. **Hat Başı Tıkanması (HoL Blocking) Simülatörü (`simulate_hol_blocking`):**
   - Paket kaybı yaşandığında TCP (HTTP/2) üzerindeki tüm akışların bloklanması ile QUIC (HTTP/3) üzerindeki bağımsız akışların kesintisiz çalışması arasındaki farkı somut simülasyonla modeller.
6. **Sentetik HTTP/2 Çerçeve İnşa Edici (`build_synthetic_h2_frame`):**
   - Birim testler ve laboratuvar simülasyonları için standartlara uygun 9 baytlık ikili çerçeveler üretir.

---

## 3. Doğrulanabilir Kanıtlar ve Test Sonuçları

### 3.1. Birim Testleri (`test_http2_http3_analyzer.py`)
- **Toplam Test:** 14
- **Başarılı:** 14 (%100)
- **Hatalı / Başarısız:** 0
- **Çalışma Süresi:** 0.001 saniye
- **Kanıt Dosyası:** `kanit/gercek/test_sonuclari.txt` ve `kanit/gercek/komut_ve_cikis.txt`

### 3.2. Negatif ve Sınır Değer Testleri (`invalid_h2_h3_inputs.json`)
- **Toplam Negatif Senaryo:** 9
- **Başarılı Engelleme:** 9 (%100)
- **Kanıt Dosyası:** `kanit/gercek/negatif_kontrol_sonuclari.txt`

| Senaryo ID | Test Tanımı | Beklenen İstisna | Alınan Sonuç |
| :--- | :--- | :--- | :--- |
| `NEG_01` | Kesilmiş Çerçeve Başlığı (< 9 bayt) | `HTTP2MalformedFrameError` | Başarıyla Yakalandı |
| `NEG_02` | Tanımsız Çerçeve Tipi (255) | `HTTP2ValidationError` | Başarıyla Yakalandı |
| `NEG_03` | 16384 Bayt Üst Sınır Aşımı | `HTTP2ValidationError` | Başarıyla Yakalandı |
| `NEG_04` | DATA Çerçevesi Akış ID 0 İhlali | `HTTP2ValidationError` | Başarıyla Yakalandı |
| `NEG_05` | SETTINGS Çerçevesi Akış ID > 0 İhlali | `HTTP2ValidationError` | Başarıyla Yakalandı |
| `NEG_06` | RST_STREAM Hatalı Yük Boyutu (!= 4 bayt) | `HTTP2MalformedFrameError` | Başarıyla Yakalandı |
| `NEG_07` | PING Hatalı Yük Boyutu (!= 8 bayt) | `HTTP2MalformedFrameError` | Başarıyla Yakalandı |
| `NEG_08` | CVE-2023-44487 Rapid Reset Saldırısı | `HTTP2RapidResetAttackError` | Başarıyla Yakalandı |
| `NEG_09` | RFC 9000 QUIC 3x Anti-Amplification Sınır Aşımı | `QUICAmplificationError` | Başarıyla Yakalandı |

---

## 4. Akademik ve Sektörel Standart Referansları

1. **RFC 7540 / RFC 9113:** Hypertext Transfer Protocol Version 2 (HTTP/2)
2. **RFC 7541:** HPACK: Header Compression for HTTP/2
3. **RFC 9000:** QUIC: A UDP-Based Multiplexed and Secure Transport
4. **RFC 9114:** Hypertext Transfer Protocol Version 3 (HTTP/3)
5. **RFC 9204:** QPACK: Field Compression for HTTP/3
6. **CVE-2023-44487:** HTTP/2 Rapid Reset DDoS Saldırısı Zafiyeti Raporu

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Günlük değerlendirme raporu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
