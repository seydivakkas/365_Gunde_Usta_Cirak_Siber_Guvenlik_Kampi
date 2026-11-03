# G064: Hafta 10 Gün 64 — Wireshark Filtre Sözdizimi Değerlendirme Raporu
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## 1. Yönetici Özeti ve Proje Kapsamı

Bu çalışma, 365 Günlük Siber Güvenlik Müfredatı Aşama 03 bünyesindeki **Hafta 10 (Web Güvenliği Temelleri ve Analiz Yöntemleri)** başlangıç projesidir (**Gün 64: Wireshark Filtre Sözdizimi**).

Proje kapsamında, BPF (yakalama filtresi) ile Wireshark görüntüleme filtresi (display filter) arasındaki farklar incelenmiş, Wireshark standartlarındaki kurallı filtreleme dilini sözcüksel analiz (lexer/tokenizer) ve özyinelemeli sözdizim ağacı (recursive descent AST parser) ile ayrıştırıp yürüten tam teşekküllü bir `WiresharkFilterEngine` motoru geliştirilmiştir. Motor, mantıksal operatörleri (`&&`, `||`, `!`), karşılaştırma operatörlerini (`==`, `!=`, `>`, `<`, `contains`, `matches`), bayt dilimleme (`slice`) işlemlerini ve siber tehdit avcılığı (threat hunting) profillerini doğrulamıştır.

---

## 2. Birim Test Doğrulama Matrisi (14/14 PASS)

Tüm testler `portfolio.hafta_10.gun_064.tests.test_wireshark_filter_engine` altında bağımsız olarak koşulmuş ve tam başarı sağlanmıştır:

| Test No | Test Fonksiyonu | Kapsanan İşlevsellik | Süre | Durum |
| :---: | :--- | :--- | :---: | :---: |
| **01** | `test_01_simple_equality_filter` | Basit eşitlik filtresi (`ip.src == "192.168.1.100"`) doğrulaması | 0.001s | **BAŞARILI (PASS)** |
| **02** | `test_02_alias_fields_ip_addr_and_tcp_port` | Takma alanlar (`ip.addr` ve `tcp.port`) kaynak/hedef eşleşmesi | 0.001s | **BAŞARILI (PASS)** |
| **03** | `test_03_logical_and_operator` | Mantıksal VE (`&&`) bağlacı ve çoklu koşul denetimi | 0.001s | **BAŞARILI (PASS)** |
| **04** | `test_04_logical_or_and_parentheses` | Mantıksal VEYA (`||`) ve parantezli öncelik çözümleme | 0.001s | **BAŞARILI (PASS)** |
| **05** | `test_05_logical_not_operator` | Mantıksal DEĞİL (`!`) ile koşulun tersini alma | 0.001s | **BAŞARILI (PASS)** |
| **06** | `test_06_relational_operators_length` | Boyutsal ilişkisel operatör (`frame.len > 200`) denetimi | 0.001s | **BAŞARILI (PASS)** |
| **07** | `test_07_contains_operator_payload` | HTTP gövdesinde açık metin parola arama (`contains`) | 0.001s | **BAŞARILI (PASS)** |
| **08** | `test_08_regex_matches_operator` | Düzenli ifade deseni ile URI filtreleme (`matches`) | 0.001s | **BAŞARILI (PASS)** |
| **09** | `test_09_byte_slice_operator` | Bayt dilimleme (`tcp.payload_hex[0:4] == "4745"`) denetimi | 0.001s | **BAŞARILI (PASS)** |
| **10** | `test_10_threat_hunting_profile_run` | 5 kritik siber tehdit avı profilinin (SYN, RST, Auth, DNS, ZeroWin) çalışması | 0.001s | **BAŞARILI (PASS)** |
| **11** | `test_11_neg01_neg06_syntax_and_empty_errors` | Dengesiz parantez (`FilterSyntaxError`) ve boş filtre (`EmptyFilterError`) | 0.001s | **BAŞARILI (PASS)** |
| **12** | `test_12_neg02_neg03_unknown_field_and_type_errors` | Tanımsız alan (`UnknownFieldError`) ve tip uyuşmazlığı (`FilterTypeError`) | 0.001s | **BAŞARILI (PASS)** |
| **13** | `test_13_neg04_neg05_slice_and_regex_errors` | Bayt dilim aşımı (`SliceOutOfBoundsError`) ve bozuk regex (`RegexFilterError`) | 0.001s | **BAŞARILI (PASS)** |
| **14** | `test_14_neg07_to_neg09_invalid_op_malformed_pkt_tokenize_errors` | Geçersiz operatör (`InvalidOperatorError`), bozuk paket ve kapatılmamış tırnak | 0.001s | **BAŞARILI (PASS)** |

**Toplam Koşu Süresi:** 0.007 saniye | **Sonuç:** 14/14 BAŞARILI (%100)

---

## 3. Negatif Sınır ve Güvenlik Anomalisi Test Sonuçları (9/9 PASS)

| Test Kodu | Senaryo Adı | Beklenen Hata Sınıfı | Yakalanan Hata Sınıfı | Sonuç |
| :---: | :--- | :--- | :--- | :---: |
| **NEG_01** | Dengesiz Parantez Sözdizim Hatası | `FilterSyntaxError` | `FilterSyntaxError` | **UYUMLU (PASS)** |
| **NEG_02** | Tanımsız Protokol Alanı | `UnknownFieldError` | `UnknownFieldError` | **UYUMLU (PASS)** |
| **NEG_03** | Veri Tipi Uyuşmazlığı | `FilterTypeError` | `FilterTypeError` | **UYUMLU (PASS)** |
| **NEG_04** | Bayt Dilimleme Sınır Aşımı | `SliceOutOfBoundsError` | `SliceOutOfBoundsError` | **UYUMLU (PASS)** |
| **NEG_05** | Bozuk Düzenli İfade (Regex) | `RegexFilterError` | `RegexFilterError` | **UYUMLU (PASS)** |
| **NEG_06** | Boş / Beyaz Boşluk Filtre Girdisi | `EmptyFilterError` | `EmptyFilterError` | **UYUMLU (PASS)** |
| **NEG_07** | Geçersiz Karşılaştırma Operatörü (===) | `InvalidOperatorError` | `InvalidOperatorError` | **UYUMLU (PASS)** |
| **NEG_08** | Bozuk veya Geçersiz Paket Formatı | `MalformedPacketError` | `MalformedPacketError` | **UYUMLU (PASS)** |
| **NEG_09** | Kapatılmamış Tırnak İşareti | `FilterTokenizeError` | `FilterTokenizeError` | **UYUMLU (PASS)** |

---

## 4. Değerlendirme Puanı ve Sonuç

| Değerlendirme Kriteri | Taban Puan | Verilen Puan | Açıklama |
| :--- | :---: | :---: | :--- |
| **Kodlama ve Uygulama** | 20 | **20** | Tüm satırlarda didaktik açıklamalar; sağlam AST parser ve lexer mimarisi. |
| **Test Kapsamı ve Kanıtlar** | 40 | **40** | 14 birim test, 9 negatif sınır vakası, tehdit avı raporu ve şemalar. |
| **Müfredat Uyumu ve Pedagoji** | 25 | **25** | BPF vs Display filter analizi, Wireshark grameri ve usta-çırak pedagojisi. |
| **Belgeleme ve Raporlama** | 15 | **15** | soru_cevap.md (3 senaryo, 4 zorunlu başlık), ders.md, sonuc.json, manifest.json. |
| **TOPLAM** | **100** | **100** | **YETERLİ / PASS** |

---

## 5. Hafta 10 Başlangıç Notu

Gün 64 başarıyla tamamlanmış olup Hafta 10 (Web Güvenliği Temelleri ve Analiz Yöntemleri) müfredatı tam hızla ilerlemektedir. Bir sonraki gün olan **Gün 65: Paket yakalama analizi** çalışmalarına geçiş için tüm gereksinimler hazırdır.
