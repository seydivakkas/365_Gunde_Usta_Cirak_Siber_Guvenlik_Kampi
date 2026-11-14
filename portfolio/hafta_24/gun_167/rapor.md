# Gün 167: Path Traversal ve Dosya Erişimi — Günlük Değerlendirme ve İlerleme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Genel Bilgiler

- **Tarih:** 2026-11-14
- **Eğitim Programı:** 365 Günde Usta-Çırak Siber Güvenlik Kampı
- **Aşama:** Aşama 07: Web Güvenliği
- **Hafta:** Hafta 24: Enjeksiyon ve İstek Güvenliği
- **Konu Başlığı:** Path Traversal ve Dosya Erişimi (Gün 167 - Excel Satır No: 171)
- **Durum:** Tamamlandı (100/100 PASS)

---

## 2. 100/100 Başarı ve Değerlendirme Puan Kartı

| Kriter Kategorisi | Hedef / Standart | Gerçekleşen | Ağırlık | Alınan Puan | Durum |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Birim Testler (tests/)** | 15/15 Kapsamlı Test, 0 Hata | 15/15 PASS (0.028s) | %20 | 20 | MÜKEMMEL |
| **Uygulama & Mimari (uygulama/)** | Path Traversal Savunma Motoru, CLI, Didaktik Yorumlar | Tam teşekküllü motor & CLI, %100 yorum | %40 | 40 | MÜKEMMEL |
| **Kanıt & Negatif Kontroller (kanit/)** | 9 Negatif Kontrol, Gerçek & Temsili Kanıtlar | 9/9 Savunuldu, Tüm kanıtlar üretildi | %25 | 25 | MÜKEMMEL |
| **Dokümantasyon (ders, soru_cevap)** | Usta-Çırak anlatımı, 3 mülakat sorusu | Eksiksiz ders, soru-cevap ve rapor | %15 | 15 | MÜKEMMEL |
| **GENEL TOPLAM** | **100 Puan Standardı** | **100/100** | **%100** | **100** | **TAM BAŞARI (PASS)** |

---

## 3. Yapılan Çalışmaların Özeti

1. **Uygulama Geliştirme (`uygulama/path_traversal_engine.py` & `path_traversal_cli.py`):**
   - Dizin Atlama (Path Traversal / CWE-22) saldırılarını analiz eden çok katmanlı savunma motoru kodlandı.
   - Çoklu geçişli URL kod çözme normalizasyonu (Multi-Pass URL Decoding) ile gizlenmiş `%252e%252e%252f` türevlerini çözen modül geliştirildi.
   - `os.path.join` fonksiyonunun mutlak yol sıçrama (`/etc/passwd` veya `C:\...`) açığını ve sembolik bağ risklerini engelleyen kanonik hapishane denetleyicisi (`os.path.realpath` ve `os.path.commonpath`) yazıldı.
   - Tek geçişli filtreleri atlatmak için kullanılan iç içe geçmiş payload'ları (`....//`) ve Null Byte (`%00`) enjeksiyonunu tespit eden güvenlik katmanları entegre edildi.
   - Dosya adı karakter seti beyaz listesi (`^[a-zA-Z0-9_\-\.]+$`) ve dosya uzantısı kısıtlaması uygulandı.
   - Kullanıcı girdisini doğrudan dosya yoluna bağlamaktan kurtaran Dolaylı Nesne Referansı (UUID/Token bazlı dosya soyutlama) mimarisi simüle edildi.
   - Zafiyetli ve güvenli dosya okuma fonksiyonlarını karşılaştıran sanal dosya sistemi (`MockFileSystemStorage`) kuruldu.
   - Kod tabanındaki her bir çalıştırılabilir satıra didaktik Türkçe yorumlar eklendi.

2. **Birim Test Paketi (`tests/test_path_traversal.py`):**
   - Basit traversal engeli, URL kodlu traversal, çift kodlu (Double Encoded) traversal, iç içe geçmiş (nested) traversal, mutlak yol (Absolute Path) sıçraması, Null Byte engeli, geçersiz karakter engeli, izin verilmeyen uzantı engeli, meşru dosya okuma, zafiyetli fonksiyon sızıntı ispatı, kanonik hapishane ihlali, UUID indirme testi, CLI denetim raporu testi ve CLI dosya okuma senaryolarını içeren 15 birim test 0.028 saniyede %100 başarıyla tamamlandı.

3. **Örnek Veri ve Kurumsal Politikalar (`ornek_veri/`):**
   - `enterprise_storage_policy.json`: Kurumsal dosya saklama, izin verilen uzantılar ve kanonik kısıtlama standardı JSON şemasıyla tanımlandı.
   - `invalid_traversal_payloads.json`: 9 negatif saldırı kontrol senaryosu oluşturuldu.

4. **Kanıt Üretimi ve Doğrulama (`kanit/`):**
   - `kanit_uretici.py` ile gerçek test sonuçları, negatif kontrol raporu (9/9 savunuldu), denetim JSON çıktısı, karşılaştırmalı dosya okuma dökümleri ve CLI konsol günlükleri üretildi.
   - `kanit/temsili/path_traversal_savunma_mimarisi.txt` dosyası zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII formatında kaydedildi.

---

## 4. Negatif Kontrol Saldırı Senaryoları Tablosu

| Senaryo ID | Saldırı Türü | Girdi / Payload | Tespit Edilen Tehdit | Karar / Kod | Savunma Durumu |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **SCN-TRAV-01** | BASIC_DOT_DOT_SLASH | `../../../../etc/passwd` | TRAVERSAL_PATTERN_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-02** | URL_ENCODED_TRAVERSAL | `%2e%2e%2f%2e%2e%2fetc/passwd` | TRAVERSAL_PATTERN_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-03** | DOUBLE_ENCODED_TRAVERSAL | `%252e%252e%252f%252e%252e%252fetc/passwd` | TRAVERSAL_PATTERN_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-04** | NESTED_TRAVERSAL | `....//....//etc/passwd` | NESTED_TRAVERSAL_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-05** | ABSOLUTE_PATH_POSIX | `/etc/shadow` | ABSOLUTE_PATH_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-06** | ABSOLUTE_PATH_WINDOWS | `C:\Windows\System32\drivers\etc\hosts` | ABSOLUTE_PATH_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-07** | NULL_BYTE_INJECTION | `report_2026.pdf%00.exe` | NULL_BYTE_DETECTED | 400 Bad Request | SAVUNULDU |
| **SCN-TRAV-08** | DISALLOWED_EXTENSION | `reverse_shell.php` | EXTENSION_NOT_ALLOWED | 403 Forbidden | SAVUNULDU |
| **SCN-TRAV-09** | SPECIAL_CHARACTERS | `report|cat /etc/passwd;.pdf` | INVALID_CHARACTERS_IN_FILENAME | 400 Bad Request | SAVUNULDU |

---

## 5. Çıkarılan Temel Mühendislik İlkeleri

1. **`os.path.join` Fonksiyonuna Asla Güvenme:** Standart kütüphaneler dosya sistemi kurallarını işletir, güvenlik kısıtlaması yapmaz. Mutlak bir yol argümanı geldiğinde önceki dizinlerin yok sayıldığını unutma.
2. **Kanonikleştirme (`realpath`) Zorunludur:** Sembolik bağlar (symlinks) ve göreceli yollar ancak `os.path.realpath` ile çözümlendikten sonra `os.path.commonpath` kullanılarak hapishane (Jail) sınırında tutulabilir.
3. **Karakter Silme, İsteği Reddet:** Tek geçişli `replace("../", "")` mantığı `....//` gibi iç içe payload'lar karşısında çöker. Şüpheli bir dizgi tespit edildiğinde istek temizlenmeye çalışılmamalı, doğrudan reddedilmelidir.
4. **UUID Mapping Dosya Sistemini Soyutlar:** Kullanıcı girdisini fiziksel dosya isimlerine bağlamaktan vazgeçip UUID tabanlı nesne referansları kullanmak dizin atlama saldırı yüzeyini kökten yok eder.
