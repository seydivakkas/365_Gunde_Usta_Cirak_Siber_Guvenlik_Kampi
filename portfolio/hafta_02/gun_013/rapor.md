# GÜN 013: Değerlendirme ve Denetim Raporu
**Konu:** Güvenli Araştırma ve Kaynak Doğrulama (CRAAP Çerçevesi, Çapraz Teyit / Triangulation ve Kriptografik İmza Kalkanı)  
**Tarih:** 2026-10-27  
**Değerlendirme Puanı:** 100 / 100  
**Durum:** YETERLİ (PASS)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📊 1. Puanlama Tablosu

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum | Açıklama |
| :--- | :---: | :---: | :---: | :--- |
| **Teorik Derinlik ve Kavramsal Model** | 20 | **20** | Eksiksiz | "Tıp fakültesi kütüphanesi vs anonim forum bitkisel kürü" analojisiyle kaynak güvenilirlik piramidi, CRAAP testi, çapraz teyit (triangulation), Truva Atı içeren sahte PoC'lar ve Lazarus APT vakası derinlemesine açıklandı. |
| **Uygulama ve Kod Kalitesi** | 40 | **40** | Eksiksiz | Her satırı zengin pedagojik açıklamalarla donatılmış `security_source_validator.py` CLI motoru geliştirildi; CRAAP puanlama, zehirli kod tespiti (`curl \| sh`), yıkıcı yetki kaldırma tespiti (`chmod 777`) ve çapraz teyit mekanizması eksiksiz kodlandı. |
| **Birim Testler ve Negatif Kontroller** | 25 | **25** | Eksiksiz | 14 birim test ile pozitif resmî NVD ve CIS Benchmark akışları, çapraz karşılaştırma onayları, Truva Atı PoC tespiti (FLAG-04), chmod 777 yıkıcı tavsiyesi (FLAG-05), 5 yıl yaş aşımı (FLAG-01), imza yokluğu ve sınır ihlalleri 0.003s'de %100 doğrulandı. |
| **Dokümantasyon, Soru-Cevap ve Kanıtlar** | 15 | **15** | Eksiksiz | 7 bölümlü masterclass ders metni, 4 katı alt başlıklı 3 soru-cevap, gerçek CLI yürütme çıktısı ve temsilî ASCII mimari şeması eksiksiz üretildi. |
| **TOPLAM** | **100** | **100** | **YETERLİ (PASS)** | Müfredat ve kalite standartlarının tüm şartları tam olarak karşılandı. |

---

## 🔍 2. Pozitif ve Negatif Kontrol Doğrulama Matrisi

| Kontrol Türü | Test Fonksiyonu | Beklenen Davranış | Gözlenen Sonuç | Durum |
| :--- | :--- | :--- | :--- | :---: |
| **Pozitif Kontrol (NVD Resmî)** | `test_01_resmi_birincil_kaynak_yuksek_puan` | Resmî NVD ve MSRC bülteni ≥90 puan almalı ve GUVENILIR_ONAYLI olmalıdır. | Skor: 100, 0 bayrak, Durum: GUVENILIR_ONAYLI | **GEÇTİ** |
| **Pozitif Kontrol (CIS Benchmark)**| `test_02_cis_benchmark_kurumsal_standart_onay` | CIS Benchmark belgesi ≥90 puan almalı ve tam otorite onayı almalıdır. | Skor: 100, Durum: GUVENILIR_ONAYLI | **GEÇTİ** |
| **Pozitif Kontrol (VAKA-01 Teyit)** | `test_03_capraz_kaynak_karsilastirma_vaka_01_onay` | VAKA-01 için çapraz teyitte NVD onaylanmalı, sahte GitHub PoC reddedilmelidir. | NVD onaylandı, PoC reddedildi. | **GEÇTİ** |
| **Pozitif Kontrol (VAKA-02 Teyit)** | `test_04_capraz_kaynak_karsilastirma_vaka_02_onay` | VAKA-02 için CIS Benchmark onaylanmalı, forum yazısı reddedilmelidir. | CIS onaylandı, forum reddedildi. | **GEÇTİ** |
| **Negatif Kontrol (Zehirli PoC)** | `test_05_zehirli_poc_truva_ati_tespiti` | Sahte GitHub PoC'unda `curl \| sh` tespitiyle FLAG-04 FELAKET bayrağı açılmalıdır. | FLAG-04 yakalandı, GUVENSIZ_REDDEDILDI. | **GEÇTİ** |
| **Negatif Kontrol (chmod 777)** | `test_06_yikici_guvenlik_tavsiyesi_chmod777_tespiti`| Eski forumdaki `chmod 777` tavsiyesi FLAG-05 ile FELAKET olarak yakalanmalıdır. | FLAG-05 yakalandı, skor: 15. | **GEÇTİ** |
| **Negatif Kontrol (5 Yıl Yaş)** | `test_07_eski_kaynak_tarih_asimi_tespiti` | 5 yıldan eski (2011) içerikte FLAG-01-ESKI-KAYNAK bayrağı açılmalıdır. | FLAG-01-ESKI-KAYNAK tespit edildi. | **GEÇTİ** |
| **Negatif Kontrol (İmza Yokluğu)**| `test_08_kriptografik_butunluk_eksikligi_tespiti` | GPG veya SHA-256 olmayan kaynakta FLAG-03-KRIPTO-BUTUNLUK-YOK tetiklenmelidir. | FLAG-03 yakalandı (-25 puan). | **GEÇTİ** |
| **Negatif Kontrol (Anonim Yazar)** | `test_09_otoritesiz_anonim_kaynak_tespiti` | Anonim profilli kaynakta FLAG-02-OTORITESIZ-KAYNAK bayrağı açılmalıdır. | FLAG-02 yakalandı (-25 puan). | **GEÇTİ** |
| **Hata Yönetimi (Tek Kaynak)** | `test_10_tek_kaynak_ile_capraz_teyit_hatasi` | Tek kaynaklı vakada çapraz teyit IncompatibleTriangulationError fırlatmalıdır. | IncompatibleTriangulationError doğrulandı. | **GEÇTİ** |
| **Hata Yönetimi (Tanımsız Vaka)** | `test_11_tanimsiz_vaka_hata_yonetimi` | Tanımsız vaka kimliği sorgulandığında SourceValidatorError fırlatılmalıdır. | SourceValidatorError yakalandı. | **GEÇTİ** |
| **Hata Yönetimi (Tarihsiz Kaynak)**| `test_12_tarihi_belirsiz_kaynak_puan_kirilmasi`| Yayın tarihi olmayan kaynakta FLAG-01-TARIH-YOK cezası kesilmelidir. | FLAG-01-TARIH-YOK doğrulandı (-20 puan). | **GEÇTİ** |
| **İşlevsellik (Toplu Karşılaştırma)**| `test_13_tum_vakalar_icin_karsilastirma_dongusu` | Veri tabanındaki tüm vakalar döngüde başarıyla analiz edilmelidir. | Tüm vakalar döngüde onaylandı. | **GEÇTİ** |
| **Hata Yönetimi (Olmayan Dosya)**| `test_14_olmayan_veri_tabani_dosya_hatasi` | Olmayan veri tabanı yolunda FileNotFoundError fırlatılmalıdır. | FileNotFoundError teyit edildi. | **GEÇTİ** |

---

## 🛠️ 3. Tamamlanan Çıktılar ve Kanıt Dosyaları

1. `ornek_veri/guvenlik_arastirma_kaynaklari.json`: Resmî ve zehirli kaynakları içeren sentetik araştırma veri tabanı.
2. `ornek_veri/craap_dogrulama_kriterleri.json`: CRAAP puanlama ağırlıkları, seviye eşikleri ve otomatik ret koşulları tablosu.
3. `uygulama/security_source_validator.py`: Her satırı pedagojik açıklamalarla yazılmış kaynak doğrulama ve çapraz teyit CLI aracı.
4. `tests/test_security_source_validator.py`: 14 birim test senaryosunu içeren ve 0.003 saniyede sonuçlanan tam test paketi.
5. `kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme çıktısı ve platform ortam kaydı.
6. `kanit/gercek/test_sonuclari.txt`: 14/14 unittest başarı çıktısı.
7. `kanit/temsili/guvenli_arastirma_ve_kaynak_hiyerarsisi.txt`: İstihbarat piramidi, CRAAP akışı ve zehirli PoC tuzağını gösteren pedagojik ASCII şeması.
8. `ders.md`: 7 aşamalı "Usta-Çırak" masterclass ders metni.
9. `soru_cevap.md`: Soru bankasındaki 3 soruya (`G013-SC1`, `G013-SC2`, `G013-SC3`) ait 4 katı alt başlıklı kurumsal yanıtlar.

---

## 🏁 4. Sonuç ve Bir Sonraki Güne Geçiş

GÜN 013 çalışması; siber güvenlik araştırmalarında kaynak doğruluğu hiyerarşisini, CRAAP modelini, zehirli PoC istismar tuzaklarını ve iki bağımsız kaynaktan çapraz teyit almanın zorunluluğunu başarıyla tamamlamıştır.

Tüm testler ve denetimler **%100 PASS** ile sonuçlanmış olup, Aşama 01 Hafta 02 kapsamındaki **GÜN 014 (Mini Proje 2)** konusuna geçiş için tüm ön koşullar eksiksiz sağlanmıştır.
