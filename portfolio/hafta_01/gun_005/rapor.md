<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 005 DEĞERLENDİRME VE DOĞRULAMA RAPORU

## 5 Satırlık Yönetici Özeti
1. **Konu ve Kapsam:** Varlık Envanteri, Sahiplik (Ownership) ve 4 Seviyeli Veri Sınıflandırması hiyerarşisi NIST CSF 2.0 (ID.AM, PR.DS) ve ISO 27001 standartlarıyla incelenmiştir.
2. **Pedagojik Derinlik:** "Donanım Fiyatı != Varlık Değeri" ilkesi (Crown Jewels Paradoksu) somutlaştırılmış; sahipsiz varlıkların (Orphan Assets / Shadow IT) yarattığı riskler usta-çırak perspektifinde işlenmiştir.
3. **Uygulama ve Kod:** `asset_classifier.py` geliştirilmiş, tüm kod satırları zengin Türkçe açıklamalarla donatılmış, görsel ASCII denetim tablosu ve finansal risk çarpanı hesaplanmıştır.
4. **Test ve Kanıt:** 10 birim test (pozitif kontrol, sahipsiz varlık, geçersiz sınıf, şifresiz gizli veri, DMZ uyarısı, mükerrer ID) %100 başarıyla (PASS) tamamlanmış ve kanıt dosyaları üretilmiştir.
5. **Nihai Karar:** G005 günü için belirlenen tüm teknik, etik ve pedagojik hedefler eksiksiz sağlanmış olup değerlendirme notu 100/100 (YETERLİ / PASS) olarak doğrulanmıştır.

---

## Değerlendirme Puan Tablosu

| Kategori | Azami Puan | Alınan Puan | Durum | Gerekçe |
| :--- | :---: | :---: | :---: | :--- |
| **Teori ve Kavramsal Derinlik** | 20 | 20 | Mükemmel | Varlık türleri (Cihaz, Uygulama, Kimlik, Veri), 4 seviyeli veri sınıflandırması ve Crown Jewels mantığı eksiksiz açıklandı. |
| **Uygulama, Kod ve Zengin Açıklamalar** | 40 | 40 | Mükemmel | Kullanıcının isteği doğrultusunda tüm kod satırları eğitsel açıklamalarla zenginleştirildi; sahipsizlik ve şifreleme kuralları kodlandı. |
| **Test Kapsamı ve Kanıt Bütünlüğü** | 25 | 25 | Mükemmel | 10/10 test geçti; sahipsiz varlık, geçersiz tür, DMZ riski ve şifresiz veri negatif kontrolleri doğrulandı; kanıtlar üretildi. |
| **Dokümantasyon ve Standart Uyumu** | 15 | 15 | Mükemmel | Özel lisans hükümleri, 4 bölümlü soru-cevap formatı, bağımsız çalışma ilkesi ve manifest.json uyumu sağlandı. |
| **TOPLAM** | **100** | **100** | **YETERLİ** | **Kabul: PASS** |

---

## Pozitif ve Negatif Kontroller Tablosu

| Test Adı | Kontrol Türü | Girdi / Koşul | Beklenen Sonuç | Gerçekleşen Sonuç | Karar |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `test_gecerli_envanter_pozitif_kontrol` | Pozitif | 5 standart varlık | Toplam: $69.5k / $58.05M, 0 uyarı | Durum: GECERLI, 0 açık bulgu | **PASS** |
| `test_sahipsiz_varlik_negatif_kontrol` | Negatif | Varlık `sahip` alanı boş | `AssetValidationError` fırlatılmalı | Sahipsiz varlık hatası yakalandı | **PASS** |
| `test_gecersiz_veri_sinifi_negatif_kontrol` | Negatif | Bilinmeyen `veri_sinifi` | `AssetValidationError` fırlatılmalı | Geçersiz sınıf hatası yakalandı | **PASS** |
| `test_gecersiz_varlik_turu_negatif_kontrol` | Negatif | Tanımsız varlık türü | `AssetValidationError` fırlatılmalı | Geçersiz tür hatası yakalandı | **PASS** |
| `test_mukerrer_id_negatif_kontrol` | Negatif | İki varlığa aynı ID | `AssetValidationError` fırlatılmalı | Mükerrer kimlik hatası yakalandı | **PASS** |
| `test_bos_envanter_negatif_kontrol` | Negatif | `varliklar: []` | `AssetValidationError` fırlatılmalı | Boş envanter hatası yakalandı | **PASS** |
| `test_guvenlik_uyumsuzlugu_sifresiz_veri` | Negatif / Kural | Şifresiz `COK_GIZLI_SIR` | `KRİTİK AÇIK` uyarısı üretilmeli | Şifresiz hassas veri tespit edildi | **PASS** |
| `test_dmz_kritik_varlik_uyarisi` | Negatif / Kural | DMZ'de kritik iç varlık | `YÜKSEK RİSK` uyarısı üretilmeli | DMZ segmentasyon riski tespit edildi | **PASS** |
| `test_esnek_mod_hata_toplama` | Negatif / Esnek | Bozuk kök yapısı | `(False, [hata_listesi])` dönmeli | Esnek modda hatalar toplandı | **PASS** |
| `test_tablo_ve_crown_jewel_orani` | Görsel / Matematik | Matris girdisi | $2,500 sunucuya 6000.0x risk oranı | Doğru ASCII tablo ve oran basıldı | **PASS** |

---

## Üretilen Dosya ve Kanıt Envanteri

1. `portfolio/hafta_01/gun_005/ders.md`: Usta-Çırak pedagojisinde 7 bölümlü derin masterclass dersi.
2. `portfolio/hafta_01/gun_005/soru_cevap.md`: G005-SC1, SC2, SC3 için 4 bölümlü standart yanıtlar.
3. `portfolio/hafta_01/gun_005/ornek_veri/varlik_envanteri.json`: 5 farklı varlık türünü içeren zengin veri.
4. `portfolio/hafta_01/gun_005/uygulama/asset_classifier.py`: Baştan sona açıklamalı varlık değerlendirici CLI aracı.
5. `portfolio/hafta_01/gun_005/tests/test_asset_classifier.py`: 10 birim test içeren kapsamlı test süiti.
6. `portfolio/hafta_01/gun_005/kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme ve stdout/stderr kaydı.
7. `portfolio/hafta_01/gun_005/kanit/gercek/test_sonuclari.txt`: 10/10 unittest başarı kaydı.
8. `portfolio/hafta_01/gun_005/kanit/temsili/veri_siniflandirma_piramidi.txt`: Temsilî ASCII sınıflandırma şeması.
9. `portfolio/hafta_01/gun_005/rapor.md`: Bu değerlendirme raporu.
10. `portfolio/hafta_01/gun_005/README.md`: Hızlı başlangıç ve kullanım kılavuzu.
11. `portfolio/hafta_01/gun_005/sonuc.json`: 14 standart alanlı makine-okunabilir durum özeti.
12. `portfolio/hafta_01/gun_005/manifest.json`: Tüm dosyaların SHA-256 bütünlük özetleri.
