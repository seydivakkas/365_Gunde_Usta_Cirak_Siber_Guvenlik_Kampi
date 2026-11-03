<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 007 DEĞERLENDİRME VE DOĞRULAMA RAPORU

## 5 Satırlık Yönetici Özeti
1. **Konu ve Kapsam:** 1. Haftanın taçlandırma adımı (Milestone 1) olarak Güvenli Laboratuvar Kurulum Sözleşmesi ve İzolasyon Topolojisi kodlanmıştır.
2. **Pedagojik Derinlik:** Dijital BSL-4 (Biyogüvenlik Seviyesi 4) benzetmesiyle sanal makinelerden dış dünyaya sızıntı ve VM Escape (hipervizör kaçış) mekanizmaları usta-çırak perspektifinde açıklanmıştır.
3. **Uygulama ve Kod:** `lab_contract_validator.py` geliştirilmiş, tüm kod satırları zengin eğitsel yorumlarla donatılmış, ASCII topoloji şeması ve izolasyon denetim algoritmaları kodlanmıştır.
4. **Test ve Kanıt:** 11 birim test (pozitif kontrol, genel internet kapsam ihlali, pano/klasör açık kontrolü, köprü adaptör sızıntısı, IP çakışması) %100 başarıyla (PASS) tamamlanmış ve kanıtlar üretilmiştir.
5. **Nihai Karar:** G007 ve Aşama 01 / Hafta 01 için belirlenen tüm teknik, etik ve kurumsal hedefler eksiksiz sağlanmış olup değerlendirme notu 100/100 (YETERLİ / PASS) olarak tescil edilmiştir.

---

## Değerlendirme Puan Tablosu

| Kategori | Azami Puan | Alınan Puan | Durum | Gerekçe |
| :--- | :---: | :---: | :---: | :--- |
| **Teori ve Kavramsal Derinlik** | 20 | 20 | Mükemmel | Hafta 1 sentezi (CIA, Risk, RoE, NIST CSF, Varlık, Tehdit Modelleme) ve laboratuvar izolasyon ilkeleri eksiksiz açıklandı. |
| **Uygulama, Kod ve Zengin Açıklamalar** | 40 | 40 | Mükemmel | Tüm satırları eğitsel açıklamalarla donatılmış sözleşme doğrulama CLI aracı yazıldı; IP ve hipervizör kontrolleri kodlandı. |
| **Test Kapsamı ve Kanıt Bütünlüğü** | 25 | 25 | Mükemmel | 11/11 test geçti; internet ihlali, köprü adaptör ve VM escape negatif kontrolleri doğrulandı; gerçek kanıtlar üretildi. |
| **Dokümantasyon ve Standart Uyumu** | 15 | 15 | Mükemmel | Özel lisans hükümleri, 4 bölümlü soru-cevap formatı, bağımsız çalışma ilkesi ve manifest.json sağlandı. |
| **TOPLAM** | **100** | **100** | **YETERLİ** | **Kabul: PASS** |

---

## Pozitif ve Negatif Kontroller Tablosu

| Test Adı | Kontrol Türü | Girdi / Koşul | Beklenen Sonuç | Gerçekleşen Sonuç | Karar |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `test_gecerli_sozlesme_pozitif_kontrol` | Pozitif | Onaylı sözleşme, 2 düğüm, tam izolasyon | Durum: GECERLI, 0 kusur | Tam doğrulama, izolasyon başarılı | **PASS** |
| `test_genel_internet_kapsam_ihlali` | Negatif / Kapsam | İzinli listede `0.0.0.0/0` | `ContractViolationError` fırlatılmalı | Yasal ihlal yakalandı | **PASS** |
| `test_yasakli_ip_cakismasi` | Negatif / Kapsam | İzinli listede `8.8.8.8` | `ContractViolationError` fırlatılmalı | Kapsam çelişkisi yakalandı | **PASS** |
| `test_onaylanmamis_sozlesme` | Negatif / İdari | Durum: `TASLAK` | `ContractViolationError` fırlatılmalı | Onaylanmamış sözleşme durduruldu | **PASS** |
| `test_eksik_imza_negatif_kontrol` | Negatif / İdari | CISO imzası eksik | `ContractViolationError` fırlatılmalı | İmza eksikliği yakalandı | **PASS** |
| `test_pano_paylasimi_acik` | Negatif / İzolasyon | Pano paylaşımı `ETKIN` | `KRİTİK İZOLASYON KUSURU` üretilmeli | VM Escape riski raporlandı | **PASS** |
| `test_ortak_klasor_acik` | Negatif / İzolasyon | Ortak klasörler `ETKIN` | `KRİTİK İZOLASYON KUSURU` üretilmeli | Disk sıçrama riski raporlandı | **PASS** |
| `test_guvensiz_kopru_adaptor` | Negatif / Ağ | Düğüm adaptörü `Bridged` | `GÜVENLİKSİZ AĞ ADAPTÖRÜ` üretilmeli | Ağ sızıntı riski tespit edildi | **PASS** |
| `test_mukerrer_ip_cakismasi` | Negatif / Ağ | İki düğüme aynı IP | `ContractViolationError` fırlatılmalı | IP çakışması engellendi | **PASS** |
| `test_kapsam_disi_dugum_ip` | Negatif / Ağ | Alt ağ dışı düğüm IP'si | `KAPSAM DIŞI IP ADRESİ` üretilmeli | Segmentasyon hatası yakalandı | **PASS** |
| `test_esnek_mod_hata_toplama` | Negatif / Esnek | Bozuk kök JSON sözleşmesi | `(False, [hata_listesi])` dönmeli | Esnek modda hatalar toplandı | **PASS** |

---

## Üretilen Dosya ve Kanıt Envanteri

1. `portfolio/hafta_01/gun_007/ders.md`: 1. Hafta Mini Projesi masterclass ders metni.
2. `portfolio/hafta_01/gun_007/soru_cevap.md`: G007-SC1, SC2, SC3 için 4 bölümlü standart yanıtlar.
3. `portfolio/hafta_01/gun_007/ornek_veri/laboratuvar_sozlesmesi.json`: Kurumsal laboratuvar sözleşmesi ve 5 düğümlü topoloji verisi.
4. `portfolio/hafta_01/gun_007/uygulama/lab_contract_validator.py`: Baştan sona açıklamalı sözleşme doğrulayıcı CLI aracı.
5. `portfolio/hafta_01/gun_007/tests/test_lab_contract_validator.py`: 11 birim test içeren kapsamlı test süiti.
6. `portfolio/hafta_01/gun_007/kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme ve stdout/stderr kaydı.
7. `portfolio/hafta_01/gun_007/kanit/gercek/test_sonuclari.txt`: 11/11 unittest başarı kaydı.
8. `portfolio/hafta_01/gun_007/kanit/temsili/laboratuvar_topolojisi.txt`: Temsilî ASCII topoloji ve izolasyon şeması.
9. `portfolio/hafta_01/gun_007/rapor.md`: Bu değerlendirme raporu.
10. `portfolio/hafta_01/gun_007/README.md`: Hızlı başlangıç ve kullanım kılavuzu.
11. `portfolio/hafta_01/gun_007/sonuc.json`: 14 standart alanlı makine-okunabilir durum özeti.
12. `portfolio/hafta_01/gun_007/manifest.json`: Tüm dosyaların SHA-256 bütünlük özetleri.
