# GÜN 009: Değerlendirme ve Denetim Raporu
**Konu:** Windows Üzerinde Laboratuvar Hazırlığı (Windows Sandbox, Hyper-V vSwitch, WSL2 ve Defender Kalkanı)  
**Tarih:** 2026-10-26  
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
| **Teorik Derinlik ve Kavramsal Model** | 20 | **20** | Eksiksiz | VBS/HVCI mimarisi, Windows Sandbox .wsb yaşam döngüsü, Hyper-V vSwitch türleri ve Exclusion Hijacking tehlikesi "Usta-Çırak" derinliğinde açıklandı. |
| **Uygulama ve Kod Kalitesi** | 40 | **40** | Eksiksiz | Her satırı zengin pedagojik açıklamalarla donatılmış `windows_lab_provisioner.py` CLI aracı geliştirildi; otomatik güvenli `.wsb` XML profil üretimi ve şema doğrulama eksiksiz kodlandı. |
| **Birim Testler ve Negatif Kontroller** | 25 | **25** | Eksiksiz | 13 birim test ile pozitif altın standart, Sandbox sızıntısı (Networking=Default), Sandbox C:\ eşlemesi, External vSwitch, Defender C:\Users dışlaması ve bozuk şemalar 0.214s'de %100 doğrulandı. |
| **Dokümantasyon, Soru-Cevap ve Kanıtlar** | 15 | **15** | Eksiksiz | 7 bölümlü masterclass ders metni, 4 katı alt başlıklı 3 soru-cevap, gerçek CLI yürütme çıktısı ve temsilî ASCII mimari şeması eksiksiz üretildi. |
| **TOPLAM** | **100** | **100** | **YETERLİ (PASS)** | Müfredat ve kalite standartlarının tüm şartları tam olarak karşılandı. |

---

## 🔍 2. Pozitif ve Negatif Kontrol Doğrulama Matrisi

| Kontrol Türü | Test Fonksiyonu | Beklenen Davranış | Gözlenen Sonuç | Durum |
| :--- | :--- | :--- | :--- | :---: |
| **Pozitif Kontrol** | `test_01_altin_standart_pozitif_kontrol` | Tam sertleştirilmiş Windows lab profilinde 100/100 puan ve 0 bulgu üretilmeli. | Skor: 100, Bulgu: 0, Durum: GÜVENLİ | **GEÇTİ** |
| **Negatif Kontrol (Sandbox Ağ)** | `test_02_sandbox_networking_default_negatif_kontrol` | Sandbox ağı 'Default' bırakıldığında C2 sızıntı uyarısı ile 35 ceza puanı kesilmeli. | Skor: 65, KRİTİK bulgu tespit edildi. | **GEÇTİ** |
| **Negatif Kontrol (Sandbox C:\)** | `test_03_sandbox_mapped_folder_kok_dizin_felaket_kontrol` | Sandbox içine konak C:\ dizini eşlenirse FELAKET uyarısıyla 50 ceza puanı kesilmeli. | Skor: 50, 1 adet FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Yazma İzni)** | `test_04_sandbox_mapped_folder_yazma_izni_negatif_kontrol` | Eşlenen klasörde salt_okunur=False olduğunda konak bozma riski uyarısı verilmeli. | Skor: 70, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (vSwitch)** | `test_05_hyper_v_external_vswitch_negatif_kontrol` | Hyper-V External vSwitch tespit edildiğinde fiziksel ağa yayılma uyarısı verilmeli. | Skor: 60, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Sniffing)** | `test_06_hyper_v_promiscuous_mode_negatif_kontrol` | vSwitch promiscuous mod açıkken sanal ağ koklama riski uyarısı verilmeli. | Skor: 75, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Exclusion)** | `test_07_defender_yasakli_genis_dislama_felaket_kontrol` | Defender dışlamalarında C:\Users olduğunda FELAKET uyarısıyla 50 ceza puanı kesilmeli. | Skor: 50, FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (ACL)** | `test_08_defender_acl_standart_kullanici_yazma_negatif_kontrol` | Dışlanan klasörde standart kullanıcı yazma izni varsa YÜKSEK risk uyarısı verilmeli. | Skor: 75, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (VBS/HVCI)**| `test_09_vbs_ve_hvci_kapali_negatif_kontrol` | VBS ve HVCI kapalıyken çekirdek bellek koruma uyarısı verilmeli. | Skor: 65, VBS ve HVCI bulguları üretildi. | **GEÇTİ** |
| **Negatif Kontrol (WSL1)** | `test_10_wsl1_eski_mimari_negatif_kontrol` | WSL1 çekirdek paylaşımı uyarısı üretilmeli. | Skor: 85, ORTA risk bulgusu üretildi. | **GEÇTİ** |
| **İşlevsellik (WSB Üretimi)** | `test_11_wsb_dosya_uretim_dogrulamasi` | Üretilen .wsb XML dosyasında Networking=Disable ve ReadOnly=true doğrulanmalı. | XML doğrulandı ve etiketler teyit edildi. | **GEÇTİ** |
| **Hata Yönetimi (Şema)** | `test_12_gecersiz_sema_ve_alan_eksikligi` | Eksik zorunlu alanda WindowsLabValidationError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |
| **Hata Yönetimi (Dosya)** | `test_13_olmayan_dosya_hatasi` | Bulunmayan dosya yolunda FileNotFoundError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |

---

## 🛠️ 3. Tamamlanan Çıktılar ve Kanıt Dosyaları

1. `ornek_veri/windows_lab_yapilandirmasi.json`: Sertleştirilmiş ve güvensiz Windows laboratuvar mimarilerini modelleyen veri tabanı.
2. `ornek_veri/Izole_Zararli_Inceleme.wsb`: Otomatik üretilen BSL-4 seviyesinde tam izole Windows Sandbox profili.
3. `uygulama/windows_lab_provisioner.py`: Her satırı zengin eğitsel yorumlarla donatılmış, Windows laboratuvar denetim ve WSB üretim motoru.
4. `tests/test_windows_lab_provisioner.py`: 13 birim test senaryosunu içeren ve 0.214 saniyede sonuçlanan tam test paketi.
5. `kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme çıktısı ve platform ortam kaydı.
6. `kanit/gercek/test_sonuclari.txt`: 13/13 unittest başarı çıktısı.
7. `kanit/temsili/windows_lab_mimarisi.txt`: Windows Sandbox, Hyper-V vSwitch, WSL2 ve Defender dışlama kalkanını gösteren pedagojik ASCII mimari şeması.
8. `ders.md`: 7 aşamalı "Usta-Çırak" masterclass ders metni.
9. `soru_cevap.md`: Soru bankasındaki 3 soruya (`G009-SC1`, `G009-SC2`, `G009-SC3`) ait 4 katı alt başlıklı kurumsal yanıtlar.

---

## 🏁 4. Sonuç ve Bir Sonraki Güne Geçiş

GÜN 009 çalışması; Windows 11/10 üzerinde güvenli, kalıntısız ve fiziksel ağa sızıntı yapmayan bir güvenlik laboratuvarının nasıl inşa edileceğini, Windows Sandbox XML etiketlerinin güvenlik mekanizmalarını ve Defender Exclusion Hijacking tehlikesini başarıyla tamamlamıştır.

Tüm testler ve denetimler **%100 PASS** ile sonuçlanmış olup, Aşama 01 Hafta 02 kapsamındaki **GÜN 010 ("Linux üzerinde laboratuvar hazırlığı")** konusuna geçiş için tüm ön koşullar eksiksiz sağlanmıştır.
