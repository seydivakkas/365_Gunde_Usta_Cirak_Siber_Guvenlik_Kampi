# GÜN 010: Değerlendirme ve Denetim Raporu
**Konu:** Linux Sanal Makinesine Güvenli Başlangıç (SSH Sertleştirmesi, Sudoers, Shadow İzinleri ve UFW Kalkanı)  
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
| **Teorik Derinlik ve Kavramsal Model** | 20 | **20** | Eksiksiz | Linux yetki hiyerarşisi (UID 0 vs 1000), SSH anahtarlı kimlik doğrulama, /etc/shadow kalkanı, NOPASSWD açığı ve UFW analojisi "Usta-Çırak" derinliğinde açıklandı. |
| **Uygulama ve Kod Kalitesi** | 40 | **40** | Eksiksiz | Her satırı zengin pedagojik açıklamalarla donatılmış `linux_baseline_auditor.py` CLI motoru geliştirildi; CIS Benchmark Seviye 1 denetimleri ve güvenli sshd_config/sudoers üretimi eksiksiz kodlandı. |
| **Birim Testler ve Negatif Kontroller** | 25 | **25** | Eksiksiz | 13 birim test ile pozitif CIS altın standart, PermitRootLogin=yes, PasswordAuthentication=yes, NOPASSWD=ALL, shadow=0644 ve kapalı UFW durumları 0.196s'de %100 doğrulandı. |
| **Dokümantasyon, Soru-Cevap ve Kanıtlar** | 15 | **15** | Eksiksiz | 7 bölümlü masterclass ders metni, 4 katı alt başlıklı 3 soru-cevap, gerçek CLI yürütme çıktısı ve temsilî ASCII mimari şeması eksiksiz üretildi. |
| **TOPLAM** | **100** | **100** | **YETERLİ (PASS)** | Müfredat ve kalite standartlarının tüm şartları tam olarak karşılandı. |

---

## 🔍 2. Pozitif ve Negatif Kontrol Doğrulama Matrisi

| Kontrol Türü | Test Fonksiyonu | Beklenen Davranış | Gözlenen Sonuç | Durum |
| :--- | :--- | :--- | :--- | :---: |
| **Pozitif Kontrol** | `test_01_cis_seviye_1_pozitif_kontrol` | CIS Seviye 1 sertleştirilmiş sistemde 100/100 skor ve 0 açık bulgu üretilmeli. | Skor: 100, Bulgu: 0, Durum: GÜVENLİ | **GEÇTİ** |
| **Negatif Kontrol (Root SSH)** | `test_02_permit_root_login_negatif_kontrol` | PermitRootLogin=yes açıkken kaba kuvvet riskiyle 35 ceza puanı kesilmeli. | Skor: 65, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Parola)** | `test_03_password_authentication_negatif_kontrol` | PasswordAuthentication=yes açıkken parola saldırısı uyarısıyla 25 puan kesilmeli. | Skor: 75, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (NOPASSWD)**| `test_04_sudoers_nopasswd_felaket_kontrol` | /etc/sudoers'ta NOPASSWD açıkken FELAKET uyarısıyla 50 ceza puanı kesilmeli. | Skor: 50, 1 adet FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Shadow)** | `test_05_etc_shadow_izin_felaket_kontrol` | /etc/shadow izinleri 0644 olduğunda FELAKET uyarısıyla 50 puan ceza kesilmeli. | Skor: 50, 1 adet FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Passwd)** | `test_06_etc_passwd_yazilabilir_felaket_kontrol` | /etc/passwd izinleri 0777 olduğunda FELAKET uyarısıyla 50 puan ceza kesilmeli. | Skor: 50, 1 adet FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (UFW)** | `test_07_ufw_kapali_negatif_kontrol` | Güvenlik duvarı kapalıyken açık port tehlikesiyle KRİTİK bulgu üretilmeli. | Skor: 65, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Politika)**| `test_08_ufw_varsayilan_gelen_allow_negatif_kontrol` | Varsayılan gelen ağ trafiği ALLOW olduğunda KRİTİK bulgu üretilmeli. | Skor: 65, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Servis)** | `test_09_yasakli_servis_telnet_negatif_kontrol` | Şifresiz telnetd aktifken YÜKSEK risk bulgusuyla 20 ceza puanı kesilmeli. | Skor: 80, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Umask)** | `test_10_guvensiz_umask_negatif_kontrol` | umask=000 yapıldığında YÜKSEK risk bulgusu üretilmeli. | Skor: 80, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **İşlevsellik (Şablon Üretimi)**| `test_11_sshd_ve_sudoers_dosya_uretim_kontrol` | Üretilen sshd_config ve sudoers dosyalarında CIS Seviye 1 kuralları doğrulanmalı. | Dosyalar üretildi ve parametreler teyit edildi. | **GEÇTİ** |
| **Hata Yönetimi (Şema)** | `test_12_gecersiz_sema_ve_alan_eksikligi` | Zorunlu alan eksikliğinde LinuxSecurityValidationError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |
| **Hata Yönetimi (Dosya)** | `test_13_olmayan_dosya_hatasi` | Bulunmayan dosya yolunda FileNotFoundError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |

---

## 🛠️ 3. Tamamlanan Çıktılar ve Kanıt Dosyaları

1. `ornek_veri/linux_vm_yapilandirmasi.json`: Sertleştirilmiş (`LINUX-SEC-01`) ve güvensiz (`LINUX-RISK-99`) Linux sistem veri tabanı.
2. `ornek_veri/sshd_config_hardened`: Otomatik üretilen CIS Seviye 1 OpenSSH sunucu sertleştirme dosyası.
3. `ornek_veri/sudoers_hardened`: Otomatik üretilen güvenli `/etc/sudoers.d/` kural dosyası.
4. `uygulama/linux_baseline_auditor.py`: Her satırı pedagojik açıklamalarla yazılmış, Linux taban çizgisi denetim ve konfigürasyon motoru.
5. `tests/test_linux_baseline_auditor.py`: 13 birim test senaryosunu içeren ve 0.196 saniyede sonuçlanan tam test paketi.
6. `kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme çıktısı ve platform ortam kaydı.
7. `kanit/gercek/test_sonuclari.txt`: 13/13 unittest başarı çıktısı.
8. `kanit/temsili/linux_guvenlik_mimarisi.txt`: SSH kalkanı, sudoers denetimi, shadow izinleri ve UFW politikasını gösteren pedagojik ASCII şeması.
9. `ders.md`: 7 aşamalı "Usta-Çırak" masterclass ders metni.
10. `soru_cevap.md`: Soru bankasındaki 3 soruya (`G010-SC1`, `G010-SC2`, `G010-SC3`) ait 4 katı alt başlıklı kurumsal yanıtlar.

---

## 🏁 4. Sonuç ve Bir Sonraki Güne Geçiş

GÜN 010 çalışması; Linux sanal makinelerinin ilk kurulumundan itibaren nasıl kurşun geçirmez hale getirileceğini, SSH ve Sudoers sertleştirmesini, dosya izinlerinin kritik önemini ve UFW güvenlik duvarı disiplinini başarıyla tamamlamıştır.

Tüm testler ve denetimler **%100 PASS** ile sonuçlanmış olup, Aşama 01 Hafta 02 kapsamındaki **GÜN 011 ("Temel Linux komutları ve dosya sistemi hiyerarşisi")** konusuna geçiş için tüm ön koşullar eksiksiz sağlanmıştır.
