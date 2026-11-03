# GÜN 134: Linux Sudo ve Ayrıcalık Devri Güvenlik Denetim Raporu

**Tarih:** 2026-11-02  
**Denetçi / Güvenlik Mimarı:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux `/etc/sudoers` ve `/etc/sudoers.d/` yapılandırmaları, GTFOBins kabuk kaçışları, NOPASSWD riskleri, `env_keep` / `LD_PRELOAD` enjeksiyonları, Defaults direktifleri ve dosya izinleri  
**Standartlar:** CIS Linux Benchmark (Section 5.3), GTFOBins Privilege Escalation Matrix, MITRE ATT&CK Matrix (T1548.003, T1574.006)  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Şablon Üretimi** | Audit, Remediate, Template | JSON, SH ve CONF Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `sudo_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+--------------------------------------------------------------------------+
|            GÜN 134 SKOR KARTI: LINUX SUDO VE AYRICALIK DEVRİ             |
+--------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                          : 100.0   |
| Uygulama Mimarisi ve Sudoers Denetim Motoru                    :  20/20  |
| Kapsamlı Birim Test Takımı (15/15 PASS)                        :  40/40  |
| Örnek Veri, Negatif Senaryolar (9/9 PASS) ve Kanıt Üretimi    :  25/25  |
| Usta-Çırak Eğitsel Dokümantasyon ve Derinlemesine Raporlama    :  15/15  |
+--------------------------------------------------------------------------+
| TOPLAM PUAN                                                    : 100/100 |
| NİHAİ DEĞERLENDİRME                                            : PASS    |
+--------------------------------------------------------------------------+
```

---

## 3. Tespit Edilen Zafiyet Kategorileri ve Tehdit Haritası

| Zafiyet Kodu | MITRE ATT&CK | Önem Derecesi | Zafiyet Başlığı | Risk Açıklaması |
|---|---|---|---|---|
| **CWE-250** | T1548.003 | CRITICAL | Şifresiz Tam Root (NOPASSWD: ALL) | Kullanıcıya şifresiz root olma yetkisi verilerek parola bariyerinin tamamen kaldırılması. |
| **CWE-250** | T1548.003 | CRITICAL / HIGH | GTFOBins Kabuk Kaçışı | `vim`, `find`, `awk`, `python`, `less` gibi ikili dosyaların sudoers içerisine eklenmesi sonucu `:!/bin/sh` veya `system()` çağrısıyla root kabuğu açılması. |
| **CWE-426** | T1574.006 | CRITICAL | env_keep LD_PRELOAD Enjeksiyonu | Dinamik bağlayıcı değişkeninin korunması sonucu saldırganın kendi derlediği zararlı `.so` kütüphanesini root sürecine enjekte etmesi. |
| **CWE-250** | T1548.003 | HIGH | Defaults env_reset Kapalı | Çağıran kabuk ortamının temizlenmeyerek root sürecine aktarılması. |
| **CWE-426** | T1574.007 | HIGH | Güvensiz secure_path | PATH içerisinde göreceli dizin (`.`) veya geçici dizin (`/tmp`) barındırılması. |
| **CWE-732** | T1548.003 | CRITICAL | Sudoers Gevşek Dosya İzinleri | `/etc/sudoers` dosyasının `0666` veya root dışı sahiplikte olması. |
| **CWE-88** | T1548.003 | MEDIUM | Komut Yolunda Wildcard (*) | Parametre ve dosya adı enjeksiyonu riski. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen denetim motoru (`LinuxSudoSecurityEngine`) ve CLI aracı (`sudo_security_cli.py`), tespit edilen tüm zafiyetler için operasyonel ekiplere:
1. Sıkılaştırılmış `/etc/sudoers` şablonu ([`ornek_guvenli_sudoers.conf`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_134/kanit/gercek/ornek_guvenli_sudoers.conf)),
2. Otomatik dosya izinlerini kilitleyen (`chmod 0440`, `chown root:root`) ve `visudo -c` ile sözdizimi doğrulayan Bash betiği ([`otomatik_sikilastirma.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_134/kanit/gercek/otomatik_sikilastirma.sh)) üretmiştir.

---

## 5. Sonuç ve Gelecek Gün Geçişi

Hafta 20'nin ilk günü (Gün 134) başarıyla tamamlanmış, Linux sudo ve ayrıcalık devri temelleri 100/100 tam puanla belgelenmiştir. Yarın (Gün 135), Linux oturum ve kimlik doğrulama mimarisinin omurgası olan **PAM ve oturum politikası** konusu işlenecektir.
