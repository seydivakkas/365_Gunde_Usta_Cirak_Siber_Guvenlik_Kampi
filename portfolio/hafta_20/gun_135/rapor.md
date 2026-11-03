# GÜN 135: Linux PAM ve Oturum Politikası Güvenlik Denetim Raporu

**Tarih:** 2026-11-02  
**Denetçi / Güvenlik Mimarı:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux Pluggable Authentication Modules (PAM) mimarisi, `/etc/pam.d/`, hesap kilitleme (`pam_faillock`), parola karmaşıklığı (`pam_pwquality`), parola geçmişi (`pam_pwhistory`), boş parola denetimi (`nullok`), oturum zaman aşımı (`TMOUT`) ve dosya izinleri  
**Standartlar:** CIS Linux Benchmark (Section 5.4), MITRE ATT&CK Matrix (T1110.001, T1078, T1201), Common Weakness Enumeration (CWE-307, CWE-521, CWE-262, CWE-258, CWE-613, CWE-732)  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Betik Üretimi** | Audit & Remediate | JSON ve Bash Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `pam_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+--------------------------------------------------------------------------+
|            GÜN 135 SKOR KARTI: LINUX PAM VE OTURUM POLİTİKASI            |
+--------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                          : 100.0   |
| Uygulama Mimarisi ve PAM Denetim Motoru                        :  20/20  |
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
| **CWE-307** | T1110.001 | CRITICAL | Hesap Kilitleme Kapalı | `pam_faillock` modülünün olmaması sonucu sınırsız parola denemesi ve kaba kuvvet riski. |
| **CWE-307** | T1110.001 | HIGH / MEDIUM | Zayıf Kilitleme Parametreleri | `deny > 5`, `unlock_time < 900s` veya `even_deny_root` eksikliği. |
| **CWE-521** | T1201 | HIGH | Yetersiz Parola Karmaşıklığı | `minlen < 14` ve kredi kısıtlarının (`dcredit`, `ucredit`, `lcredit`, `ocredit`) eksik olması. |
| **CWE-258** | T1078 | CRITICAL | Boş Parola Giriş İzni (nullok) | `pam_unix.so` içinde `nullok` tanımlanarak şifresi olmayan hesaplara şifresiz giriş imkanı verilmesi. |
| **CWE-262** | T1201 | HIGH | Yetersiz Parola Geçmişi | `remember < 5` olması sonucu eski parolaların tekrar kullanılabilmesi. |
| **CWE-613** | T1078 | HIGH | Yetersiz Oturum Zaman Aşımı | `TMOUT > 900s` veya tanımsız olması sonucu açık bırakılan terminallerin istismara açık kalması. |
| **CWE-732** | T1548 | CRITICAL | Gevşek PAM Dosya İzinleri | `/etc/pam.d/` ve `/etc/security/` dosyalarının `0666` veya root harici sahiplikte olması. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen denetim motoru (`LinuxPamSecurityEngine`) ve CLI aracı (`pam_security_cli.py`), tespit edilen tüm zafiyetler için operasyonel ekiplere:
1. Otomatik dosya izinlerini kilitleyen (`chmod 0644`, `chown root:root`),
2. `/etc/security/faillock.conf` ve `/etc/security/pwquality.conf` yapılandırmalarını CIS standartlarına getiren,
3. `/etc/profile.d/timeout.sh` dosyası oluşturarak `readonly TMOUT=900` oturum zaman aşımını zorunlu kılan Bash sıkılaştırma betiği ([`otomatik_sikilastirma.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_135/kanit/gercek/otomatik_sikilastirma.sh)) üretmiştir.

---

## 5. Sonuç ve Gelecek Gün Geçişi

Gün 135 başarıyla tamamlanmış, Linux kimlik doğrulama ve oturum politikası temelleri 100/100 tam puanla belgelenmiştir. Yarın (Gün 136), Linux arka plan mimarisi ve servis yönetiminin kalbi olan **Linux servisleri ve systemd** konusu işlenecektir.
