# GÜN 136: Linux Servisleri ve Systemd Güvenlik Denetim Raporu

**Tarih:** 2026-11-02  
**Denetçi / Güvenlik Mimarı:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux PID 1 (systemd) Mimarisi, Servis Unit Dosyaları, Sandboxing Direktifleri (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`), ExecStart İkili Dosya İzinleri, SUID Tespiti, Linux Capabilities Kısıtlamaları ve CIS Benchmark Servis Sertleştirme Standartları  
**Standartlar:** CIS Linux Benchmark v2.0.0 (Section 2.1 & 2.2), MITRE ATT&CK Matrix (T1543.002, T1548.001, T1068, T1005, T1059), Common Weakness Enumeration (CWE-250, CWE-732, CWE-200, CWE-377)  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Betik Üretimi** | Audit, Remediate, Template | JSON, SH ve Service Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `systemd_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+--------------------------------------------------------------------------+
|          GÜN 136 SKOR KARTI: LINUX SERVİSLERİ VE SYSTEMD GÜVENLİĞİ       |
+--------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                          : 100.0   |
| Uygulama Mimarisi ve Systemd Güvenlik Motoru                   :  20/20  |
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

| Kural Kodu | Zafiyet Türü | MITRE ATT&CK | Önem Derecesi | Risk Açıklaması |
|---|---|---|---|---|
| **SYS-001** | CWE-250 | T1059 | HIGH | Gereksiz ve Güvensiz Legacy Servis (CIS 2.1) | Telnet, RSH, Rexec, TFTP gibi eski protokollerin aktif olması sonucu şifresiz veri sızması ve istismar riski. |
| **SYS-002** | CWE-732 | T1543.002 | CRITICAL | Gevşek Servis Unit Dosyası İzinleri | `/etc/systemd/system/` dosyalarının `0666` veya root harici sahiplikte olması sonucu saldırganın ExecStart'ı değiştirip root olabilmesi. |
| **SYS-003** | CWE-732 / CWE-250 | T1548.001 | CRITICAL | Güvensiz Binary İzinleri veya SUID | ExecStart ikili dosyasının yazılabilir olması veya SUID bayrağı taşıması sonucu yerel yetki yükseltme. |
| **SYS-004** | CWE-250 | T1068 | HIGH | Servisin Doğrudan Root Olarak Koşması | `User=` tanımlanmamış veya `root` bırakılmış servislerin zafiyete uğraması durumunda saldırgana tam yetki vermesi. |
| **SYS-005** | CWE-250 | T1548 | HIGH | NoNewPrivileges Sandboxing Eksikliği | Alt süreçlerin SUID ikili dosyaları çağırarak yetki yükseltmesini engelleyen `PR_SET_NO_NEW_PRIVS` bayrağının eksikliği. |
| **SYS-006** | CWE-732 | T1565.001 | MEDIUM | ProtectSystem Eksikliği | `/usr`, `/boot` ve `/etc` dosya sistemlerinin salt-okunur kilitlenmemesi sonucu sistem dosyalarının tahrif edilebilmesi. |
| **SYS-007** | CWE-200 | T1005 | MEDIUM | ProtectHome Eksikliği | `/home`, `/root` dizinlerinin servisten gizlenmemesi sonucu SSH özel anahtarlarının ve verilerin çalınabilmesi. |
| **SYS-008** | CWE-377 | T1059 | LOW | PrivateTmp Eksikliği | Servisin paylaşımlı `/tmp` alanını kullanması sonucu geçici dosya yarış koşulları ve sembolik bağ saldırıları. |
| **SYS-009** | CWE-250 | T1059 | LOW | PrivateDevices Eksikliği | Ham disk ve bellek blok aygıtlarına (`/dev/mem`, `/dev/sda`) doğrudan raw erişimin kısıtlanmaması. |
| **SYS-010** | CWE-250 | T1548 | HIGH | Tehlikeli Linux Capabilities | Servise `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO` gibi yıkıcı yeteneklerin kontrolsüz devredilmesi. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen denetim motoru (`LinuxSystemdSecurityEngine`) ve CLI aracı (`systemd_security_cli.py`), envanterdeki zafiyetleri gidermek üzere operasyonel ekipler için otomatik olarak:
1. Güvensiz legacy servisleri durduran ve maskeleyen (`systemctl stop`, `disable`, `mask telnet.socket`),
2. Unit ve ikili dosya izinlerini sıkan (`chown root:root`, `chmod 0644 / 0755`, `chmod u-s`),
3. Her servis için `/etc/systemd/system/<servis>.service.d/99-security-hardening.conf` drop-in override dosyaları oluşturarak `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes` direktiflerini enjekte eden,
4. Systemd daemon'ını güvenle yeniden yükleyen (`systemctl daemon-reload`)
çalıştırılabilir Bash sertleştirme betiğini ([`otomatik_sikilastirma.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_136/kanit/gercek/otomatik_sikilastirma.sh)) ve CIS uyumlu güvenli servis şablonunu ([`ornek_guvenli_servis.service`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_136/kanit/gercek/ornek_guvenli_servis.service)) başarıyla üretmiştir.

---

## 5. Sonuç ve Gelecek Gün Geçişi

Gün 136 başarıyla tamamlanmış, Linux servis yönetimi ve systemd sandboxing mimarisi 100/100 tam puanla belgelenmiştir. Yarın (Gün 137), Linux uzak yönetiminin omurgası olan **SSH anahtar güvenliği ve sunucu sertleştirmesi** konusu işlenecektir.
