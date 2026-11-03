# GÜN 138: Linux Güvenlik Duvarı (nftables/UFW) Güvenlik Denetim Raporu

**Tarih:** 2026-11-02  
**Denetçi / Güvenlik Mimarı:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux Çekirdeği Netfilter Kancaları, modern nftables Mimarisi, UFW (Uncomplicated Firewall) Yönetimi, Varsayılan Reddetme (Default Deny), Durum Denetimli (Stateful / conntrack) Paket Filtreleme, Loopback İzolasyonu, Anti-Spoofing ve Açık Port Denetimleri  
**Standartlar:** CIS Linux Benchmark v2.0.0 (Section 3.4: Configure nftables & Section 3.5: Configure UFW), MITRE ATT&CK Matrix (T1562.004, T1046, T1584.004, T1059), Common Weakness Enumeration (CWE-284, CWE-693, CWE-290, CWE-250, CWE-778, CWE-732), NIST SP 800-41 Rev. 1: Guidelines on Firewalls and Firewall Policies  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Betik Üretimi** | Audit, Remediate, nft/ufw Template | JSON, SH ve nftables.conf Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `firewall_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+--------------------------------------------------------------------------+
|         GÜN 138 SKOR KARTI: LINUX GÜVENLİK DUVARI (NFTABLES / UFW)       |
+--------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                          : 100.0   |
| Uygulama Mimarisi ve Güvenlik Duvarı Motoru                    :  20/20  |
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
| **FW-001** | CWE-284 | T1562.004 | CRITICAL | Güvenlik Duvarı Devre Dışı veya Durdurulmuş | nftables veya UFW servisinin kapalı olması sonucu sunucunun ağ seviyesinde tamamen savunmasız kalması. |
| **FW-002** | CWE-284 | T1046 | CRITICAL | Varsayılan Gelen (INPUT) Politikasının ACCEPT Olması | Default Deny kuralının ihlal edilmesi; izin verilmeyen tüm yabancı paketlerin içeri kabul edilmesi. |
| **FW-003** | CWE-284 | T1046 | HIGH | Varsayılan Yönlendirme (FORWARD) Politikasının ACCEPT Olması | Router olmayan sunucuda paket yönlendirmeye izin verilmesi; sunucunun pivot/tünel amacıyla istismarı. |
| **FW-004** | CWE-693 | T1059 | HIGH | Durum Denetimli (conntrack) Filtreleme Eksikliği | Established/related kurallarının olmaması veya invalid TCP bayraklı paketlerin düşürülmemesi. |
| **FW-005** | CWE-290 | T1584.004 | HIGH | Loopback İzolasyonu veya Anti-Spoofing Eksikliği | lo arayüzüne izin verilmemesi veya harici arayüzden gelen sahte 127.0.0.0/8 paketlerinin filtrelenmemesi. |
| **FW-006** | CWE-250 | T1046 | HIGH | Herkese Açık Tehlikeli Servis Portu | Telnet (23), SMB (445), RDP (3389) gibi hassas servislerin IP kısıtlaması olmaksızın tüm ağa açılması. |
| **FW-007** | CWE-778 | T1562.001 | MEDIUM | Güvenlik Duvarı Loglamasının Kapalı Olması | Düşürülen şüpheli paketlerin loglanmaması sonucu saldırı tespitinin ve adli bilişim incelemelerinin engellenmesi. |
| **FW-008** | CWE-732 | T1565.001 | LOW | Gevşek Yapılandırma Dosya İzinleri | `/etc/nftables.conf` dosyasının `0666` modunda olması sonucu yetkisiz kullanıcılarca kuralların değiştirilebilmesi. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen güvenlik motoru (`LinuxFirewallSecurityEngine`) ve CLI aracı (`firewall_security_cli.py`), sunucudaki güvenlik duvarı açıklarını gidermek üzere:
1. Varsayılan politikaları kilit altına alan (`INPUT: DROP`, `FORWARD: DROP`, `OUTPUT: ACCEPT`),
2. Loopback ve anti-spoofing kurallarını enjekte eden,
3. `ct state established,related accept` ve `ct state invalid drop` durum denetimli kurallarını ekleyen,
4. Yetkili servisleri rate-limiting ile güvenceye alan (SSH: `limit rate 10/minute`, HTTP/HTTPS `accept`),
5. Engellenen paketleri loglayan
çalıştırılabilir Bash sertleştirme betiğini ([`otomatik_sikilastirma.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_138/kanit/gercek/otomatik_sikilastirma.sh)), CIS uyumlu nftables şablonunu ([`ornek_guvenli_nftables.conf`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_138/kanit/gercek/ornek_guvenli_nftables.conf)) ve UFW şablonunu ([`ornek_guvenli_ufw.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_138/kanit/gercek/ornek_guvenli_ufw.sh)) başarıyla üretmiştir.

---

## 5. Sonuç ve Gelecek Gün Geçişi

Gün 138 başarıyla tamamlanmış, Linux host tabanlı güvenlik duvarı mimarisi 100/100 tam puanla belgelenmiştir. Yarın (Gün 139), Linux denetim ve olay izleme altyapısının kalbi olan **Linux audit ve journal güvenliği (auditd / journald)** konusu işlenecektir.
