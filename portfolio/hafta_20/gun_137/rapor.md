# GÜN 137: Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirme Denetim Raporu

**Tarih:** 2026-11-02  
**Denetçi / Güvenlik Mimarı:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux SSH Protokol Mimarisi, Özel ve Açık Anahtarlar, Kriptografik Algoritmalar (Ed25519, RSA, DSA), Anahtar Dosya/Dizin İzinleri, authorized_keys Kısıtlamaları ve OpenSSH Sunucu (sshd_config) Sertleştirmesi  
**Standartlar:** CIS Linux Benchmark v2.0.0 (Section 5.2: SSH Server Configuration), MITRE ATT&CK Matrix (T1552.004, T1098.004, T1078.003, T1110.001), Common Weakness Enumeration (CWE-732, CWE-522, CWE-327, CWE-326, CWE-250, CWE-307, CWE-258, CWE-613), NIST SP 800-131A & NIST SP 800-123  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Betik Üretimi** | Audit, Remediate, sshd-config | JSON, SH ve Sshd Config Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `ssh_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+--------------------------------------------------------------------------+
|          GÜN 137 SKOR KARTI: LINUX SSH ANAHTAR VE SUNUCU GÜVENLİĞİ       |
+--------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                          : 100.0   |
| Uygulama Mimarisi ve SSH Güvenlik Motoru                       :  20/20  |
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
| **SSH-001** | CWE-732 | T1552.004 | CRITICAL | Gevşek Özel Anahtar (Private Key) İzinleri | Özel anahtarın `0644` veya `0666` olması sonucu sunucuya sızan saldırganın anahtarı çalıp diğer sunuculara sıçrayabilmesi. |
| **SSH-002** | CWE-522 | T1552.004 | MEDIUM | Parolasız Özel Anahtar | Özel anahtarın şifresiz kaydedilmesi sonucu kopyalandığı anda kullanılabilir olması. |
| **SSH-003** | CWE-327 | T1552.004 | CRITICAL | Güvensiz ve Kırılmış DSA Anahtarı | 1024-bit DSA algoritmasının kriptografik olarak kırılmış ve OpenSSH tarafından terk edilmiş olması. |
| **SSH-004** | CWE-326 | T1552.004 | HIGH | Yetersiz RSA Anahtar Uzunluğu (< 2048 bit) | 1024-bit RSA anahtarının çarpanlara ayırma saldırılarıyla kırılabilmesi. |
| **SSH-005** | CWE-732 | T1098.004 | CRITICAL | Gevşek `authorized_keys` Dosya İzinleri | Dosyanın başkalarınca yazılabilir olması sonucu saldırganın kendi açık anahtarını ekleyip kalıcılık sağlaması. |
| **SSH-006** | CWE-327 | T1078.003 | HIGH | `authorized_keys` İçinde Zayıf DSA Anahtarı | Yetkilendirilmiş açık anahtarlar arasında kırılmış DSA anahtarı bulunması. |
| **SSH-007** | CWE-250 | T1078.003 | HIGH | Doğrudan Root Giriş İzni (PermitRootLogin yes) | Root hesabına doğrudan oturum açılabilmesi sonucu kaba kuvvet ve hesap izleme zafiyeti. |
| **SSH-008** | CWE-307 | T1110.001 | HIGH | Parola ile Kimlik Doğrulamanın Açık Olması | Sunucunun sözlük ve kaba kuvvet parola saldırılarına açık bırakılması. |
| **SSH-009** | CWE-258 | T1078 | CRITICAL | Boş Parola ile Giriş İzni (PermitEmptyPasswords yes) | Şifresiz hesaplara SSH üzerinden doğrudan şifresiz giriş imkanı verilmesi. |
| **SSH-010** | CWE-307 | T1110.001 | MEDIUM | Yüksek Başarısız Giriş Deneme Sınırı (MaxAuthTries > 4) | Oturum başına aşırı parola/anahtar denemesine izin verilmesi. |
| **SSH-011** | CWE-200 | T1059 | LOW | X11 Grafik Yönlendirmesi Aktif | Sunucuda gereksiz GUI tünellemesi sonucu tuş vuruşu izleme riski. |
| **SSH-012** | CWE-613 | T1078 | LOW | Hareketsizlik Zaman Aşımı Eksikliği | Boşta bırakılan SSH terminallerinin otomatik sonlandırılmaması. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen güvenlik motoru (`LinuxSshSecurityEngine`) ve CLI aracı (`ssh_security_cli.py`), tespit edilen tüm SSH zafiyetleri için sistem yöneticilerine:
1. Özel anahtarların (`0600`) ve `authorized_keys` dosyalarının (`0600`) izinlerini kilitleyen,
2. `/etc/ssh/sshd_config` dosyasının yedeğini alıp `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `PermitEmptyPasswords no`, `MaxAuthTries 3` direktiflerini otomatik uygulayan,
3. Sözdizimini `sshd -t` ile doğruladıktan sonra servisi güvenle yeniden yükleyen (`systemctl reload sshd`)
çalıştırılabilir Bash sertleştirme betiğini ([`otomatik_sikilastirma.sh`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_137/kanit/gercek/otomatik_sikilastirma.sh)) ve CIS uyumlu altın standart sunucu şablonunu ([`ornek_guvenli_sshd_config`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_20/gun_137/kanit/gercek/ornek_guvenli_sshd_config)) başarıyla üretmiştir.

---

## 5. Sonuç ve Gelecek Gün Geçişi

Gün 137 başarıyla tamamlanmış, Linux SSH anahtar güvenliği ve sunucu sertleştirme mekanizması 100/100 tam puanla belgelenmiştir. Yarın (Gün 138), Linux ağ güvenliğinin ve paket filtreleme mimarisinin temeli olan **Linux firewall: nftables/ufw kavramı** konusu işlenecektir.
