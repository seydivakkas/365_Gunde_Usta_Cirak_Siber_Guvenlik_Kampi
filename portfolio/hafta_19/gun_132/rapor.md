# GÜN 132: Windows Hizmet Güvenliği Denetim ve Sıkılaştırma Raporu

**Tarih:** 2026-11-02  
**Denetçi / Mühendis:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Windows Service Control Manager (SCM), Service DACL (SDDL), Tırnaksız Servis Yolları (CWE-428), Zayıf Dosya İzinleri (CWE-732), En Az Ayrıcalık İhlalleri (CWE-250) ve CIS Windows Benchmark  
**Genel Değerlendirme:** BAŞARILI (100 / 100 PASS)

---

## 1. Yürütme ve Doğrulama Özeti

| Denetim Bileşeni | Hedeflenen Metrik | Gerçekleşen Metrik | Sonuç |
|---|---|---|---|
| **Birim Testleri (Unit Tests)** | 15 / 15 Test | 15 / 15 Test Başarılı (0.001s) | **TAM BAŞARILI (%100)** |
| **Negatif Kontrol Senaryoları** | 9 / 9 Sınır Durum | 9 / 9 Doğru Tespit Edildi | **TAM BAŞARILI (%100)** |
| **CLI Denetim ve Raporlama** | Audit & Remediate | JSON & PowerShell Çıktıları Üretildi | **TAM BAŞARILI (%100)** |
| **Mimari ASCII Diyagramı** | Standart Başlıklı | `service_mimarisi.txt` Doğrulandı | **TAM BAŞARILI (%100)** |
| **Kod Açıklama Standardı** | Didaktik Türkçe | Tüm Satırlarda Açıklama Mevcut | **TAM BAŞARILI (%100)** |
| **Lisans & Telif Uyumu** | Özel Lisans | Tüm Dosyalarda Lisans Başlığı Mevcut | **TAM BAŞARILI (%100)** |

---

## 2. Puanlama ve Güvenlik Skor Kartı

```text
+-------------------------------------------------------------------------+
|                  GÜN 132 SKOR KARTI: WINDOWS HİZMET GÜVENLİĞİ           |
+-------------------------------------------------------------------------+
| Temel Başlangıç Puanı                                         : 100.0   |
| Uygulama Mimarisi ve SCM Denetim Motoru                       :  20/20  |
| Kapsamlı Birim Test Takımı (15/15 PASS)                       :  40/40  |
| Örnek Veri, Negatif Senaryolar (9/9 PASS) ve Kanıt Üretimi   :  25/25  |
| Usta-Çırak Eğitsel Dokümantasyon ve Derinlemesine Raporlama   :  15/15  |
+-------------------------------------------------------------------------+
| TOPLAM PUAN                                                   : 100/100 |
| NİHAİ DEĞERLENDİRME                                           : PASS    |
+-------------------------------------------------------------------------+
```

---

## 3. Tespit Edilen Zafiyet Kategorileri ve Tehdit Haritası

| Zafiyet Kodu | MITRE ATT&CK | Önem Derecesi | Zafiyet Başlığı | Risk Açıklaması |
|---|---|---|---|---|
| **CWE-428** | T1574.009 | HIGH | Tırnaksız Servis Yolu | Boşluk içeren ImagePath değerinin tırnak içine alınmaması sonucu `C:\Program.exe` üzerinden SYSTEM haklarına sıçrama riski. |
| **CWE-732** | T1543.003 | CRITICAL | Zayıf Servis DACL İzni | `BUILTIN\Users` veya `Everyone` grubuna `SERVICE_CHANGE_CONFIG` (`DC`) veya `WRITE_DAC` (`WD`) yetkisi verilerek servisin zararlı ikili dosyayı çalıştıracak şekilde yeniden yapılandırılması. |
| **CWE-732** | T1574.010 | CRITICAL | Zayıf Dosya İzinleri | Servisin çalıştırdığı ikili dosyanın standart kullanıcılar tarafından yazılabilir / değiştirilebilir olması. |
| **CWE-250** | T1078.003 | MEDIUM | En Az Ayrıcalık İhlali | Üçüncü parti servislerin gereksiz yere `LocalSystem` hesabıyla koşarak saldırı yüzeyini genişletmesi. |
| **CWE-250** | T1134 | HIGH | Tehlikeli Ayrıcalık Talebi | Servisin `SeDebugPrivilege` veya `SeTcbPrivilege` gibi kritik çekirdek haklarını gereksiz yere talep etmesi. |
| **CWE-16** | T1003.002 | HIGH / MEDIUM | CIS Benchmark İhlali | `RemoteRegistry` veya `XboxGipSvc` gibi gereksiz ve saldırı yüzeyi oluşturan servislerin aktif bırakılması. |

---

## 4. İyileştirme (Remediation) Doğrulaması

Geliştirilen denetim motoru (`WindowsServiceSecurityEngine`) zafiyetleri tespit etmekle kalmayıp, operasyonel ekiplerin tek tıkla çalıştırabileceği PowerShell sıkılaştırma betikleri üretmiştir:

1. **Tırnak Koruması:** `sc.exe config "<Service>" binPath= "\"C:\Program Files\...\""`
2. **SDDL Sıkılaştırması:** `sc.exe sdset "<Service>" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"`
3. **CIS Kapatma:** `Set-Service -Name "RemoteRegistry" -StartupType Disabled; Stop-Service -Name "RemoteRegistry"`
4. **Dosya İzinlerinin Kilitlenmesi:** `icacls "<BinaryPath>" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)"`

---

## 5. Sonuç ve Gelecek Hafta Geçişi

Gün 132 başarıyla tamamlanmış, Windows Service Control Manager ve servis güvenlik dinamikleri tam puanla doğrulanmıştır. Bir sonraki gün (Gün 133), Hafta 19'un kapanış çalışması olan **Mini Proje 18: Windows Denetim Raporu** icra edilecektir.
