# GÜN 128: WINDOWS GÜVENLİK MERKEZİ VE DEFENDER SERTLEŞTİRME DERSİ
**Eğitmen:** Usta Siber Güvenlik Mimarı  
**Öğrenci:** Çırak Güvenlik Mühendisi  
**Tarih:** 2 Kasım 2026  
**Konu:** Windows Güvenlik Merkezi, Microsoft Defender Antivirus Mimarisi, ASR Kuralları ve Kurumsal Sertleştirme  

---

## 1. GİRİŞ VE USTADAN ÇIRAĞA TAVSİYELER

**Usta:** Evlat, dün uç nokta tehdit modellemesini tamamladık ve kurumsal istemcilerin saldırganlar için neden birincil sıçrama tahtası olduğunu konuştuk. Bugün kurumsal dünyada en yaygın kullanılan işletim sistemi olan Windows'un ilk ve en temel savunma kalkanına iniyoruz: **Microsoft Defender Antivirus ve Windows Güvenlik Merkezi (Windows Security Center)**.

Birçok acemi güvenlikçi Microsoft Defender'ı "ev kullanıcısı için basit bir antivirüs" zanneder ve üçüncü parti hantal yazılımlar kurarak sistemi yavaşlatır. Oysa modern Microsoft Defender, arkasındaki **Microsoft Intelligent Security Graph (MAPS)**, **Attack Surface Reduction (ASR)** motoru, **Davranışsal Analiz (Behavior Monitoring)** ve **Kurcalama Koruması (Tamper Protection)** ile dünya standartlarında bir uç nokta koruma katmanıdır. Tabii ki bir şartla: **Fabrika ayarlarındaki gevşeklikleri giderip CIS (Center for Internet Security) standartlarına göre sertleştirdiğin sürece!**

**Çırak:** Hocam, Defender varsayılan olarak zaten aktif gelmiyor mu? Neden ek sertleştirmeye ihtiyaç duyuyoruz?

**Usta:** Harika bir soru! Varsayılan kurulumda Microsoft, uyumluluk ve kullanıcı konforu adına birçok kritik korumayı gevşek veya denetim (audit) modunda bırakır. Örneğin:
1. **Kurcalama Koruması (Tamper Protection)** merkezi politikalarla zorlanmazsa, yerel yönetici yetkisi elde eden bir saldırgan tek bir PowerShell komutuyla (`Set-MpPreference -DisableRealtimeMonitoring $true`) Defender'ı anında felç edebilir.
2. **Attack Surface Reduction (ASR)** kuralları varsayılan olarak etkin değildir; Office belgelerinin PowerShell çalıştırması veya LSASS bellek alanına yetkisiz erişimler bloklanmaz.
3. **Hariç Tutmalar (Exclusions)** bilinçsiz sistem yöneticileri veya yazılım geliştiriciler tarafından `C:\` veya `*.exe` şeklinde tanımlanarak devasa güvenlik kör noktaları (CWE-732) oluşturulur.

Bugün Defender'ın anatomisini cerrah titizliğiyle inceleyecek, PowerShell ve CIS kılavuzlarıyla kurşun geçirmez bir kale inşa edeceğiz.

---

## 2. MICROSOFT DEFENDER VE WINDOWS GÜVENLİK MERKEZİ ANATOMİSİ

```
+---------------------------------------------------------------------------------------+
|                 MICROSOFT DEFENDER SERTLEŞTİRİLMİŞ SAVUNMA PİRAMİDİ                  |
+---------------------------------------------------------------------------------------+
|  [KATMAN 5] KURCALAMA KORUMASI (Tamper Protection - Kayıt Defteri / WMI Koruması)    |
|  [KATMAN 4] BULUT KORUMASI & MAPS (HighPlus / Zero-Tolerance / Hızlı İmza Dağıtımı)  |
|  [KATMAN 3] SALDIRI YÜZEYİ AZALTMA (7 Kritik ASR Kuralı - Blok Modunda)              |
|  [KATMAN 2] FIDYE & KLASÖR KORUMASI (Controlled Folder Access - Veri Şifreleme Engeli)|
|  [KATMAN 1] ÇEKİRDEK AV & DAVRANIŞSAL İZLEME (RTP, IOAV, Behavior Monitoring, PUA)   |
+---------------------------------------------------------------------------------------+
```

### 2.1 Çekirdek Antivirüs ve Gerçek Zamanlı Koruma (RTP)
Defender'ın kalbi `MsMpEng.exe` (Antimalware Service Executable) sürecidir. Bu süreç şu alt bileşenleri yönetir:
- **Real-Time Protection (RTP):** Bir dosya okunurken, yazılırken veya belleğe yüklenirken dosya başlıklarını ve imzasını kontrol eder. Devre dışı bırakılması `CWE-693 (Protection Mechanism Failure)` oluşturur.
- **Davranışsal İzleme (Behavior Monitoring):** Dosyaların çalışma anındaki (runtime) aktivitelerini izler. Örneğin bilinen imzada zararlı olmayan bir ikili dosya, arka arkaya 500 dosyayı şifrelemeye veya `lsass.exe` sürecine `OpenProcess(PROCESS_VM_READ)` göndermeye çalıştığında bu motor devreye girer.
- **IOAV (Internet/Office Antivirus Protection):** E-posta istemcilerinden veya tarayıcılardan indirilen dosyaların disk üzerine yazıldığı ilk anda taranmasını garanti eder (MITRE T1566 Phishing koruması).
- **PUA/PUP Protection:** Reklam yazılımları, kripto madenciler ve istenmeyen araç çubuklarını engeller.

### 2.2 Attack Surface Reduction (ASR) Kuralları
ASR, Windows işletim sistemindeki en tehlikeli saldırı vektörlerini (özellikle Office makroları, betikler ve kimlik bilgisi hırsızlığı) süreç seviyesinde engelleyen kural motorudur. Her kural benzersiz bir GUID ile tanımlanır:

| Kural Tanımı | Kural GUID | Güvenlik Amacı & MITRE Eşleşmesi |
|---|---|---|
| **LSASS Belleğinden Kimlik Çalınmasını Engelle** | `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` | Mimikatz türevi araçların LSASS'tan NTLM/Kerberos çalmasını engeller (T1003.001). |
| **Office Uygulamalarının Alt Süreç Başlatmasını Engelle** | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Word/Excel makrolarının `cmd.exe` veya `powershell.exe` açmasını bloklar (T1059 / T1566). |
| **Gizlenmiş/Karartılmış Betikleri Engelle** | `5BEB8E28-82E8-4337-BCB8-D4CB72E45278` | Base64 ile karartılmış VBScript/JScript yürütmelerini durdurur (T1027). |
| **PSExec ve WMI Komutlarıyla Süreç Oluşturulmasını Engelle** | `3B576C88-A8D9-4467-9781-CE450E586364` | Yanal ilerleme (Lateral Movement) tekniklerini keser (T1021.002 / T1047). |
| **E-posta İstemcilerinden Yürütülebilir İçerik Engelle** | `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` | Outlook veya Thunderbird üzerinden gelen `.exe/.scr` dosyalarını durdurur (T1566). |
| **JS/VBS'in İndirilen İkilileri Çalıştırmasını Engelle** | `D3E037E1-3EB8-44C8-A917-57927947596D` | Web tarayıcısından inen dosyanın betiklerle çalıştırılmasını engeller (T1204). |
| **Gelişmiş Fidye Yazılımı Koruması** | `C1DB55AB-C21A-4637-BB3F-A12568109D35` | Şüpheli şifreleme ve dosya yeniden adlandırma dalgalarını anında keser (T1486). |

### 2.3 Kurcalama Koruması (Tamper Protection) Mimarisi
**Usta:** Dikkat et evlat! Bir sistemde yerel yönetici (Local Administrator) yetkisine sahip bir zararlı yazılım veya sızma testi uzmanı, `Set-MpPreference -DisableRealtimeMonitoring $true` komutunu çalıştırabilir veya `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` anahtarına `DisableAntiSpyware=1` yazabilir.

İşte **Tamper Protection** tam olarak bunu önlemek için tasarlanmıştır:
- Tamper Protection devredeyken, yerel kayıt defteri veya PowerShell üzerinden Defender'ın devre dışı bırakılmasına yönelik talepler Windows Güvenlik Çekirdeği tarafından reddedilir.
- Değişiklikler yalnızca **Intune / SCCM** veya Microsoft Defender for Endpoint bulut konsolu üzerinden imzalanmış merkezi politikalarla yapılabilir.
- Kayıt defterindeki yolu: `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` (Değeri `5` aktif olduğunu gösterir).

### 2.4 Tehlikeli Hariç Tutmalar (Exclusion Abuse - CWE-732)
Saldırganların en sevdiği taktiklerden biri, elde ettikleri geçici yönetici yetkisiyle Defender'a geniş hariç tutma (exclusion) eklemektir:
```powershell
# Saldırganın savunmayı kör etme hamlesi:
Add-MpPreference -ExclusionPath "C:\"
Add-MpPreference -ExclusionExtension ".exe"
```
Bu komut çalıştığı anda Defender hiçbir `.exe` dosyasını taramaz ve tüm C sürücüsünü görmezden gelir. Bir güvenlik denetçisi olarak ilk bakacağın yer `Get-MpPreference | Select-Object -ExpandProperty ExclusionPath` olmalıdır!

---

## 3. CIS WINDOWS BENCHMARK SERTLEŞTİRME PROTOKOLÜ

Kurumsal bir Windows uç noktasında uygulanacak PowerShell sertleştirme şablonu şöyledir:

```powershell
# ====================================================================
# MICROSOFT DEFENDER CIS HARDENING STANDARD (POWERSHELL 5.1 / 7+)
# ====================================================================

# 1. Çekirdek Korumaları ve Davranışsal Analizi Zorunlu Kıl
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false

# 2. Bulut Koruması Seviyesini 'HighPlus' Olarak Belirle
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -CloudBlockLevel HighPlus
Set-MpPreference -SubmitSamplesConsent SendSafeSamples

# 3. İstenmeyen Uygulama (PUA) ve Ağ Korumasını Etkinleştir
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled

# 4. Fidye Yazılımlarına Karşı Denetimli Klasör Erişimini Aç
Set-MpPreference -EnableControlledFolderAccess Enabled

# 5. Kritik ASR Kurallarını 'Block' (1) Moduna Al
$criticalASR = @(
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', # Office alt süreç engeli
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2', # LSASS bellek koruması
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550', # E-posta yürütülebilir engeli
    '3B576C88-A8D9-4467-9781-CE450E586364', # WMI/PSExec süreç engeli
    '5BEB8E28-82E8-4337-BCB8-D4CB72E45278', # Obfuscated betik engeli
    'D3E037E1-3EB8-44C8-A917-57927947596D', # Web'den inen JS/VBS engeli
    'C1DB55AB-C21A-4637-BB3F-A12568109D35'  # Fidye yazılımı gelişmiş engeli
)
$asrActions = @(1, 1, 1, 1, 1, 1, 1)
Set-MpPreference -AttackSurfaceReductionRules_Ids $criticalASR -AttackSurfaceReductionRules_Actions $asrActions

Write-Host "[+] Microsoft Defender CIS Sertleştirmesi Başarıyla Uygulandı." -ForegroundColor Green
```

---

## 4. BİR GÜVENLİK MÜHENDİSİNİN DİKKAT ETMESİ GEREKEN HUSUSLAR

1. **Önce Audit, Sonra Block:** Üretim ortamında çalışan sistemlerde ASR kurallarını doğrudan `Block (1)` moduna almak meşru muhasebe veya ERP makrolarını kesintiye uğratabilir. Doğru pratik: Kuralları 14 gün boyunca `Audit (2)` modunda bırakıp Olay Günlükleri (Event Viewer `Applications and Services Logs/Microsoft/Windows/Windows Defender/Operational`, Event ID 1121/1122) üzerinden incelemek, ardından `Block` moduna geçirmektir.
2. **Kayıt Kütüğü Telemetrisi:** Defender bulgularını SIEM ortamına aktarmak için Event ID 1116 (Tehdit Algılandı), Event ID 1117 (Tehdit Eylemi Alındı) ve Event ID 5001 (Gerçek Zamanlı Koruma Kapandı) alarmları mutlaka yapılandırılmalıdır.
3. **Hariç Tutma Denetimi:** Herhangi bir yazılım üreticisi "Bizim programın çalışması için Defender'da C:\Program Files klasörünü hariç tutun" diyorsa, bu talebi derhal reddet; yalnızca spesifik imzalı ikili dosya yolu (`C:\Vendor\app.exe`) tanımla.

---

## 5. ÖZET VE KAZANIMLAR

Bugünkü çalışmamızla:
- Microsoft Defender'ın katmanlı koruma mimarisini öğrendik.
- 7 kritik ASR kuralının saldırganların en yaygın MITRE tekniklerini nasıl bertaraf ettiğini analiz ettik.
- Kurcalama Koruması (Tamper Protection) olmadan uç nokta güvenliğinin bir tıkla yıkılabileceğini kavradık.
- Geniş hariç tutma listelerinin oluşturduğu CWE-732 zafiyetlerini ve PowerShell ile otomatik sertleştirme yöntemlerini uyguladık.
