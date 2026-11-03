# GÜN 128: WINDOWS GÜVENLİK MERKEZİ VE DEFENDER SORU - CEVAP
**Tarih:** 2 Kasım 2026  
**Format:** Usta - Çırak / Hoca Dersi  

---

### SORU 1: Attack Surface Reduction (ASR) Kurallarının Çalışma Prensibi, GUID Yönetimi ve Kurumsal Dağıtımda Yanlış Pozitif (False-Positive) Yönetimi

#### 1. Soru Başlığı ve Tanımı
Attack Surface Reduction (ASR) kuralları işletim sisteminin hangi katmanında çalışır? Kural GUID yapılandırması nasıl yönetilir ve geniş ölçekli kurumsal ağlarda operasyonel iş akışlarını aksatmadan (false-positive üretmeden) nasıl kademeli olarak devreye alınır?

#### 2. Derinlemesine Teknik Analiz
ASR kuralları, Microsoft Defender'ın çekirdek düzeyindeki filtre sürücüsü (`WdFilter.sys`) ve Windows AM-PPL (Antimalware Protected Process Light) mimarisiyle entegre çalışan bir davranışsal kontrol kalkanıdır. 
- Standart antivirüs imzaları dosyanın statik hash değerine veya diskteki baytlarına bakarken, ASR kuralları süreçler arası ilişkileri (process lineage), bellek çağrılarını ve API isteklerini gerçek zamanlı olarak denetler.
- Örneğin `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` GUID'li kural, `WINWORD.EXE` veya `EXCEL.EXE` ana sürecinin `CreateProcess` API'si üzerinden `cmd.exe`, `powershell.exe`, `cscript.exe` gibi yorumlayıcıları çağırmasını çekirdek seviyesinde yakalar.
- Kural eylemleri 4 farklı modda tanımlanabilir:
  - `0 (Disabled)`: Kural tamamen kapalıdır.
  - `1 (Block)`: Zararlı veya kurala uymayan davranış anında kesilir ve engellenir.
  - `2 (Audit)`: Süreç engellenmez; ancak Windows Event Log (`Microsoft-Windows-Windows Defender/Operational`, Event ID 1121) içerisine telemetri yazılır.
  - `6 (Warn)`: Kullanıcıya "Bu işlem engellendi, yine de devam etmek istiyor musunuz?" uyarısı gösterilir (Etkileşimli masaüstü sistemleri için).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** 5.000 istemcili bir finans kuruluşunda güvenlik ekibi, fidye yazılımlarına karşı ASR kurallarını bir gecede tüm bilgisayarlarda `Block (1)` moduna almıştır. Ertesi sabah muhasebe departmanının banka hesap özetlerini çeken meşru ve makro içeren Excel şablonları çökmüş, iş akışı durmuştur.
**Çözüm:**
1. Kademeli Devreye Alma (Phased Rollout): Kurallar ilk 14 gün boyunca GPO veya Intune üzerinden `Audit (2)` modunda yayınlanır.
2. Log Analizi ve Kural İstisnası: SIEM veya Defender for Endpoint (MDE) gelişmiş avlama (Advanced Hunting) sorgusu ile audit olayları incelenir:
   ```kusto
   DeviceEvents
   | where ActionType startswith "Asr"
   | summarize Count = count() by InitiatingProcessFileName, FileName, ActionType
   ```
3. Meşru iş dosyaları `Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Accounting\BankingAddin.dll"` komutuyla özel olarak istisna tutulur, ardından kurallar güvenle `Block (1)` moduna geçirilir.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Güvenlik mühendisliği, işi durdurmak değil; işin güvenli akmasını sağlamaktır. Üretim ortamında test edilmemiş hiçbir güvenlik kuralını doğrudan `Block` modunda dağıtma. Her zaman önce `Audit` modunda dinle, meşru yazılımları tanı, telemetriyi analiz et ve ardından zırhı kilitle!"

---

### SORU 2: Kurcalama Koruması (Tamper Protection) Mimarisi, Kayıt Defteri Bypass Girişimleri ve Endpoint Evasion Karşı Tedbirleri (CWE-693 / MITRE T1562.001)

#### 1. Soru Başlığı ve Tanımı
Microsoft Defender Kurcalama Koruması (Tamper Protection) yerel yönetici yetkilerine sahip saldırganların savunmayı kapatmasını nasıl engeller? Bu koruma devre dışı kaldığında ne gibi güvenlik açıkları doğar ve sistem nasıl sertleştirilir?

#### 2. Derinlemesine Teknik Analiz
Geçmişte saldırganlar, hedef sistemde yerel yönetici veya SYSTEM yetkisi elde ettiklerinde ilk iş olarak Kayıt Defteri (Registry) anahtarlarına müdahale ederlerdi:
```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```
Bu komutlar işletim sisteminin antivirüs motorunu sessizce kapatırdı (`CWE-693 / MITRE T1562.001`).
- **Tamper Protection Devredeyken:** Microsoft Defender, kayıt defterindeki bu kilit anahtarları çekirdek düzeyindeki korumalı sürücüsüyle kilitler. Yerel yönetici veya SYSTEM hesabı bu kayıt defteri anahtarlarına yazma talebi gönderse dahi işlem sessizce yutulur veya `Access Denied` hatası döner.
- Değişiklik talepleri yalnızca Microsoft'un kriptografik olarak imzaladığı güvenli bulut kanalları (Intune / Defender Security Center Cloud Service) üzerinden gelen onaylanmış token'lar ile kabul edilir.
- Kayıt defteri konumu: `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` altındaki `TamperProtection` DWORD değeridir. Değer `5` olduğunda motor tam kurcalama koruması altındadır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sızma testi sırasında saldırgan, oltalama yoluyla elde ettiği yerel yönetici hesabı üzerinden bir PowerShell betiği çalıştırarak Defender'ı kapatmayı denemiştir:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
Sistemde Tamper Protection aktif olduğu için komut başarılı gibi görünse de gerçek zamanlı koruma kapanmamış, saldırganın belleğe yüklemeye çalıştığı Cobalt Strike beacon'ı anında karantinaya alınmıştır.
**Çözüm ve Sertleştirme:**
Kurumsal uç noktalarda Tamper Protection'ın aktif olup olmadığı şu PowerShell komutuyla doğrulanmalıdır:
```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled
```
Eğer `IsTamperProtected: False` ise, Intune Endpoint Security profili üzerinden `Tamper Protection: On` olarak zorunlu kılınmalı ve yerel kullanıcıların ayarı değiştirmesi engellenmelidir.

#### 4. Ustanın Çırağa Tavsiyesi
"Unutma evlat, bir kilit ne kadar sağlam olursa olsun, anahtar deliğini saldırganın tornavidasına açık bırakırsan kapı açılır. Kurcalama Koruması, kilit mekanizmasının kendisini fiziksel olarak koruyan çelik zırhtır. Kurumsal ağında Tamper Protection kapalı tek bir istemci bile varsa, o istemci saldırganın sığınağı haline gelir!"

---

### SORU 3: Antivirüs Hariç Tutma (Exclusion Abuse) Saldırıları, Kök Dizin İstismarları ve GPO Denetim Metodolojisi (CWE-732 / MITRE T1562.001)

#### 1. Soru Başlığı ve Tanımı
Geliştiriciler veya sistem yöneticileri tarafından tanımlanan geniş antivirüs hariç tutma (exclusion) kuralları saldırganlar tarafından nasıl istismar edilir (`CWE-732`)? Bu açıklıklar nasıl tespit edilir ve kurumsal düzeyde nasıl temizlenir?

#### 2. Derinlemesine Teknik Analiz
Antivirüs motorları performansı korumak veya derleme (compilation) süreçlerinin aksamasını önlemek amacıyla dosya yolu, uzantı veya süreç bazlı hariç tutma listelerini destekler (`MpPreference ExclusionPath / ExclusionExtension / ExclusionProcess`).
- **İstismar Mekanizması:** Saldırgan sistemde düşük yetkili bir oturum açtıktan sonra kayıt defterini veya PowerShell'i sorgulayarak mevcut hariç tutmaları arar:
  `reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"`
- Eğer sistem yöneticisi tembellik edip `C:\` veya `C:\Windows\Temp` veya `*.exe` gibi geniş kurallar tanımlamışsa, saldırgan yükünü (payload) doğrudan bu hariç tutulan dizine kopyalar.
- Defender `WdFilter.sys` sürücüsü, bu dizindeki dosya okuma ve çalıştırma işlemlerinde `ExclusionList` kontrolü yaptığı anda dosyanın taranmasını bypass eder. Bu durum `CWE-732 (Incorrect Permission Assignment for Critical Resource)` zafiyetidir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yazılım şirketinde geliştiriciler Docker ve Visual Studio yavaş çalışıyor şikayetiyle IT ekibine başvurmuş; IT yöneticisi de tüm geliştirici bilgisayarlarında `C:\Users` ve `*.dll` uzantısını Defender hariç tutma listesine eklemiştir. Tehdit aktörü geliştiricilerden birinin e-postasına sızmış ve zararlı DLL dosyasını `C:\Users\Developer\AppData` altına yerleştirmiştir. Defender bu DLL'i asla taramadığı için saldırgan aylarca fark edilmeden ağda yanal hareket etmiştir.
**Çözüm:**
1. Tüm istemcilerde mevcut hariç tutma listeleri merkezi olarak denetlenir:
   ```powershell
   $excl = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
   $badExcl = $excl | Where-Object { $_ -match "^[A-Za-z]:\\?$" -or $_ -match "temp" -or $_ -match "Users" }
   ```
2. Tehlikeli hariç tutmalar derhal kaldırılır:
   ```powershell
   Remove-MpPreference -ExclusionPath "C:\"
   Remove-MpPreference -ExclusionExtension ".exe"
   ```
3. GPO üzerinden `Turn off exclusion list merge` politikası aktif edilerek yerel yöneticilerin kafalarına göre hariç tutma eklemesi engellenir; tüm kurallar yalnızca merkezi güvenlik ekibinin onayladığı hash veya spesifik dizin bazında tanımlanır.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, 'Hocam bizim uygulama antivirüs açıkken çalışmıyor, C sürücüsünü hariç tutalım' diyen yazılımcıya veya üreticiye asla teslim olma! C sürücüsünü hariç tutmak, kapıya çelik kilit takıp anahtarı kilidin üzerinde bırakmak gibidir. Bir hariç tutma tanımlanacaksa, bu sadece ve sadece uygulamanın tam dosya yolu ve imzalayan sertifika sağlayıcısı ile sınırlandırılmalıdır!"
