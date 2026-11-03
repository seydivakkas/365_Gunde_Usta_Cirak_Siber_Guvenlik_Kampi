# GÜN 129: WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC SORU - CEVAP
**Tarih:** 2 Kasım 2026  
**Format:** Usta - Çırak / Hoca Dersi  

---

### SORU 1: Windows Split-Token Mimarisi, Integrity Level Farklılıkları ve UAC Onay Mekanizmasının Kernel Düzeyindeki İşleyişi

#### 1. Soru Başlığı ve Tanımı
Windows işletim sisteminde Split-Token (Ayrık Belirteç) mimarisi nasıl çalışır? Bir yönetici hesabı oturum açtığında üretilen iki belirteç arasındaki teknik farklar nelerdir ve UAC onay mekanizması bir süreci Medium Integrity Level'dan High Integrity Level'a kernel düzeyinde nasıl taşır?

#### 2. Derinlemesine Teknik Analiz
Windows NT çekirdeğinde her sürecin bir Erişim Belirteci (Access Token) bulunur. Bu belirteç; kullanıcının SID'sini, üye olduğu grupları, ayrıcalıkları (Privileges - örn: `SeDebugPrivilege`, `SeBackupPrivilege`) ve Bütünlük Seviyesini (Integrity Level - IL) içerir.
- **Split-Token Mekanizması:** Yerel Yöneticiler (`Administrators`) grubuna üye bir kullanıcı oturum açtığında, Local Security Authority Subsystem Service (`lsass.exe`) iki ayrı token üretir:
  1. **Filtered / Restricted Token (Medium IL):** Yönetici SID'leri (`S-1-5-32-544`) `USE_FOR_DENY_ONLY` olarak işaretlenir ve yönetimsel ayrıcalıkların neredeyse tamamı kaldırılır. Kullanıcının masaüstü kabuğu (`explorer.exe`) ve başlattığı standart uygulamalar bu belirteçle çalışır.
  2. **Full Administrator Token (High IL):** Tüm yönetimsel gruplar ve ayrıcalıklar aktiftir. Bu belirteç oturum boyunca bellekte güvenli bir şekilde saklanır.
- **Yükseltme Süreci:** Bir uygulama `runas` fiili veya bildiriminde `requireAdministrator` manifest bayrağı ile başlatıldığında:
  - `CreateProcess` çağrısı `ERROR_ELEVATION_REQUIRED` ile karşılaşır.
  - Windows RPC üzerinden **Application Information (AppInfo)** servisine başvurur.
  - AppInfo servisi `consent.exe` sürecini başlatarak masaüstünü `Winlogon` masaüstüne (Secure Desktop) kilitler.
  - Kullanıcı onay verdiğinde veya parolasını girdiğinde, AppInfo servisi saklanan Full Token'ı kopyalayarak yeni sürece bağlar ve süreci High IL seviyesinde başlatır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yazılım şirketinde sistem mühendisi, sürekli UAC onay kutusu görmekten sıkıldığı için `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` altında `EnableLUA` değerini `0` yapmıştır. Mühendis bir gün oltalama e-postasındaki şüpheli bir PDF dosyasını açmış; PDF okuyucudaki bir bellek taşması zafiyeti doğrudan High IL yetkisiyle kod çalıştırmış ve sisteme rootkit yerleşmiştir. Eğer UAC açık olsaydı, PDF okuyucu kısıtlanmış Medium IL belirteciyle çalışıyor olacak ve sistem dosyalarına yazamayacaktı.
**Çözüm:**
Kurumsal uç noktalarda `EnableLUA` mutlaka `1` olarak zorunlu kılınmalıdır:
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord
```
Ayrıca `FilterAdministratorToken` anahtarı da `1` yapılarak yerleşik SID 500 yöneticisinin de ayrık belirteç kullanması sağlanmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Yetki yükseltme ekranı kullanıcıyı rahatsız etmek için değil, kaza anında arabayı durduran hava yastığı olduğu için oradadır. 'Ben zaten yöneticiyim, neden bana soruyor?' diyen birine şu cevabı ver: 'Windows sana değil, arkanda çalışan ve senin tıkladığın yabancı koda güvenmediği için sana soruyor!'"

---

### SORU 2: UAC Bypass Saldırı Vektörleri (Auto-Elevate İkilileri, Mock Klasörler ve Registry Hijacking) ve `ConsentPromptBehaviorAdmin` Savunması (CWE-250 / MITRE T1548.002)

#### 1. Soru Başlığı ve Tanımı
Saldırganlar UAC onay ekranını tetiklemeden nasıl sistemde yetki yükseltir (UAC Bypass)? Otomatik yükselen (auto-elevating) Windows ikilileri nasıl istismar edilir ve CIS kılavuzundaki `ConsentPromptBehaviorAdmin=2` ayarı bu saldırıları nasıl tamamen etkisiz hale getirir?

#### 2. Derinlemesine Teknik Analiz
Microsoft, kullanıcı deneyimini korumak amacıyla kendi geliştirdiği bazı yönetimsel araçlara bildirim (manifest) dosyalarında `autoElevate=true` bayrağı tanımlamıştır (örn: `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, `ComputerDefaults.exe`).
- **İstismar Mantığı (Registry Hijacking):** Bu ikililer High IL ile çalışırken kullanıcı ortamındaki kayıt defteri anahtarlarına bakar. Örneğin `fodhelper.exe`, `HKCU\Software\Classes\ms-settings\Shell\Open\command` altındaki `DelegateExecute` değerini arar.
- Saldırgan standart Medium IL oturumundayken kendi kullanıcı kovanına (`HKCU`) istediği komutu (örn: `powershell.exe -enc ...`) yazabilir; çünkü burası yönetici izni gerektirmez.
- Ardından `fodhelper.exe` çağrıldığında, işletim sistemi `ConsentPromptBehaviorAdmin=5` (Varsayılan: Yalnızca Windows dışı ikililer için onay iste) ayarında ise ekrana hiçbir onay kutusu çıkarmadan `fodhelper.exe`'yi High IL ile başlatır.
- `fodhelper.exe` de HKCU'daki saldırganın komutunu High IL ile icra eder. Böylece UAC sessizce bypass edilmiş olur (`CWE-250 / MITRE T1548.002`).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal ağa sızan bir kırmızı takım (Red Team) uzmanı, ele geçirdiği kullanıcı oturumunda yerel yönetici grubunda olduğunu ancak belirtecinin Medium IL olduğunu görür. Doğrudan `fodhelper.exe` registry hijack tekniğini kullanarak sessizce High IL komut satırı açmayı hedefler.
**Çözüm ve Savunma:**
Uç noktalarda `ConsentPromptBehaviorAdmin` değeri CIS tavsiyesine göre `2` (Prompt for consent on the secure desktop) olarak ayarlandığında:
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
```
Windows, auto-elevate bayrağına sahip Microsoft ikilileri dahil olmak üzere **istisnasız her High IL çalıştırma talebinde** kullanıcıya güvenli masaüstünde açık onay sorar. Saldırganın arka planda sessizce yetki yükseltmesi teknik olarak imkansız hale gelir.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, 'Varsayılan ayar güvenlidir' yanılgısına asla kapılma. Windows'un varsayılan UAC modu (Level 2), güvenlik ile kullanılabilirlik arasında bir uzlaşmadır ve bu uzlaşma saldırganların en sevdiği arka kapıdır. Gerçek bir güvenlik mimarı, kurumsal ortamda `ConsentPromptBehaviorAdmin`'i daima `2` yapar ve sessiz yükselmelerin tamamının önünü keser!"

---

### SORU 3: Kurumsal Uç Noktalarda Yerel Yönetici Parola Riski (Pass-the-Hash / Lateral Movement) ve Windows LAPS Entegrasyonu (CWE-1188 / MITRE T1078.003)

#### 1. Soru Başlığı ve Tanımı
Kurumsal ağlarda tüm bilgisayarlarda aynı yerel yönetici (`Administrator`) parolasının kullanılması neden felaket senaryolarına yol açar? Windows LAPS (Local Administrator Password Solution) bu problemi kriptografik ve operasyonel olarak nasıl çözer?

#### 2. Derinlemesine Teknik Analiz
Birçok kurumda IT personeli kolaylık olması adına tüm istemci imajlarında aynı `LocalAdmin` parolasını tanımlar.
- **Saldırı Senaryosu (Pass-the-Hash):** Saldırgan ağdaki tek bir önemsiz stajyer bilgisayarına sızıp bellekten (`lsass.exe`) yerel yöneticinin NTLM hash'ini çekerse; bu hash ağdaki tüm diğer 10.000 istemcide ve sunucuda geçerlidir!
- Saldırgan şifreyi kırmasına bile gerek kalmadan `WMI`, `SMB` veya `WinRM` üzerinden hash'i doğrudan kullanarak (Pass-the-Hash - MITRE T1550.002) tüm ağa saniyeler içinde yayılabilir (`T1021.002 Lateral Movement`).
- **Windows LAPS Mimarisi:**
  1. İşletim sistemi çekirdeğine entegre edilen LAPS servisi, her makinede yerel yönetici parolasını periyodik olarak (örn. 30 günde bir) yüksek entropili (16+ karakter, karmaşık) olarak yerel olarak üretir.
  2. Yeni parolayı Active Directory veya Microsoft Entra ID (Azure AD) üzerindeki makine nesnesine güvenli ve şifreli bir öznitelik olarak yazar.
  3. Parolayı yalnızca yetkilendirilmiş yardım masası (Helpdesk) personeli rol tabanlı erişim kontrolüyle (RBAC) okuyabilir.
  4. Böylece bir makinenin parolası ifşa olsa dahi diğer hiçbir makinede kullanılamaz.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir fidye yazılımı çetesi, şirketin muhasebe departmanındaki bir istemciye sızmıştır. Sistemde LAPS aktif olmadığı için yerel yönetici hesabının hash'i ile ağdaki diğer 200 istemciye `PsExec` ile fidye yazılımını eş zamanlı olarak dağıtmış ve şirketi kilitlemiştir.
**Çözüm:**
1. Kurumsal GPO veya Intune üzerinden Windows LAPS politikası etkinleştirilir:
   ```powershell
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' -Name 'BackupDirectory' -Value 1 -Type DWord
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' -Name 'PasswordComplexity' -Value 4 -Type DWord
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' -Name 'PasswordAgeDays' -Value 30 -Type DWord
   ```
2. Yerleşik SID 500 hesabı LAPS yönetiminde tutulur ve standart kullanıcılara asla yerel yönetici hakkı verilmez.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kurumsal bir ağda 'ortak yerel yönetici parolası' kullanmak, bir oteldeki 500 odanın kapısına aynı kilidi takmak gibidir. Bir hırsız tek bir odaya girdiğinde tüm otel ele geçer. Her uç noktanın parolası kendine özgü, ömrü sınırlı ve merkezi olarak şifrelenmiş olmalıdır. LAPS kurumsal hijyenin alfabesidir!"
