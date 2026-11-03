# Gün 148: EDR, AV ve Telemetri — 3 Derin Teknik Soru ve Kapsamlı Yanıtlar

**Modül:** Hafta 22 — Gün 148 (Excel Satır 152)  
**Konu:** EDR, Antivirüs (AV), Uç Nokta Telemetrisi, Süreç Soy Ağacı ve MITRE ATT&CK Korelasyonu  
**Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas) — Özel Lisans (Tüm Hakları Saklıdır)

---

### Soru 1: Geleneksel Antivirüs (AV) ile Uç Nokta Tespit ve Müdahale (EDR) Arasındaki Mimari Farklar ve Dosyasız Zararlı (Fileless Malware) Tespiti

#### 1. Soru Başlığı ve Tanımı
Geleneksel imza tabanlı Antivirüs (AV) çözümleri ile modern Uç Nokta Tespit ve Müdahale (EDR) mimarileri arasındaki temel mimari ve operasyonel farklar nelerdir? Diske hiçbir çalıştırılabilir dosya yazmadan doğrudan bellekte (RAM) koşan **Dosyasız Zararlı Yazılımlar (Fileless Malware)** geleneksel AV motorlarını nasıl körleştirmekte ve EDR sistemleri tarafından telemetri düzeyinde nasıl yakalanmaktadır?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Geleneksel AV mimarileri disk üzerinde dosya oluşmasını veya değiştirilmesini bekleyen reaktif bir koruma modeline dayanır. Bu modelde dosyanın kriptografik hash'i (SHA-256) veya statik bayt dizilimleri bilinen kötü amaçlı imza veri tabanıyla karşılaştırılır.

Dosyasız zararlı yazılımların kurumsal ağlara getirdiği tehdit dinamikleri şunlardır:
1. **Diske Dokunmama Prensibi (Diskless Execution):** Saldırganlar PowerShell, WMI veya MSHTA gibi meşru sistem araçları üzerinden doğrudan belleğe Base64 kodlu betikler veya kabuk kodları (shellcode) yüklerler. Diskte taranacak bir dosya bulunmadığı için statik AV tarayıcıları bu saldırı karşısında tamamen işlevsiz kalır.
2. **Kalıcılık ve Tespit Edilememe (Stealth Persistence):** Dosyasız zararlılar kalıcılıklarını diske `.exe` koyarak değil; WMI Event Subscription, Kayıt Defteri ikili anahtarları (Registry Binary Payloads) veya zamanlanmış görevlere gömülen tek satırlık PowerShell komutlarıyla sağlarlar.
3. **Sıfır Gün Tehditleri (0-Day Gap):** Yeni üretilen veya polimorfik (sürekli değişen) zararlılar için antivirüs laboratuvarlarının imza üretmesi günler veya haftalar sürebilir. Bu süre zarfında tüm kurumsal uç noktalar savunmasız kalır.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
EDR sistemleri dosyanın statik varlığına değil, işletim sistemi üzerindeki davranışsal telemetri zincirine odaklanır:

```text
GELENEKSEL AV YAKLAŞIMI:
[Disk Taraması] ──> Dosya Yoksa ──> [BAŞARISIZ / TESPİT EDİLEMEDİ]

EDR TELEMETRİ YAKLAŞIMI:
[WMI / PowerShell İsteği]
         │
         ├── 1. Kernel Telemetrisi: ETW-TI üzerinden bellek tahsisatı (VirtualAllocEx - RWX)
         ├── 2. Komut Satırı Telemetrisi: -enc / DownloadString / IEX kalıbı tespiti
         ├── 3. AMSI (Antimalware Scan Interface): Bellekte çözülen betik kodunun taranması
         ├── 4. Ağ Telemetrisi (Sysmon Event ID 3): Bilinmeyen IP'ye giden şüpheli TCP bağlantısı
         │
         ▼
[KORELASYON MOTORU]: Dosyasız Zararlı Davranışı Tespiti -> Süreci Öldür (Kill) & Ağdan İzole Et!
```

- **AMSI (Antimalware Scan Interface) Entegrasyonu:** PowerShell, VBScript ve Office makroları bellekte yürütülmeden hemen önce AMSI API'si üzerinden çözülmüş (de-obfuscated) metin halini güvenlik motoruna iletir. Kod gizlenmiş (obfuscated) olsa bile bellekte açıldığı an yakalanır.
- **Bellek Koruma ve RWX İhlalleri:** EDR sürücüsü, bir sürecin bellek alanını hem yazılabilir hem de çalıştırılabilir (`PAGE_EXECUTE_READWRITE`) olarak tahsis etmesini ve buraya kabuk kodu yazılmasını çekirdek seviyesinde izler.
- **Davranışsal Heuristik ve Anomali Skoru:** Tek başına masum görünen olaylar (PowerShell çalışması + Harici ağa bağlanma + LSASS tanıtıcısı açma) bir zaman penceresi içinde korele edilerek bileşik tehdit skoru hesaplanır.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Diskte dosya aramak, hırsızı sadece bavulla gezerken yakalamaya çalışmaktır. Gerçek hırsız bavul taşımaz; evin meşru anahtarlarını kullanır. EDR ile bakman gereken şey dosya değil, odalar arasındaki ayak izleridir!"
- *Altın Kural:* Uç noktalarda yalnızca AV'ye güvenilmemeli; Windows ortamlarında Sysmon veya kurumsal EDR sensörleri aktif edilerek süreç oluşturma (Event 1), ağ bağlantıları (Event 3) ve bellek erişimleri (Event 10) merkezi SIEM/XDR sistemine kesintisiz akıtılmalıdır.

---

### Soru 2: Süreç Soy Ağacı (Process Lineage) ve LOLBAS (Living-off-the-Land) Anomalilerinin Telemetri Düzeyinde Tespiti

#### 1. Soru Başlığı ve Tanımı
Süreç Soy Ağacı (Process Lineage / Parent-Child Relationship) analizi nedir? Saldırganların meşru işletim sistemi ikili dosyalarını ve betiklerini kötüye kullandığı **LOLBAS (Living-off-the-Land Binaries and Scripts)** teknikleri (örneğin `certutil.exe`, `mshta.exe`, `rundll32.exe`, `wmic.exe`), ebeveyn-çocuk süreç anomalileri üzerinden telemetri düzeyinde nasıl tespit edilir?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Saldırganlar geleneksel güvenlik duvarlarını ve uygulama beyaz listelerini (AppLocker / Windows Defender Application Control) aşmak için Microsoft tarafından dijital olarak imzalanmış meşru sistem araçlarını kullanırlar. Bu teknik MITRE ATT&CK matrisinde *T1218 - System Binary Proxy Execution* olarak adlandırılır.

Karşılaşılan en tehlikeli senaryolar şunlardır:
1. **İkincil İndirme ve Yürütme (Ingress Tool Transfer):** Meşru sertifika aracı olan `certutil.exe`'nin `-urlcache -split -f` parametreleriyle internetten zararlı yazılım indirmek için kullanılması.
2. **Kör Noktadan Kod Çalıştırma:** `mshta.exe` veya `rundll32.exe` üzerinden doğrudan harici bir web adresindeki zararlı HTA veya DLL dosyasının arka planda çalıştırılması.
3. **Office Üzerinden Komut Kabuğu Başlatma:** Bir kullanıcının e-posta ekiyle gelen Word belgesindeki (`WINWORD.EXE`) makronun arka planda `cmd.exe` veya `powershell.exe` başlatarak saldırganın komutlarını işletmesi.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Süreç soy ağacı telemetrisi, her yürütülen sürecin kim tarafından ve hangi komut satırı argümanlarıyla başlatıldığını takip eder:

```text
MEŞRU VE BEKLENEN SOY AĞACI:
explorer.exe (PID: 1004) ──> chrome.exe (PID: 2048)  [NORMAL]
services.exe (PID: 650)  ──> svchost.exe (PID: 880)  [NORMAL]

ANOMALİK VE ZARARLI SOY AĞACI (LOLBAS):
WINWORD.EXE (PID: 3200)  ──> powershell.exe (PID: 4500)  [ALARM: EDR-RULE-001]
                                    │
                                    └── whoami.exe / privs  [KEŞİF]
```

1. **Sysmon Event ID 1 / Windows Event ID 4688 Yapılandırması:**
   - GPO üzerinden `IncludeCommandLineProcessCreation` (Komut satırı argümanlarını loglama) zorunlu kılınmalıdır.
   - Her olayda `ParentProcessName`, `ParentProcessId`, `NewProcessName` ve `CommandLine` alanları kaydedilir.
2. **Kural Tabanlı Anomali Filtreleri:**
   - Ebeveyn Süreç: `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `OUTLOOK.EXE` ise ve Çocuk Süreç: `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe` ise **CRITICAL ALARM ÜRET VE SÜRECİ ÖLDÜR!**
   - Ebeveyn Süreç: `w3wp.exe` (IIS Web Sunucusu) ise ve Çocuk Süreç bir komut kabuğu ise (Web Shell tespiti) anında müdahale et.
3. **Komut Satırı Desen Analizi:**
   - `certutil.exe` komut satırında `http://` veya `https://` ile `-urlcache` parametresi geçiyorsa işlem bloke edilmelidir.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Bir Word belgesinin tek görevi yazı yazmaktır; eğer o Word belgesi arkasından komut satırı (CMD) doğuruyorsa, orada bir kaza değil organize bir komplo vardır!"
- *Altın Kural:* Kurumsal ortamlarda Attack Surface Reduction (ASR) kuralları aktif edilmeli; özellikle *"Block Office applications from creating child processes"* kuralı tavizsiz uygulanmalıdır.

---

### Soru 3: EDR Atlatma (Evasion) Teknikleri (API Unhooking, Direct Syscalls) ve Kernel Düzeyinde Telemetri Bütünlüğü (ETW-TI / eBPF)

#### 1. Soru Başlığı ve Tanımı
Gelişmiş saldırganların EDR sensörlerini körleştirmek için kullandığı **Kullanıcı Alanı Kanca Kaldırma (Userland API Unhooking)** ve **Doğrudan Sistem Çağrıları (Direct Syscalls)** teknikleri nasıl çalışır? EDR mimarileri bu atlatma tekniklerine karşı çekirdek düzeyinde **ETW-TI (Event Tracing for Windows - Threat Intelligence)** ve çekirdek geri çağırma (Kernel Callbacks) mekanizmalarıyla telemetri bütünlüğünü nasıl korur?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Pek çok EDR çözümü, süreçlerin Windows API çağrılarını (örneğin `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) izleyebilmek için her yeni başlatılan sürecin kullanıcı alanı (Userland / Ring 3) belleğindeki `ntdll.dll` kütüphanesine bellek yaması (**Inline Hooking - `JMP` komutları**) yerleştirir.

Gelişmiş saldırganlar bu kullanıcı alanı kancalarını şu tekniklerle etkisiz hale getirir:
1. **Userland Unhooking (Kancaları Temizleme):** Zararlı yazılım, disktengelen temiz `ntdll.dll` dosyasını kendi belleğine okur (`MapViewOfFile`) ve EDR tarafından üzerine `JMP` yazılmış olan `.text` bölümünün üzerine temiz kütüphane kodunu yazar. Böylece EDR kancaları silinir ve EDR körleşir.
2. **Direct Syscalls (Doğrudan Sistem Çağrısı):** Saldırgan `ntdll.dll` fonksiyonlarını hiç çağırmaz. Bunun yerine assembly ile doğrudan CPU'nun `syscall` komutunu işletir. API kancalarından hiç geçilmediği için Ring 3 seviyesindeki EDR bu çağrıyı göremez.
3. **ETW Patching (Olay İzleme Körleştirme):** Süreç belleğindeki `ntdll!EtwEventWrite` fonksiyonunun başına `RET` (`0xC3`) yazılarak Windows olay loglarının SIEM veya EDR'a akması engellenir.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Modern EDR mimarileri, kullanıcı alanı (Ring 3) manipüle edilebildiği için asla yalnızca `ntdll.dll` kancalarına güvenmez; çekirdek (Ring 0) seviyesinde güven inşa eder:

```text
SALDIRGANIN ATLATMA GİRİŞİMİ (Ring 3 / Kullanıcı Alanı):
[Zararlı Kod] ──(Direct Syscall / Kancayı Baypas Eder)──> [CPU: syscall]
                                                               │
                                                               ▼ (Çekirdeğe Geçiş)
EDR'IN ÇEKİRDEK SAVUNMASI (Ring 0 / Kernel Alanı):
[Windows Kernel (ntoskrnl.exe)]
         │
         ├── 1. ETW-TI (Threat Intelligence Provider):
         │      Çekirdek doğrudan sistem çağrısını loglar (Kullanıcı alanı kancası gerekmez!)
         ├── 2. Kernel Callbacks:
         │      PsSetCreateProcessNotifyRoutineEx / ObRegisterCallbacks
         │      Tanıtıcı (Handle) seviyesinde koruma: Bellek açılsa bile LSASS erişimi engellenir.
         └── 3. Call Stack Telemetrisi:
                Syscall çağrısının ntdll dışından geldiği tespit edilirse anında ALARM üretilir.
```

1. **ETW-TI (Event Tracing for Windows - Threat Intelligence):**
   - Microsoft tarafından yalnızca dijital olarak imzalanmış EDR sürücülerine (Early Launch Anti-Malware - ELAM) sunulan özel çekirdek telemetri sağlayıcısıdır.
   - Doğrudan çekirdek içinde çalıştığı için kullanıcı alanında yapılan unhooking veya doğrudan syscalls çağrılarından etkilenmez; çekirdeğe ulaşan her işlemi tarafsız olarak kaydeder.
2. **Call Stack Spoofing ve Yığın Analizi:**
   - EDR çekirdek sürücüsü, bir sistem çağrısı geldiğinde çağrı yığınını (Call Stack) inceler. Çağrı meşru bir `ntdll.dll` adresinden değil de bilinmeyen bir bellek bölgesinden veya doğrudan çalıştırılabilir alandan geliyorsa bu bir Direct Syscall anomalisidir ve süreç durdurulur.
3. **Linux Ortamında eBPF ile Çekirdek Güvencesi:**
   - Linux'ta `ptrace` veya `LD_PRELOAD` gibi kullanıcı alanı kancaları yerine, eBPF programları doğrudan `kprobe`, `tracepoints` ve `LSM (Linux Security Module)` kancalarına takılarak çekirdek seviyesinde tarafsız telemetri toplar.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Kullanıcı alanı (Userland) saldırganın oyun bahçesidir; oradaki kancanı temizleyebilir. Ama çekirdek (Kernel) kralın sarayıdır. Gerçek EDR, nöbetini bahçede değil sarayın kapısında (çekirdekte) tutar!"
- *Altın Kural:* Kurumsal EDR seçiminde ajanın ELAM (Early Launch Anti-Malware) sertifikasına sahip olduğu ve telemetrisini kullanıcı alanı kancalarından değil, doğrudan ETW-TI ve çekirdek geri çağırmalarından (Kernel Callbacks) topladığı doğrulanmalıdır.
