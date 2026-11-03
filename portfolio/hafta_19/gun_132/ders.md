# GÜN 132: Windows Hizmet Güvenliği ve Servis Yetki Yükseltme Savunması

## Usta-Çırak / Hoca Dersi: Service Control Manager ve Ayrıcalık Koruması

Hoş geldin evlat. Windows sistem güvenliğinde en ölümcül ayrıcalık yükseltme (Privilege Escalation) vektörlerinin kalbine geldik: **Windows Servisleri (Windows Services)**. 

Bir saldırgan bir makinede düşük yetkili bir kullanıcı (`BUILTIN\Users`) olarak ayak bastığında ilk baktığı yer hizmetlerdir. Çünkü hizmetler çoğunlukla işletim sisteminin en yüksek yetkili kimliği olan `NT AUTHORITY\SYSTEM` (veya `LocalSystem`) altında arka planda çalışır. Eğer bir servis yanlış yapılandırılmışsa, saldırgan tek bir komutla makinenin mutlak hakimi haline gelir.

Bugün seninle Service Control Manager (SCM) çekirdeğini, SDDL ile yazılan servis DACL tablolarını, tırnaksız servis yollarını (Unquoted Service Path) ve servis sıkılaştırma (Service Hardening) prensiplerini santim santim inceleyeceğiz.

---

### 1. Service Control Manager (SCM) ve Hizmet Mimarisi

Windows'ta servislerin yönetimi `C:\Windows\System32\services.exe` yani **Service Control Manager (SCM)** tarafından yürütülür. Sistem açılışında `wininit.exe` tarafından başlatılan SCM, bir RPC (Remote Procedure Call) sunucusu olarak davranır.

SCM'nin temel görevleri:
1. **Veritabanı Bakımı:** Yüklü tüm hizmetlerin durumunu, bağımlılıklarını ve güvenlik tanımlayıcılarını bellekte tutar.
2. **Servisleri Başlatma ve Denetleme:** Servisleri `CreateProcessAsUserW` API'si ile hedef güvenlik bağlamında (Security Context) ayağa kaldırır.
3. **Kayıt Defteri Entegrasyonu:** Tüm servis metaverileri şu anahtar altında saklanır:
   ```text
   HKLM\SYSTEM\CurrentControlSet\Services\<HizmetAdı>
   ```
   Bu anahtar altındaki kritik değerler:
   - `ImagePath` (REG_EXPAND_SZ): Servisin çalıştıracağı binary yolu ve parametreleri.
   - `ObjectName` (REG_SZ): Servisin hangi hesapla çalışacağı (Örn: `LocalSystem`, `NT AUTHORITY\LocalService`, `NT SERVICE\<HizmetAdı>`).
   - `Start` (REG_DWORD): Başlangıç türü (0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled).
   - `Security` (REG_BINARY): Servisin ikili formatta saklanan Güvenlik Tanımlayıcısı (Security Descriptor).
   - `RequiredPrivileges` (REG_MULTI_SZ): Servis sürecine verilecek minimum Windows ayrıcalıkları.

---

### 2. Tırnaksız Servis Yolu Zafiyeti (Unquoted Service Path - CWE-428 / MITRE ATT&CK T1574.009)

Evlat, bu zafiyet Windows'un geriye dönük uyumluluk (backward compatibility) için 1990'lardan bu yana taşıdığı bir komut satırı çözümleme mantığından doğar.

Eğer bir servis yolu tırnak içine alınmamışsa ve yolunda boşluk (space) varsa:
```text
C:\Program Files\Kurumsal Yedekleme\backup_agent.exe -run
```
Windows `CreateProcess` fonksiyonu çağrıldığında ilk argüman tırnak içinde değilse, işletim sistemi boşlukları parametre ayracı zannedebilir. Bu nedenle Windows dosyayı sırayla şu kombinasyonlarda arar:
1. `C:\Program.exe` (Çalışırsa parametre: `Files\Kurumsal Yedekleme\backup_agent.exe -run`)
2. `C:\Program Files\Kurumsal.exe` (Çalışırsa parametre: `Yedekleme\backup_agent.exe -run`)
3. `C:\Program Files\Kurumsal Yedekleme\backup_agent.exe` (Asıl dosya)

**Saldırı Senaryosu:**
Eğer standart kullanıcı `C:\` kök dizinine veya `C:\Program Files\` dizinine dosya yazma hakkına sahipse, buraya `Program.exe` adında zararlı bir binary bırakır. Servis `LocalSystem` olarak başladığında Windows doğrudan `C:\Program.exe`'yi SYSTEM haklarıyla çalıştırır!

**Savunma:**
Servis yolları daima çift tırnak (`"`) içerisine alınmalıdır:
```cmd
sc.exe config "KurumsalYedekleme" binPath= "\"C:\Program Files\Kurumsal Yedekleme\backup_agent.exe\" -run"
```

---

### 3. Servis Güvenlik Tanımlayıcıları (Service DACL / SDDL - CWE-732 / MITRE ATT&CK T1543.003)

Nasıl ki dosya ve klasörlerin bir DACL'ı varsa, SCM içerisindeki her servisin de kendine ait bir **Service DACL (Discretionary Access Control List)** tablosu vardır.

Bir servisin izinleri `sc.exe sdshow <HizmetAdı>` komutuyla SDDL formatında görüntülenir:
```text
sc.exe sdshow Spooler
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

**SCM SDDL İzin Haritası:**
- `CC` : `SERVICE_QUERY_CONFIG` (0x0001) - Servis ayarlarını okuma (Güvenli, okuma amaçlı).
- `DC` : `SERVICE_CHANGE_CONFIG` (0x0002) - Servis yapılandırmasını değiştirme (**Kritik Tehlike!**).
- `LC` : `SERVICE_QUERY_STATUS` (0x0004) - Servis durumunu sorgulama.
- `RP` : `SERVICE_START` (0x0010) - Servisi başlatma.
- `WP` : `SERVICE_STOP` (0x0020) - Servisi durdurma.
- `WD` : `WRITE_DAC` (0x00040000) - Servisin erişim izinlerini değiştirme (**Kritik Tehlike!**).
- `WO` : `WRITE_OWNER` (0x00080000) - Servis sahipliğini alma (**Kritik Tehlike!**).

**Ölümcül Hata:**
Eğer bir sistem yöneticisi veya dikkatsiz bir yazılım yükleyicisi `BUILTIN\Users` (`BU`) veya `Everyone` (`WD`) grubuna `DC` (`SERVICE_CHANGE_CONFIG`) yetkisi verirse:
Standart kullanıcı komut satırından şunu yazar:
```cmd
sc config ZayifServis binPath= "cmd.exe /c net localgroup Administrators saldirgan /add"
sc stop ZayifServis
sc start ZayifServis
```
Servis yeniden başladığında saldırgan anında Yerel Yönetici (Local Administrator) grubuna eklenir!

---

### 4. Zayıf Servis İkili Dosya İzinleri (Weak Service Binary Permissions - CWE-732 / MITRE ATT&CK T1574.010)

Servisin SCM izinleri sıkı olsa bile, servisin çağırdığı `.exe` veya onun dinamik yüklediği DLL'lerin bulunduğu klasörde standart kullanıcılara `Modify` veya `Write` yetkisi verilmiş olabilir.

Saldırgan dosyanın adını `service_backup.exe` yapar, kendi zararlı yazılımını `service.exe` olarak yerleştirir. Servis yeniden başlatıldığında veya makine yeniden başladığında (reboot) kod SYSTEM olarak koşar.

**Savunma (icacls ile Kilitleme):**
```cmd
icacls "C:\Program Files\App\service.exe" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)"
```

---

### 5. En Az Ayrıcalık Prensibi ve Modern Servis Hesapları (CWE-250)

Evlat, Windows'un eski sürümlerinde her uygulama kolaylık olsun diye `LocalSystem` hesabıyla kurulurdu. Bu devir kapandı.

| Hesap Türü | Ağ Erişimi | Yerel Yetki | Kullanım Alanı |
|---|---|---|---|
| **LocalSystem (`SYSTEM`)** | Makine hesabı (`DOMAIN\HOST$`) | Mutlak (Sistem Çekirdeği) | Sadece işletim sistemi çekirdek servisleri |
| **NetworkService** | Makine hesabı (`DOMAIN\HOST$`) | Sınırlı kullanıcı yetkisi | Ağa erişmesi gereken standart servisler |
| **LocalService** | Anonim / Ağ erişimi yok | Sınırlı kullanıcı yetkisi | Ağ erişimi gerekmeyen yerel arka plan işleri |
| **Virtual Account (`NT SERVICE\<Ad>`)** | Makine hesabı | Servise özel izole SID | Modern yerel servis yalıtımı |
| **gMSA (Group Managed Service Account)**| Kerberos / Active Directory | Otomatik parola yönetimi | Kurumsal ve çok düğümlü dağıtık servisler |

Üçüncü parti hiçbir yazılımın `LocalSystem` ile çalışmasına izin verme. Servisleri sanal hesaplar (`NT SERVICE`) veya gMSA ile sınırla.

Ayrıca servisin kayıt defterindeki `RequiredPrivileges` değerini incele; bir web servisinin `SeDebugPrivilege` veya `SeTcbPrivilege` hakkı talep etmesi doğrudan bir kırmızı bayraktır.

---

### 6. CIS Windows Benchmark Uyarınca Kapatılması Gereken Servisler

Kurumsal sıkılaştırma rehberlerinde saldırı yüzeyini küçültmek için gereksiz servisler devre dışı bırakılmalıdır:
1. `RemoteRegistry`: Ağ üzerinden kayıt defterine erişimi engellemek için `Disabled` yapılmalıdır.
2. `RemoteAccess`: Yönlendirme ve VPN hizmeti sunulmuyorsa kapatılmalıdır.
3. `Xbox*` Servisleri: Kurumsal sunucularda oyun telemetrisi barındırılamaz.
4. `TapiSrv` & `PNRPsvc`: Eski ve kullanılmayan protokol zafiyetlerini önlemek için kapatılmalıdır.

---

### Ustanın Çırağa Öğüdü
> *"Evlat, bir sistemde en yüksek yetkili hesap `LocalSystem`'dır; ama o hesabı yöneten şey bir metin dizgisinden (ImagePath) ve bir izin tablosundan (DACL) ibarettir. Tırnağı unutursan yolunu çalarlar, DACL'ı gevşetirsen tahtını devirirler. Servisleri en az ayrıcalıkla izole et, dosya izinlerini kilit altında tut!"*
