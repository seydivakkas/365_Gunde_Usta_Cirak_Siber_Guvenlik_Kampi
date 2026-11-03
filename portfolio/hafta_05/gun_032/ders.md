# GÜN 32: BAŞLANGIÇ UYGULAMALARI VE HİZMET YÖNETİMİ
## Usta-Çırak / Hoca Dersi Notları

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, dağıtılamaz, ticari amaçla kullanılamaz.
```

---

### 1. Giriş ve Temel Pedagojik Yaklaşım: Çırağa Öğüt
Evlat, siber güvenlik dünyasında bir saldırganın hedef sistemde tutunabilmesi için en kritik aşama **Kalıcılık (Persistence)** aşamasıdır. Bir sunucuda veya kullanıcı iş istasyonunda ne kadar sofistike bir zero-day zafiyeti istismar edersen et, sistem yeniden başlatıldığında (reboot) kodun tekrar ayağa kalkmıyorsa veya arka planda sessiz sedasız çalışan bir hizmet haline gelemiyorsa operasyonun çöker.

İşte bu yüzden başlangıç uygulamaları (startup items) ve işletim sistemi servisleri (services/daemons), hem saldırganın en gözde mevzisi hem de mavi takım (SOC analisti, tehdit avcısı, DFIR uzmanı) için en zengin av sahasıdır.

Bugün seninle şu temel gerçeği iliklerimize kadar işleyeceğiz:
> **"Otomatik başlayan uygulamalar ve servisler sistem saldırı yüzeyini doğrudan büyütür; fakat gerekli hizmetler internetteki kulaktan dolma 'sistemi hızlandırma' rehberleriyle gelişigüzel kapatılamaz."**

---

### 2. Başlangıç Mekanizmaları: Nereden Başlarlar?

İşletim sistemleri kullanıcı oturumu açılmadan önce ve oturum açıldıktan sonra yazılımları otomatik çalıştırmak için sayısız kayıt defteri anahtarı, dizin ve zamanlama mekanizması barındırır.

#### A. Windows Kayıt Defteri Otomatik Başlatma Noktaları (Run Keys)
Windows ortamında en yaygın kullanılan kalıcılık konumları şunlardır:
1. **HKLM (Local Machine - Tüm Kullanıcılar):**
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` (Bir kez çalışır, ardından kayıt silinir)
   - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` (32-bit uygulamalar için)
2. **HKCU (Current User - Aktif Kullanıcı):**
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
3. **Kullanıcı Başlangıç Klasörleri:**
   - Ortak: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
   - Kullanıcıya Özel: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (`shell:startup`)
4. **Gelişmiş Başlangıç Noktaları (Winlogon & WMI):**
   - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
   - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` (Normalde `explorer.exe`)
   - WMI Event Filters & Event Consumers (`CommandLineEventConsumer`).

#### B. Linux Başlangıç ve Otomatik Çalıştırma Noktaları
Linux sistemlerde ise süreç yönetimi ve başlangıç mekanizmaları şu konumlarda şekillenir:
1. **systemd Unit Dosyaları:**
   - Sistem birimleri: `/lib/systemd/system/` veya `/usr/lib/systemd/system/`
   - Yönetici yapılandırmaları: `/etc/systemd/system/` (Yerel geçersiz kılmalar burada yer alır)
2. **Zamanlanmış Görevler (cron / anacron):**
   - `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`
   - Kullanıcı spool dizinleri: `/var/spool/cron/crontabs/<kullanıcı>`
3. **Kullanıcı Kabuk Betikleri (Shell Initialization):**
   - Global: `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc`
   - Kullanıcı: `~/.bashrc`, `~/.bash_profile`, `~/.profile`

---

### 3. Windows Hizmetleri (Services) ve Hizmet Denetim Yöneticisi (SCM)

Windows işletim sisteminde arka plan görevlerini, donanım sürücülerini ve ağ protokollerini yürüten süreçlere **Hizmet (Service)** denir. Hizmetleri yöneten ana çekirdek süreç `services.exe` (Service Control Manager - SCM) sürecidir.

#### A. Hizmet Başlatma Türleri (Startup Types)
SCM, servislerin ne zaman ve nasıl başlayacağını şu kiplerle belirler:
- **Otomatik (Automatic):** Sistem açılışında, oturum açılmasını beklemeden derhal başlar.
- **Otomatik - Gecikmeli (Automatic - Delayed Start):** Sistemin açılış performansını düşürmemek için çekirdek servislerden 1-2 dakika sonra başlatılır.
- **Elle (Manual):** Bir kullanıcı veya başka bir uygulama/servis ihtiyaç duyup tetiklediğinde başlar.
- **Devre Dışı (Disabled):** Hizmet hiçbir koşulda başlatılamaz; tetiklense dahi SCM yürütmeyi reddeder.

#### B. Hizmet Güvenlik Bağlamları ve Hesaplar (Service Accounts)
Servislerin hangi yetkiyle çalıştığı, sistem güvenliği açısından hayati öneme sahiptir:
1. **NT AUTHORITY\SYSTEM (LocalSystem):**
   İşletim sistemindeki en yetkili hesaptır. Çekirdek (Kernel) seviyesine yakın ayrıcalıklara sahiptir; yerel kayıt defteri, dosya sistemi ve bellek üzerinde sınırsız yetkisi vardır. Bir servis saldırgan tarafından bu hesap altında istismar edilirse tam sistem ele geçirilir.
2. **NT AUTHORITY\LocalService:**
   En az ayrıcalık (Least Privilege) ilkesine uygun yerel hesaptır. Ağ üzerinde anonim kimlikle gezinir.
3. **NT AUTHORITY\NetworkService:**
   Ağ üzerindeki diğer Windows makinelerine bilgisayar hesabı (`DOMAIN\MACHINE$`) olarak kimlik doğrulaması yapabilen yetkilendirilmiş hesaptır.
4. **Sanal Hesaplar ve gMSA (Group Managed Service Accounts):**
   Kurumsal ortamlarda otomatik parola rotasyonu sağlayan modern ve güvenli servis hesaplarıdır.

---

### 4. Gelişigüzel Hizmet Kapatmanın Tehlikeleri

Usta bir sistem yöneticisi ve güvenlikçi asla internetteki "10 adımda Windows'u uçurun" videolarına kanmaz. Servisler birbirinden bağımsız izole kutular değildir; aralarında karmaşık bir **Bağımlılık (Dependency) Ağacı** bulunur.

- **Örnek 1:** `Remote Procedure Call (RPCSS)` servisini kapatırsan Windows Gezgini, COM nesneleri ve ağ iletişimi anında kilitlenir.
- **Örnek 2:** `Windows Event Log (EventLog)` servisini "kaynak tasarrufu" bahanesiyle kapatırsan, işletim sistemindeki tüm güvenlik loglama mekanizması felç olur; sisteme sızan bir saldırgan arkasında hiçbir log izi bırakmadan hareket eder.
- **Örnek 3:** `Windows Defender Antivirus (WinDefend)` veya `Windows Firewall (MpsSvc)` servislerini durdurursan, saldırganın lateral movement (yatayda yayılma) yapması çocuk oyuncağı haline gelir.

---

### 5. Saldırı Vektörleri ve Yetki Yükseltme Mekanizmaları

#### A. Tırnaksız Servis Yolu (Unquoted Service Path - MITRE ATT&CK T1574.009)
Windows API'sinde yer alan `CreateProcess` fonksiyonu, parametre olarak verilen yürütülebilir dosya yolu çift tırnak (`"..."`) içerisine alınmadığında ve yolda boşluk (space) karakteri bulunduğunda, her boşluk karakterini potansiyel bir argüman ayracı olarak yorumlar.

Diyelim ki bir yedekleme yazılımı şu yolla kaydedilmiş:
`C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe -daemon`

Hizmet Denetim Yöneticisi (SCM), bu yolu yürütürken tırnak görmediği için dosya sisteminde sırasıyla şu ikilileri arar:
1. `C:\Program.exe`
2. `C:\Program Files\Vulnerable.exe`
3. `C:\Program Files\Vulnerable Backup\Solution\BackupAgent.exe`
4. `C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe`

Eğer standart bir kullanıcı (örneğin kısıtlı bir kullanıcı hesabı), `C:\` kök dizinine veya `C:\Program Files\` altına dosya yazma yetkisine sahipse, oraya zararlı kodunu `Program.exe` adıyla bırakır. Sistem yeniden başlatıldığında, SCM bu zararlıyı **NT AUTHORITY\SYSTEM** yetkisiyle çalıştırır! Bu durum ders kitaplarına geçmiş bir **Yerel Yetki Yükseltme (Local Privilege Escalation - LPE)** zafiyetidir.

#### B. İsim Sahteciliği ve Benzetme (Masquerading / Typosquatting - MITRE ATT&CK T1036)
Saldırganlar güvenlik yazılımlarını ve göz ucuyla inceleme yapan analistleri aldatmak için meşru sistem süreçlerinin isimlerini taklit ederler:
- `svchost.exe` yerine `svch0st.exe` (sıfır harfi ile)
- `lsass.exe` yerine `lsasss.exe`
- Meşru `svchost.exe` dosyasını `C:\Windows\System32\` yerine `C:\Windows\Temp\` veya `C:\Users\Public\` altına kopyalayıp servis olarak kaydetmek.

#### C. Savunmayı Zayıflatma (Impair Defenses - MITRE ATT&CK T1562.001)
Saldırgan sisteme yerleştikten sonra ilk iş olarak güvenlik servislerini hedef alır:
```powershell
# Windows Defender ve Güvenlik Duvarı servislerini devre dışı bırakma girişimleri:
sc.exe config WinDefend start= disabled
sc.exe stop WinDefend
sc.exe config MpsSvc start= disabled
sc.exe stop MpsSvc
```
Bu anormallik derhal tespit edilmeli ve alarm üretilmelidir.

---

### 6. Tespit, Denetim ve Savunma Prensipleri

1. **Sysinternals Autoruns ile Derin Tarama:**
   Standart Görev Yöneticisi yalnızca buzdağının görünen yüzünü listeler. Microsoft Sysinternals Autoruns aracı; Run anahtarları, Explorer eklentileri, AppInit DLL'leri, Image Hijacks, Winlogon, SchedTasks ve SCM servislerini tek bir ekranda toplayıp dijital imza ve VirusTotal taramasına tabi tutar.
2. **Kural: Tırnaksız Servis Yollarını Otomatik Düzeltin:**
   Tüm üçüncü taraf yazılım servisleri taranmalı, boşluk içeren ve tırnaksız bırakılmış yollar çift tırnak içerisine alınmalıdır:
   ```cmd
   sc.exe config "VulnBackupService" binPath= "\"C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe\" -daemon"
   ```
3. **En Az Ayrıcalık (Least Privilege):**
   Bir servis kesinlikle kernel erişimi gerektirmiyorsa asla `SYSTEM` hesabı ile koşturulmamalı; `LocalService` veya özel bir servis hesabı atanmalıdır.
4. **EDR ve Dosya Bütünlüğü İzleme (FIM):**
   Kayıt defterindeki `Run` anahtarlarına ve `services` tablosuna yazma girişimleri EDR ajanları tarafından gerçek zamanlı izlenmeli, onaylanmamış her yeni başlangıç girdisi bloklanmalıdır.

---

### Resmî Kaynaklar
- Microsoft Learn: [Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- Microsoft Sysinternals: [Autoruns for Windows](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- MITRE ATT&CK: [T1574.009 - Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009/)
- MITRE ATT&CK: [T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
