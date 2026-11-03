# Gün 127: Soru & Cevap — Uç Nokta Tehdit Modeli

---

### Soru 1: Windows uç noktalarda LSASS Bellek Dökümü Saldırıları (Credential Dumping - CWE-311 / MITRE T1003.001) nasıl gerçekleşir ve RunAsPPL ile Credential Guard bu süreci çekirdek düzeyinde nasıl bloke eder?

#### 1. Soru Başlığı ve Tanımı
Windows işletim sistemlerinde `lsass.exe` (Local Security Authority Subsystem Service), kullanıcı oturum açma kimlik bilgilerini, Kerberos biletlerini ve NTLM özetlerini belleğinde barındıran kritik bir güvenlik sürecidir. Saldırganların yerel yönetici yetkisi elde ettikten sonra ilk başvurduğu yöntem, LSASS sürecinin bellek alanını dökerek (Memory Dump) bu parolaları ve biletleri ele geçirmektir (CWE-311 / MITRE T1003.001).

#### 2. Derinlemesine Teknik Analiz
1. **Saldırı Mekanizması:**
   - Standart bir yönetici süreci (`SeDebugPrivilege` ayrıcalığına sahip), Windows API'si olan `OpenProcess` çağrısı ile LSASS sürecine `PROCESS_VM_READ` veya `PROCESS_ALL_ACCESS` yetkisiyle bağlanır.
   - Ardından `MiniDumpWriteDump` fonksiyonu kullanılarak LSASS belleği bir `.dmp` dosyasına yazılır.
   - Mimikatz, Pypykatz veya comsvcs.dll gibi araçlar bu bellek dökümünü ayrıştırarak aktif oturumların düz metin parolalarını (WDigest), NTLM özetlerini ve Kerberos TGT/TGS biletlerini çeker.
2. **RunAsPPL (Protected Process Light) Savunması:**
   - Windows 8.1 / Server 2012 R2 ile gelen bu özellik, LSASS sürecini "Korumalı Süreç (PPL)" olarak işaretler.
   - PPL modundaki bir sürece, kendisi de Microsoft tarafından dijital olarak imzalanmış bir PPL süreci olmadığı sürece hiçbir harici süreç (yönetici olsa dahi) `PROCESS_VM_READ` yetkisiyle erişemez. Çekirdek (Kernel), erişim talebini `ACCESS_DENIED` ile reddeder.
3. **Credential Guard (VBS Mimarisi):**
   - Donanım Sanallaştırması (Virtualization Based Security - VBS) ve Hyper-V hipervizörünü kullanarak izole bir sanal alan (Virtual Secure Mode - VSM / LSAIso.exe) yaratır.
   - Kerberos anahtarları ve NTLM özetleri ana işletim sisteminin bellek alanından tamamen çıkarılarak bu yalıtılmış hipervizör konteynerine taşınır.
   - Ana işletim sistemi çekirdeği (Ring 0) tamamen ele geçirilse bile, hipervizör katmanındaki VSM belleğine erişilemez.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir üretim firmasında saldırgan, oltalama e-postasıyla bir mühendisin bilgisayarına sızmış ve yerel bir zafiyetle Local Administrator olmuştur. Bilgisayarda LSA Protection açık olmadığı için saldırgan PowerShell üzerinden `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump` komutunu çalıştırarak LSASS dökümünü almış; o sırada bilgisayara bakım için oturum açmış olan Domain Admin'in NTLM özetini çalarak Pass-the-Hash yöntemiyle tüm Active Directory yapısını şifrelemiştir.
**Pratik Çözüm:**
Kurumsal GPO üzerinden RunAsPPL ve Credential Guard zorunlu kılınır:
```powershell
# RunAsPPL Etkinleştirme Kayıt Defteri Anahtarı
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

# Credential Guard Etkinleştirme
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord
```

#### 4. Ustanın Çırağa Tavsiyesi
Bir Windows makinesinde LSASS korumasızsa, o makinede yerel yönetici olan herkes aslında tüm domain'in yöneticisidir. Credential Guard ve RunAsPPL senin ilk savunma hattındır; yeni kurduğun her Windows sisteminde bu iki kilidi açmadan bilgisayarı kullanıcıya teslim etme!

---

### Soru 2: Tırnaksız Servis Yolları (Unquoted Service Paths - CWE-428 / MITRE T1574.009) ve Linux SUID İkili Dosyaları (CWE-250 / MITRE T1548.001) üzerinden Yetki Yükseltme (Privilege Escalation) mekanizması nasıl çalışır?

#### 1. Soru Başlığı ve Tanımı
Yetki Yükseltme (Privilege Escalation), kısıtlı kullanıcı yetkilerine sahip bir saldırganın, işletim sistemindeki veya kurulu üçüncü parti yazılımlardaki yapılandırma hatalarını kullanarak en yüksek yetkili kullanıcıya (`NT AUTHORITY\SYSTEM` veya `root`) dönüşmesidir (CWE-428 / CWE-250).

#### 2. Derinlemesine Teknik Analiz
1. **Windows Tırnaksız Servis Yolları (CWE-428):**
   - Windows Servis Yöneticisi (SCM), bir servis başlatırken `ImagePath` kayıt defteri değerini ayrıştırır.
   - Eğer yol `C:\Program Files\Vendor Tools\agent.exe` şeklinde tırnaksızsa, boşluk karakteri parametre ayracı olarak kabul edilir.
   - Windows sırasıyla şu yollarda yürütülebilir dosya arar:
     1. `C:\Program.exe`
     2. `C:\Program Files\Vendor.exe`
     3. `C:\Program Files\Vendor Tools\agent.exe`
   - Eğer standart kullanıcının `C:\` köküne veya `Vendor` klasörüne yazma izni varsa, buraya `Program.exe` adıyla kendi zararlı dosyasını koyar. Sistem yeniden başladığında servis bu zararlıyı çalıştırır ve saldırgan SYSTEM haklarına kavuşur.
2. **Linux SUID İkili Dosyaları (CWE-250):**
   - Linux dosya sisteminde 4000 biti (`chmod 4755`) atanmış bir ikili dosya, hangi kullanıcı tarafından çağrılırsa çağrılsın dosya sahibi (örneğin root) yetkileriyle yürütülür.
   - Eğer bir sistem yöneticisi veya yazılım paketi `find`, `vim`, `python`, `nmap` veya `bash` gibi dosya okuma/yazma veya kabuk açma yeteneği olan araçlara SUID biti vermişse:
     - Örnek: `/usr/bin/find . -exec /bin/sh -p \; -quit` komutu doğrudan root ayrıcalıklı bir kabuk açar (GTFOBins tekniği).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir veri analitiği sunucusunda geliştirici, yedekleme scriptini çalıştırmak için `/usr/bin/python3` ikili dosyasına SUID biti vermiştir (`chmod u+s /usr/bin/python3`). Sunucuya sızan düşük yetkili bir stajyer hesabı, komut satırından `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` komutunu çalıştırarak anında root olmuş ve tüm müşteri veritabanı yedeğini silmiştir.
**Pratik Çözüm:**
- **Windows Çözümü:** Kayıt defterindeki tüm servis yolları tırnak içine alınır:
  ```powershell
  Get-CimInstance win32_service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } | ForEach-Object {
      # Tırnaksız servisleri tespit et ve düzelt
  }
  ```
- **Linux Çözümü:** SUID biti taşıyan anormal dosyalar denetlenir ve kaldırılır:
  ```bash
  find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
  chmod u-s /usr/bin/python3
  ```

#### 4. Ustanın Çırağa Tavsiyesi
Yetki yükseltme açıklarının %90'ı sıfır gün (0-day) açığı değildir; tembel yöneticilerin "tırnak koymayı unuttuğu" veya "kolaylık olsun diye SUID bastığı" basit dikkatsizliklerdir. Sisteminde çalışan her servisin yolunu tırnakla kilitle, Linux'ta kabuk açabilen hiçbir araca SUID biti verme!

---

### Soru 3: Gelişmiş Tehdit Atlatma (Defense Evasion - MITRE T1562.001) saldırılarına karşı EDR Kurcalama Koruması (Tamper Protection) ve Derin Uç Nokta Telemetrisi (Sysmon/Auditd) nasıl entegre edilmelidir?

#### 1. Soru Başlığı ve Tanımı
Gelişmiş saldırganlar ve modern fidye yazılımları (Ransomware), uç noktaya ayak bastıktan hemen sonra ilk iş olarak güvenlik savunmalarını felç etmeye çalışırlar (Defense Evasion). EDR servislerini durdurmak, antivirüs sürücülerini bellekten kaldırmak ve olay günlüklerini silmek en yaygın atlatma taktikleridir (MITRE T1562.001 / T1070).

#### 2. Derinlemesine Teknik Analiz
1. **EDR Kurcalama Koruması (Tamper Protection):**
   - Geleneksel antivirüs servisleri, yerel yönetici (Administrator/root) yetkilerine sahip bir kullanıcı tarafından `net stop` veya `systemctl stop` komutlarıyla kolayca durdurulabilir.
   - Kurcalama Koruması açık olduğunda; EDR ajanının çekirdek sürücüsü (Kernel Driver / Early Launch Anti-Malware - ELAM), işletim sistemi API'lerine filtre kancası atar. Yerel yönetici dahi olsa EDR süreçlerini sonlandırmaya, servis ayarlarını değiştirmeye veya kayıt defteri anahtarlarını silmeye yönelik tüm çağrılar çekirdek seviyesinde engellenir. Bu koruma sadece merkezi bulut konsolundan yetkili güvenli parola ile açılabilir.
2. **Derin Uç Nokta Telemetrisi (Sysmon / Auditd - CWE-778):**
   - Windows Olay Günlükleri standart haliyle sadece temel bilgileri tutar. Sysmon (System Monitor) ise çekirdek sürücüsü düzeyinde çalışarak:
     - **Event ID 1:** Süreç oluşturma (komut satırı argümanları, parent-child PID ilişkisi, dosya hash'i).
     - **Event ID 3:** Ağ bağlantısı (kaynak/hedef IP ve port, bağlantıyı açan süreç).
     - **Event ID 10:** Süreç erişimi (Process Injection ve LSASS bellek erişimi denemeleri).
     - **Event ID 11:** Dosya oluşturma ve fidye yazılımı uzantı değişiklikleri.
   - Linux tarafında `auditd` kural seti ile `/etc/passwd`, `/etc/shadow` ve `execve` sistem çağrıları izlenerek SIEM/SOC merkezine gerçek zamanlı beslenir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir sağlık kuruluşuna sızan BlackCat fidye yazılımı çetesi, yerel yönetici parolasıyla sunucuya bağlanmış; EDR üzerinde Kurcalama Koruması kapalı olduğu için `sc config EDRService start=disabled` komutuyla EDR'ı kapatmış ve ardından `wevtutil cl Security` komutuyla tüm güvenlik loglarını silerek 30 dakika içinde 100 terabaytlık veriyi şifrelemiştir.
**Pratik Çözüm:**
1. Merkezi yönetimden Tamper Protection kesinlikle kilitlenir.
2. Sysmon ve WEF (Windows Event Forwarding) ile loglar uç noktada depolanmak yerine anlık olarak SIEM'e (veya izole log sunucusuna) WEC ile iletilir:
```powershell
# Sysmon Kurulumu ve SwiftOnSecurity Kural Seti ile Başlatma
sysmon.exe -i -accepteula sysmonconfig-export.xml
```
Saldırgan yerel logu silse bile log kopyası milisaniyeler içinde SIEM'e ulaştığı için SOC analisti saldırıyı anında tespit eder.

#### 4. Ustanın Çırağa Tavsiyesi
Koruması olmayan muhafız, ilk vurulacak hedeftir. EDR kurup Tamper Protection'ı açmamak, nöbetçiye çelik yelek giydirmeden savaşa sürmek gibidir. Telemetriyi öyle sıkı tut ki, saldırgan klavyede tek bir tuşa bassa bile arkasında silinemez bir ayak izi kalsın!
