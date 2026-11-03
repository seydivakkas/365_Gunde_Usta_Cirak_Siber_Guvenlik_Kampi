# GÜN 132: Windows Hizmet Güvenliği Soru-Cevap ve Derinlemesine Analiz

## Soru 1: Tırnaksız Servis Yolu (Unquoted Service Path - CWE-428) Zafiyeti Neden Oluşur ve Windows Çözümleme Mantığı Nasıl Suiistimal Edilir?

### 1. Soru Başlığı ve Tanımı
Tırnaksız Servis Yolu (Unquoted Service Path - CWE-428 / MITRE ATT&CK T1574.009), Windows işletim sisteminde çalışan bir hizmetin yürütülebilir dosya yolu (`ImagePath` veya `binPath`) içerisinde boşluk karakterleri barındırmasına rağmen çift tırnak (`"`) içine alınmaması sonucu oluşan kritik bir yerel yetki yükseltme (Privilege Escalation) zafiyetidir.

### 2. Derinlemesine Teknik Analiz
Windows API'sinde süreç oluşturan temel fonksiyon `CreateProcess` (ve Service Control Manager tarafından kullanılan türevi `CreateProcessAsUser`) çağrıldığında, `lpApplicationName` parametresi `NULL` geçilirse işletim sistemi komut satırını `lpCommandLine` parametresi üzerinden ayrıştırır.

Eğer yol çift tırnak ile sınırlandırılmamışsa, işletim sistemi boşluk karakterini argüman ayracı olarak yorumlar. Örneğin:
`C:\Program Files\Enterprise Vendor\agent.exe` yolu için Windows sırasıyla şu aday yolları var mı diye kontrol eder:
1. `C:\Program.exe` (Argümanlar: `Files\Enterprise Vendor\agent.exe`)
2. `C:\Program Files\Enterprise.exe` (Argümanlar: `Vendor\agent.exe`)
3. `C:\Program Files\Enterprise Vendor\agent.exe` (Hedef dosya)

Eğer saldırganın `C:\` veya `C:\Program Files\` dizininde yazma izni varsa (veya bu dizinlerin ACL'lerinde gevşek izinler bırakılmışsa), aradaki dosya isimlerinden birinde kötü amaçlı bir çalıştırılabilir dosya oluşturur. Hizmet `LocalSystem` olarak başladığında, Windows arama sırasındaki ilk eşleşen dosyayı çalıştırır ve saldırgan kodunu SYSTEM haklarıyla icra eder.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kurumda kullanılan yedekleme istemcisi `C:\Program Files\Kurumsal Yedek\backup.exe` yoluna kurulmuştur ve tırnaksızdır. Sisteme sızan düşük yetkili bir kullanıcı `C:\Program Files\` dizinine yazma hakkı olduğunu keşfeder ve buraya `Kurumsal.exe` adında tersine kabuk (reverse shell) üreten bir binary bırakır. Gece saat 02:00'de otomatik yedekleme servisi tetiklendiğinde veya makine yeniden başlatıldığında, SCM doğrudan `C:\Program Files\Kurumsal.exe`'yi SYSTEM haklarıyla çalıştırır.

**Pratik Çözüm:**
Kayıt defterinde veya PowerShell üzerinden yol tırnak içine alınarak düzeltilir:
```powershell
# PowerShell ile tırnaksız yolu çift tırnak içine alma
$serviceName = "KurumsalYedek"
$rawPath = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$serviceName").ImagePath
if (-not $rawPath.StartsWith('"')) {
    $quotedPath = "`"$rawPath`""
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$serviceName" -Name "ImagePath" -Value $quotedPath
    Write-Host "[+] $serviceName servisi tırnak içine alınarak güvenli hale getirildi." -ForegroundColor Green
}
```
Komut satırından `sc.exe config` ile:
```cmd
sc.exe config "KurumsalYedek" binPath= "\"C:\Program Files\Kurumsal Yedek\backup.exe\""
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, üçüncü parti yazılımları sunuculara kurduktan sonra çalıştıracağın ilk otomasyon betiği tırnaksız servis yolu taraması olmalıdır. `Get-WmiObject win32_service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' }` sorgusunu bir monitöring kuralı haline getir; tırnağı eksik olan her servis, sistemine açık bırakılmış bir arka kapıdır.

---

## Soru 2: Servis Güvenlik Tanımlayıcıları (Service DACL / SDDL) Üzerindeki Hangi İzinler Düşük Yetkili Kullanıcılara Verildiğinde Tam Sistem Ele Geçirme (Full System Compromise) Gerçekleşir?

### 1. Soru Başlığı ve Tanımı
Windows Service Control Manager (SCM), her bir servisi bağımsız bir nesne (securable object) olarak yönetir ve her servisin erişim haklarını bir Hizmet Güvenlik Tanımlayıcısı (Service Security Descriptor / DACL) ile sınırlandırır. Düşük yetkili kullanıcılara veya gruplara (`BUILTIN\Users`, `Everyone`, `Authenticated Users`) yapılandırma veya sahiplik değiştirme haklarının tanınması, saldırganın servis ikili dosyasını zararlı bir komutla değiştirerek SYSTEM yetkisi elde etmesine olanak tanır.

### 2. Derinlemesine Teknik Analiz
SCM erişim hakları (Service Access Rights) arasında yerel yetki yükseltmeye imkan veren kritik haklar şunlardır:
1. **`SERVICE_CHANGE_CONFIG` (SDDL Kodu: `DC` / Değer: `0x0002`):** Bu hakka sahip bir kullanıcı, `ChangeServiceConfig` Win32 API'sini veya `sc.exe config` komutunu kullanarak servisin `binPath`, `startType`, `serviceType` ve `accountName` parametrelerini dilediği gibi değiştirebilir.
2. **`WRITE_DAC` (SDDL Kodu: `WD` / Değer: `0x00040000`):** Bu hak, kullanıcının servisin DACL tablosunu yeniden yazmasına izin verir. Kullanıcı önce DACL'ı değiştirip kendisine `SERVICE_CHANGE_CONFIG` verir, ardından servisi manipüle eder.
3. **`WRITE_OWNER` (SDDL Kodu: `WO` / Değer: `0x00080000`):** Kullanıcı servisin sahipliğini üstlenir; Windows nesne güvenliği modeli gereği bir nesnenin sahibi nesne üzerindeki DACL'ı dilediği zaman değiştirebilir.
4. **`SERVICE_STOP` (`WP` / `0x0020`) ve `SERVICE_START` (`RP` / `0x0010`):** Eğer binary üzerinde dosya yazma izni varsa, bu iki hak saldırganın yeni binary'yi anında devreye almasını sağlar.

Standart bir serviste kullanıcıların sahip olması gereken izin kümesi yalnızca `SERVICE_QUERY_CONFIG` (`CC`), `SERVICE_QUERY_STATUS` (`LC`), `SERVICE_ENUMERATE_DEPENDENTS` (`SW`), `SERVICE_INTERROGATE` (`LO`) ve `READ_CONTROL` (`RC`) ile sınırlandırılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurum içi geliştirilen bir veri tabanı eşitleme servisi için yardım masası personelinin servisi yeniden başlatabilmesi istenirken, yanlışlıkla `BUILTIN\Users` grubuna geniş izinler verilmiş ve SDDL tablosuna `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU)` eklenmiştir. Standart kullanıcı hesabına sahip bir saldırgan bu servisi keşfeder. Tek satırla servisin yolunu değiştirir:
```cmd
sc.exe config "DbSyncSvc" binPath= "net localgroup Administrators saldirgan /add"
sc.exe stop "DbSyncSvc"
sc.exe start "DbSyncSvc"
```
Servis SYSTEM olarak çalıştığı için saldırganın kullanıcısını anında Administrator yapar.

**Pratik Çözüm:**
Servisin SDDL tablosu sıkılaştırılarak kullanıcı hakları sadece okuma ile sınırlandırılır:
```powershell
# Güvenli standart Service DACL uygulanması
$serviceName = "DbSyncSvc"
# SY=SYSTEM (Full), BA=Administrators (Full), IU=Interactive Users (Read-only), SU=Service Users (Read-only)
$secureSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
sc.exe sdset $serviceName $secureSddl
Write-Host "[+] $serviceName servisine güvenli SDDL kuralı uygulandı." -ForegroundColor Green
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, yardım masası veya operasyon ekipleri senden "servisi yeniden başlatma yetkisi" isterse, onlara asla tüm servisin yapılandırma yetkisini veya servis DACL'ını teslim etme. Sadece `SERVICE_START` (`RP`) ve `SERVICE_STOP` (`WP`) haklarını spesifik bir güvenlik grubuna ver; asla `DC`, `WD` veya `WO` haklarını sıradan kullanıcılara bulaştırma. SDDL dizgesini okumayı bir müzik notasını okur gibi öğrenmelisin.

---

## Soru 3: Üçüncü Parti Servislerin LocalSystem ile Çalıştırılması Neden En Az Ayrıcalık (Least Privilege) İhlalidir ve Modern Ortamlarda gMSA veya Sanal Hesaplar (Virtual Accounts) Nasıl Uygulanmalıdır?

### 1. Soru Başlığı ve Tanımı
Geleneksel Windows altyapılarında üçüncü parti veya kurum içi geliştirilen yazılımların yetki sorunlarıyla karşılaşmaması adına `NT AUTHORITY\SYSTEM` (`LocalSystem`) ile çalıştırılması alışkanlığı, En Az Ayrıcalık Prensibi'nin (Principle of Least Privilege - CWE-250) doğrudan ihlalidir. Bu durum, uygulamadaki tek bir zafiyetin tüm işletim sistemi çekirdeğinin ve kurumsal ağın tehlikeye girmesine yol açar.

### 2. Derinlemesine Teknik Analiz
`LocalSystem` hesabı:
1. Yerel işletim sisteminde sınırsız yetkiye sahiptir (belleğe erişim, token manipülasyonu, tüm dosya ve kayıt defteri anahtarlarına tam erişim).
2. `SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege` gibi ölümcül Windows ayrıcalıklarını taşır.
3. Ağ üzerinde makine hesabı (`DOMAIN\COMPUTER$`) kimliğiyle Kerberos kimlik doğrulaması yapar; yani ele geçirilen bir `LocalSystem` servisi, saldırgana etki alanı (Active Directory) içerisindeki diğer kaynaklara da makine kimliğiyle erişme imkanı tanır.

Modern Windows mimarisinde iki güçlü alternatif bulunur:
- **Sanal Hesaplar (Virtual Accounts - `NT SERVICE\<HizmetAdı>`):** Yerel sunucularda çalışan servisler için otomatik parola yönetimi sunan, sadece o servise özel bir Güvenlik Tanımlayıcısı (Service SID) üreten ve yerel hakları kısıtlayan izole hesaplardır.
- **Grup Tarafından Yönetilen Servis Hesapları (gMSA - Group Managed Service Accounts):** Active Directory tarafından parolası 30 günde bir otomatik değiştirilen, Kerberos biletleri otomatik yönetilen, parola sızıntısı ve Kerberoasting saldırılarına karşı korumalı kurumsal servis hesaplarıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Şirket içi ERP uygulaması sunucusunda çalışan bir PDF dönüştürme servisi `LocalSystem` ile koşmaktadır. Serviste bir Remote Code Execution (RCE) zafiyeti bulunur. Saldırgan web arayüzünden zararlı bir PDF yükleyerek sistemde komut çalıştırmayı başarır. Servis `LocalSystem` ile çalıştığı için saldırgan doğrudan LSASS sürecinin belleğini dökümleyerek (dump) etki alanı yöneticisinin NTLM karmalarını ele geçirir.

**Pratik Çözüm:**
1. Servis sanal hesaba (`NT SERVICE`) veya gMSA'ya taşınır.
2. Servisin talep ettiği gereksiz Windows ayrıcalıkları (RequiredPrivileges) kayıt defterinden temizlenir (Service Hardening):
```powershell
# Servisi Sanal Hesap (Virtual Account) ile çalıştırma
$serviceName = "PdfConvertSvc"
sc.exe config $serviceName obj= "NT SERVICE\$serviceName"
# Gerekli dosya izinlerini Servis SID'sine verme
$serviceSid = "NT SERVICE\$serviceName"
icacls "C:\Program Files\PdfApp" /grant "${serviceSid}:(OI)(CI)(RX)"
icacls "C:\Program Files\PdfApp\temp" /grant "${serviceSid}:(OI)(CI)(M)"
Write-Host "[+] $serviceName başarıyla izole sanal hesaba taşındı." -ForegroundColor Green
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, tembel yazılımcı ve sistem yöneticisi her zaman "LocalSystem verelim de çalışsın" der. Bu tembellik, fidye yazılımı (ransomware) çetelerinin ekmeğine yağ sürmektir. Çekirdek işletim sistemi bileşenleri hariç hiçbir servise `LocalSystem` verme. Ağa çıkacaksa gMSA ver, yerelde kalacaksa Sanal Hesap (`NT SERVICE`) ver; ayrıcalıklarını da `sc privs` ile buda!
