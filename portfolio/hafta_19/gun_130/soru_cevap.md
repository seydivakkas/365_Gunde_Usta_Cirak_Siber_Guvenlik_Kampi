# GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ SORU - CEVAP
**Tarih:** 2 Kasım 2026  
**Format:** Usta - Çırak / Hoca Dersi  

---

### SORU 1: Windows DACL Değerlendirme Algoritması, Kanonik ACE Sıralaması ve Mantıksal Çakışmaların Kernel Düzeyinde Çözümü (CWE-284)

#### 1. Soru Başlığı ve Tanımı
Windows Security Reference Monitor (SRM), bir dosya veya dizine erişim talep edildiğinde DACL içerisindeki ACE kurallarını hangi katı sırayla değerlendirir? Kanonik ACE sıralaması (Canonical Ordering) neden hayati bir güvenlik kuralıdır ve bu sıra bozulduğunda ne gibi yetkilendirme bypass riskleri doğar (`CWE-284`)?

#### 2. Derinlemesine Teknik Analiz
Windows NT çekirdeğinde nesne güvenliği, nesnenin Security Descriptor'ı ile çağıran sürecin Access Token'ı arasındaki karşılaştırmayla sağlanır. Bir süreç dosya açmak için `NtOpenFile` veya `NtCreateFile` sistem çağrısı yaptığında:
- Talep edilen erişim maskesi (`DesiredAccess`) belirlenir (örn: `FILE_WRITE_DATA | FILE_APPEND_DATA`).
- SRM, DACL içerisindeki ACE dizilimini yukarıdan aşağıya (sıralı olarak) okur:
  1. **Açık Reddetme (Explicit Deny):** Talep edilen haklardan herhangi biri eşleşen bir açık reddetme ACE'sinde varsa, SRM diğer kurallara bakmadan işlemi anında `STATUS_ACCESS_DENIED` ile sonlandırır.
  2. **Açık İzin Verme (Explicit Allow):** Eşleşen haklar toplanır. Talep edilen tüm haklar sağlandıysa tarama durur ve erişim verilir.
  3. **Miras Alınan Reddetme (Inherited Deny):** Üst dizinden devralınmış reddetme kuralları değerlendirilir.
  4. **Miras Alınan İzin Verme (Inherited Allow):** Üst dizinden devralınmış izin kuralları değerlendirilir.
- **Kanonik Sıra İhlali:** Eğer bir API veya hatalı betik, Explicit Allow kuralını Explicit Deny kuralının üstüne yazarsa; SRM Explicit Allow kuralını gördüğü anda talep edilen hakkı verir ve alt satırdaki Deny kuralını asla okumaz! Bu durum "Kullanıcıyı engellediğimi sanıyordum ama açık izin üstte olduğu için engellenmedi" şeklinde kritik güvenlik ihlallerine (`CWE-284`) yol açar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kurumda İnsan Kaynakları dizininde `C:\IK_Maaslar` klasörü için yöneticiler `Everyone: Deny` ve belirli bir `Müdür: Allow` kuralı tanımlamak istemiştir. Özel geliştirilen bir C# yönetim aracı DACL'a kuralları eklerken `Müdür` iznini en başa, `Everyone` reddetmesini ise ikinci sıraya koymuştur. Sonuçta `Everyone` grubu `Müdür` grubunun da üst kümesi olduğu için, Windows Explorer güvenlik sekmesini açan sistem yöneticisi "The permissions on this folder are incorrectly ordered" uyarısıyla karşılaşmış ve sistemde yetkisiz dosya okuma açığı oluşmuştur.
**Çözüm:**
1. Bozuk sıralamaya sahip ACL'ler `icacls` aracı ile taranır ve düzeltilir:
   ```cmd
   icacls "C:\IK_Maaslar" /verify
   ```
2. PowerShell üzerinden `FileSystemAccessRule` nesneleri kanonik sıraya göre dizilir veya kural doğrudan miras alarak üstten temiz bir şekilde uygulanır:
   ```powershell
   $acl = Get-Acl "C:\IK_Maaslar"
   $acl.SetAccessRuleProtection($true, $false) # Mirası kır
   $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IK_Mudurler","FullControl","Allow")))
   Set-Acl "C:\IK_Maaslar" $acl
   ```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Windows güvenlik modeli 'ilk eşleşen karar verir' mantığıyla çalışır. Açık reddetmeyi daima listenin tepesine koyacaksın. Eğer bir klasörde 'izinler kanonik sırada değil' uyarısı görüyorsan, bil ki orada bir programcı amatörce DACL manipülasyonu yapmıştır. O izin listesini derhal sıfırla ve baştan yaz!"

---

### SORU 2: Zayıf NTFS İzinleri ile SYSTEM Yetkisine Yükselme Vektörleri (DLL Hijacking ve Service Binary Overwrite) (CWE-732 / MITRE T1574.009)

#### 1. Soru Başlığı ve Tanımı
Windows işletim sisteminde `C:\Program Files` veya `C:\ProgramData` altındaki servis dizinlerinde standart kullanıcılara tanınan yazma (Write) veya değiştirme (Modify) hakları nasıl `NT AUTHORITY\SYSTEM` seviyesinde yetki yükseltmeye (Privilege Escalation) dönüşür? DLL Hijacking mekanizması bu izin zayıflığını nasıl istismar eder?

#### 2. Derinlemesine Teknik Analiz
Windows servislerinin büyük çoğunluğu arka planda `LocalSystem` (`S-1-5-18`) hesabıyla çalışır. Bir servisin ikilisi (binary) diskten belleğe yüklenirken işletim sistemi dosyayı okur ve çalıştırır.
- **İkili Üzerine Yazma (Binary Overwrite):** Eğer servisin `.exe` dosyasının DACL'ında `BUILTIN\Users` için `Modify` veya `Write` izni varsa; düşük yetkili bir saldırgan `cmd.exe` veya PowerShell üzerinden `service.exe` dosyasını kendi derlediği zararlı bir ikili ile değiştirebilir (`Copy-Item evil.exe service.exe -Force`). Servis ilk yeniden başlatıldığında işletim sistemi saldırganın kodunu SYSTEM haklarıyla çalıştırır (`CWE-732 / MITRE T1068`).
- **DLL Hijacking:** Bir servis çalışırken harici dinamik kütüphanelere (`.dll`) ihtiyaç duyar. Windows DLL arama sırası şöyledir:
  1. Uygulamanın yüklendiği dizin (Application Directory).
  2. Sistem dizini (`C:\Windows\System32`).
  3. 16-bit sistem dizini.
  4. Windows dizini (`C:\Windows`).
  5. Geçerli çalışma dizini (Current Working Directory).
  6. `PATH` ortam değişkenindeki dizinler.
- Eğer uygulamanın bulunduğu dizin standart kullanıcılar tarafından yazılabilir durumdaysa ve uygulama var olmayan bir DLL'i çağırmaya çalışıyorsa (Phantom DLL Hijack); saldırgan bu isimle kötü amaçlı bir DLL dosyasını dizine bırakır. Servis çalışırken ilk olarak kendi dizinine baktığı için saldırganın DLL'ini yükler ve `DllMain` fonksiyonu SYSTEM yetkisiyle icra edilir (`MITRE T1574.001`).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekomünikasyon şirketinde ağ izleme amacıyla `C:\Program Files\NetMonitor\monitor.exe` servisi kurulmuştur. Kurulum kılavuzunda "Uygulama log yazabilsin diye Program Files klasörüne Users grubu için Full Control verin" yazmaktadır. Bir siber saldırgan oltalama ile normal bir çalışan bilgisayarına sızmış, `accesschk.exe` aracıyla kontrol ettiğinde `C:\Program Files\NetMonitor` üzerinde yazma hakkı olduğunu görmüştür. Saldırgan `monitor.exe` yerine kendi Meterpreter yükünü koymuş ve servisi tetikleyerek makinede tam SYSTEM yetkisi elde etmiştir.
**Çözüm:**
1. Servis dizinleri ve ikilileri `icacls` ile taranır ve standart kullanıcılara ait tüm yazma hakları kaldırılır:
   ```cmd
   icacls "C:\Program Files\NetMonitor" /inheritance:r /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Users:(OI)(CI)RX"
   ```
2. Uygulama log yazmaya ihtiyaç duyuyorsa, ikili dosyaların olduğu dizine değil, yalnızca izole edilmiş bir `C:\ProgramData\NetMonitor\Logs` klasörüne sınırlı yazma izni tanımlanmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat! Bir yazılımcı sana 'bizim programın çalışması için kullanıcıların kurulum klasörüne yazması lazım' diyorsa, bil ki o yazılımcı 1995 yılındaki Windows 95 kafasında kalmıştır. Modern mimaride ikililer (kod) ile veriler (log, cache) kesin olarak ayrılır. Koda sadece yöneticiler yazar, veriye uygulama yazar. Bu kuralı bozan her yazılım bir yetki yükseltme bombasıdır!"

---

### SORU 3: Tırnak İçine Alınmamış Servis Yolları (Unquoted Service Path), Boşluk Karakteri İstismarı ve Dosya Sistemi Sertleştirmesi (CWE-428 / MITRE T1574.009)

#### 1. Soru Başlığı ve Tanımı
Windows işletim sisteminde "Tırnak İçine Alınmamış Servis Yolu" (Unquoted Service Path - `CWE-428`) zafiyeti nasıl ortaya çıkar? Dosya yolundaki boşluk karakterleri Windows API'si tarafından nasıl yorumlanır ve bu durum zayıf NTFS izinleriyle birleştiğinde nasıl istismar edilir?

#### 2. Derinlemesine Teknik Analiz
Windows API fonksiyonu `CreateProcess`, bir ikili dosya yolunu çalıştırırken eğer yol çift tırnak (`" "`) içinde verilmemişse ve yol içerisinde boşluk karakteri bulunuyorsa, yolu soldan sağa doğru her boşlukta keserek bir yürütülebilir dosya arar.
- Örneğin bir servisin `ImagePath` kayıt defteri değeri şu olsun:  
  `C:\Program Files\Acme Software\System Monitor\agent.exe`
- Windows çekirdeği tırnak işareti görmediği için boşluk karakterlerini argüman ayracı sanabilir. Bu nedenle sırasıyla şu dosyaları var mı diye diske sorar:
  1. `C:\Program.exe`
  2. `C:\Program Files\Acme.exe`
  3. `C:\Program Files\Acme Software\System.exe`
  4. `C:\Program Files\Acme Software\System Monitor\agent.exe`
- **İstismar Zinciri:** Normal şartlarda standart kullanıcılar `C:\` veya `C:\Program Files` altına dosya yazamaz. Ancak hatalı yapılandırılmış bir sistemde veya üçüncü parti bir sürücüde kök dizin veya ana klasör yazılabilir bırakılmışsa (`CWE-732`), saldırgan `C:\Program.exe` adında bir zararlı bırakır. Servis başlatıldığı anda Windows gerçek `agent.exe` yerine `C:\Program.exe`'yi SYSTEM yetkisiyle yürütür (`CWE-428 / MITRE T1574.009`).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir denetimde güvenlik ekibi `wmic service get name,displayname,pathname,startmode` komutuyla çalışan servisleri listelemiş ve 4 adet ticari uygulamanın tırnaksız servis yoluna sahip olduğunu tespit etmiştir. Üstelik bu uygulamalardan birinin kurulduğu `C:\Program Files\Vulnerable Suite` klasörünün izinleri gevşektir.
**Çözüm:**
1. Tırnaksız servis yolları PowerShell ile tespit edilir ve kayıt defteri yolu çift tırnak içine alınarak onarılır:
   ```powershell
   Get-CimInstance -ClassName Win32_Service | Where-Object {
       $_.PathName -notmatch '^"' -and $_.PathName -match ' '
   } | ForEach-Object {
       $correctPath = '"{0}"' -f $_.PathName.Trim()
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -Name "ImagePath" -Value $correctPath
   }
   ```
2. Dosya sisteminde `C:\` kök dizini ve `Program Files` ana klasörlerinin ACL'leri doğrulanarak `BUILTIN\Users` için `(OI)` bayraklı dosya oluşturma hakları temizlenir:
   ```cmd
   icacls "C:\" /remove:g "BUILTIN\Users:(OI)(CI)(W)"
   ```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Çift tırnak sadece iki minik noktalama işaretidir, ancak o iki tırnak olmadığında işletim sistemi koca bir sunucuyu saldırgana hediye edebilir. Bir güvenlik denetçisi olarak bir Windows makineye adım attığında ilk çalıştıracağın sorgulardan biri daima tırnaksız servis yolları ve o yolların NTFS izinleri olmalıdır!"
