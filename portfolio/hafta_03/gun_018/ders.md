# GÜN 018: DERS NOTLARI
# Süreç (Process), İş Parçacığı (Thread) ve Hizmet (Service) Kavramları: Bellek İzolasyonu, Yarış Durumları ve Yetki Yükseltme

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim  
> amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez,  
> satılamaz veya tersine mühendislik yapılamaz.

---

## BÖLÜM 1: Giriş ve Kavramsal Çerçeve

İşletim sistemi güvenliğinin kalbinde, kaynakların çoklu kullanıcı ve çoklu görev (multitasking) ortamlarında nasıl paylaştırıldığı ve izole edildiği yatar. Bu mekanizmanın üç ana yapı taşı vardır:
1. **Süreç (Process):** Bir programın bellekte çalışan bağımsız bir örneğidir (instance). Her sürecin kendine ait izole edilmiş bir Sanal Adres Alanı (`Virtual Address Space - VAS`), güvenlik belirteci (`Access Token` / `UID/GID`), dosya tanıtıcıları (`Handle Table`) ve işlemci kayıt haritası bulunur.
2. **İş Parçacığı (Thread):** Bir sürecin içinde CPU zaman dilimlerini (CPU scheduling) tüketen en küçük yürütme birimidir. Bir süreç birden fazla iş parçacığı barındırabilir. En kritik güvenlik gerçeği: **Bir sürecin tüm iş parçacıkları aynı sanal adres alanını, öbeği (Heap) ve açık dosyaları ortaklaşa paylaşır; her iş parçacığının yalnızca kendine ait bir yığıtı (Stack) ve yazmaç bağlamı vardır.**
3. **Hizmet / Servis (Daemon / Windows Service):** Kullanıcı oturumu açık olsun veya olmasın, arka planda işletim sistemi başladığı andan itibaren çalışan, genellikle kullanıcı arayüzü (GUI) barındırmayan ve yüksek ayrıcalıklarla (`SYSTEM`, `root`) çalışan özel süreçlerdir.

Siber savunma ve sızma testi perspektifinde; süreçler arasındaki sınırların delinmesi (**Process Injection**), iş parçacıkları arasındaki güvensiz bellek paylaşımı (**Race Condition / TOCTOU**) ve arka plan hizmetlerinin yapılandırma hataları (**Unquoted Service Path, Weak Permissions**) kurumsal ağlarda yerel yetki yükseltmenin (`Local Privilege Escalation - LPE`) en yaygın kapılarını açar.

---

## BÖLÜM 2: Süreç ve İş Parçacığı Mimarisi (Processes & Threads)

### 2.1. Süreç Anatomisi ve İzolasyon Sınırları

Windows'ta bir süreç çekirdekte `EPROCESS` veri yapısıyla, Linux'ta ise `task_struct` ile temsil edilir. Sürecin güvenliğini sağlayan ana donanım unsuru işlemcinin `CR3` kayıtçısıdır:
- `CR3` kayıtçısı, o sürece ait Sayfa Tablosu Dizinini (`Page Directory Base`) tutar.
- İşlemci bağlam değiştirdiğinde (Context Switch), `CR3` kayıtçısına yeni sürecin sayfa tablosu yüklenir.
- Böylece Süreç A'nın işaret ettiği `0x00400000` adresi ile Süreç B'nin işaret ettiği `0x00400000` adresi fiziksel RAM'de tamamen farklı yongalara ve sayfalara denk gelir. Bir süreç işletim sisteminin açık izni (Shared Memory, IPC) olmadan diğerinin belleğini göremez.

### 2.2. İş Parçacığı ve Yarış Durumu (Race Condition)

Aynı süreç içerisindeki iki iş parçacığı ortak bir global değişkene erişirken kilit (Mutex, Semaphore, Critical Section) kullanmazsa, CPU zamanlayıcısının rastgele araya girmesi nedeniyle **Yarış Durumu (Race Condition)** oluşur:
- Thread 1 değişkeni okur (`bakiye = 1000`).
- İşlemci Thread 1'i askıya alır ve Thread 2'yi çalıştırır.
- Thread 2 değeri değiştirip yazar (`bakiye = 900`).
- İşlemci tekrar Thread 1'e döner. Thread 1 eski değer üzerinden işlem yaparak (`1000 + 100 = 1100`) belleğe yazar.
- Sonuç: 900 olması gereken bakiye veya yetki bayrağı bozulur! Bu durum siber güvenlikte **TOCTOU (Time of Check to Time of Use)** zaafiyetlerinin temelini oluşturur.

---

## BÖLÜM 3: Arka Plan Hizmetleri ve Güvenlik Dinamikleri (Services)

### 3.1. Windows Hizmet Kontrol Yöneticisi (Service Control Manager - SCM)

Windows hizmetleri `services.exe` (SCM) tarafından yönetilir. Hizmetler Kayıt Defteri'nde şu anahtar altında yapılandırılır:
`HKLM\SYSTEM\CurrentControlSet\Services\<HizmetAdi>`

Her hizmetin bir çalıştırılabilir ikili dosya yolu (`ImagePath`), başlangıç türü (`Start`: Otomatik, Manuel, Devre Dışı) ve çalışacağı hesap (`ObjectName`) bulunur.

### 3.2. Hizmet Hesapları ve Session 0 İzolasyonu

Windows Vista öncesinde hizmetler oturum açan kullanıcının masaüstüyle (Session 0) aynı oturumda çalışıyordu. Bir saldırgan kullanıcı kipi arayüzünden sistem mesajları göndererek (`WM_TIMER`, `Shatter Attacks`) SYSTEM yetkisiyle çalışan hizmet penceresini ele geçirebiliyordu.
- Microsoft, Vista ile birlikte **Session 0 İzolasyonu** getirdi: Tüm arka plan hizmetleri Session 0'da ve tamamen etkileşimsiz (Non-interactive) çalışır.
- Kullanıcı masaüstü oturumları Session 1, Session 2 vb. olarak izole edilir.

Hizmet Hesapları:
- `NT AUTHORITY\LocalSystem`: İşletim sistemindeki en yetkili hesaptır. Çekirdek sürücüsü yükleyebilir, tüm dosyalara erişebilir.
- `NT AUTHORITY\LocalService`: Kısıtlı yerel yetkilere sahip, ağda anonim kimlikle gezen güvenli hesap.
- `NT AUTHORITY\NetworkService`: Yerel olarak kısıtlı, ancak ağdaki diğer makinelere bilgisayar hesabı (`DOMAIN\COMPUTER$`) ile erişebilen servis hesabı.

---

## BÖLÜM 4: Hizmet ve Süreç İstismar Vektörleri

### 4.1. Unquoted Service Path (MITRE ATT&CK T1574.009)

Windows'ta bir hizmetin `ImagePath` değeri boşluk içeriyor ve çift tırnak (`"`) içine alınmamışsa:
Örnek yol: `C:\Program Files\Kurumsal Bakim Yazilimi\agent service\engine.exe`

Windows `CreateProcess` API'si boşluk karakterini argüman ayracı olarak yorumlayabileceği için, dosyayı bulmak amacıyla sırasıyla şu yolları dener:
1. `C:\Program.exe`
2. `C:\Program Files\Kurumsal.exe`
3. `C:\Program Files\Kurumsal Bakim.exe`
4. `C:\Program Files\Kurumsal Bakim Yazilimi\agent.exe`
5. `C:\Program Files\Kurumsal Bakim Yazilimi\agent service\engine.exe`

Eğer bir saldırgan `C:\` kök dizinine veya ara klasörlere yazma hakkına sahipse, oraya `Program.exe` adında bir zararlı koyar. Sistem yeniden başladığında veya hizmet tetiklendiğinde, SCM gerçek servis yerine saldırganın `Program.exe` dosyasını `NT AUTHORITY\SYSTEM` yetkisiyle çalıştırır!

### 4.2. Zayıf Servis İzinleri (Weak Service Permissions)

Bir hizmetin DACL (Erişim Kontrol Listesi) izinlerinde standart kullanıcılara veya `Authenticated Users` grubuna `SERVICE_CHANGE_CONFIG` veya `SERVICE_ALL_ACCESS` izni verilmişse:
Saldırgan komut satırından tek bir komutla hizmetin çalıştırdığı ikili dosyayı değiştirebilir:
```powershell
sc config VulnBakimServisi binPath= "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
sc stop VulnBakimServisi
sc start VulnBakimServisi
```

---

## BÖLÜM 5: Uygulama Mimarisi ve Kod Açıklaması

Bu ünitede geliştirdiğimiz `portfolio/hafta_03/gun_018/uygulama/process_thread_service_security_auditor.py` aracı şu modüler yeteneklere sahiptir:

1. `get_live_process_and_service_inventory()`:
   - Standart Python `os.getpid()`, `os.getppid()` ve `subprocess` üzerinden `tasklist` / `sc query` çağrıları ile yerel sistemden canlı olarak 2 kullanıcı süreci ve 1 arka plan hizmetini belgeler (G018-SC2).
2. `detect_unquoted_service_path(binary_path)`:
   - Yoldaki çift tırnakları ve boşlukları ayrıştırır. Boşluklu ve tırnaksız bir yol tespit ettiğinde Windows'un arayacağı aday tuzak `.exe` yollarını sırasıyla üretir.
3. `audit_service_security(service_dict)`:
   - Hizmetin tırnaksız yol zaafiyetini, dizin yazma izinlerini ve SYSTEM hesabı kullanımını CIS standartlarına göre denetler.
4. `simulate_thread_memory_sharing(use_mutex)`:
   - İki iş parçacığının aynı bellek nesnesi üzerindeki yarış durumunu (Race Condition) ve Mutex kilitleri ile bu bozulmanın nasıl engellendiğini simüle eder.

---

## BÖLÜM 6: Doğrulama, Test ve Güvenlik Kanıtları

Test paketimiz (`tests/test_process_thread_service_security_auditor.py`) 14 birim testinden oluşur:
- **Pozitif Testler:** Canlı sistemden en az iki süreç ve bir hizmetin Session 0 izolasyonu ile tespit edilmesi, çift tırnaklı yolların güvenli sınıflandırılması, Mutex ile iş parçacığı yarışının engellenmesi, CLI alt süreç icrası.
- **Negatif Testler:** Boşluklu ve tırnaksız yolda `Unquoted Service Path` zaafiyetinin yakalanması, standart kullanıcıların yazabildiği servis klasöründe `KRİTİK` risk tespiti, olmayan dosyada `FileNotFoundError` kontrolü.

Tüm testler **14/14 PASS (%100 Başarı)** ile tamamlanmış ve `kanit/gercek/` altına işlenmiştir.

---

## BÖLÜM 7: Usta Çırak Nasihatleri ve Saha Tecrübeleri

1. **Üçüncü Parti Yazılımları Her Zaman Denetleyin:**
   - Microsoft'un kendi servisleri neredeyse istisnasız çift tırnak içine alınmıştır. Ancak antivirüs, VPN, yazıcı ve donanım üreticilerinin yüklediği üçüncü parti servislerin yaklaşık %15-20'sinde tırnaksız yol hatasıyla karşılaşılır.
2. **Kök Dizine (C:\) Yazma İznini Kısıtlayın:**
   - Normal şartlarda standart kullanıcılar `C:\` kök dizinine doğrudan dosya yazamaz (UAC ve NTFS izinleri korur). Ancak eski yazılımlar çalışsın diye `C:\` izinleri gevşetilmiş kurumsal ortamlarda `C:\Program.exe` saldırısı tam bir kabustur.
3. **Servisleri SYSTEM Yerine gMSA ile Çalıştırın:**
   - Yeni bir kurumsal servis yazarken hesabı asla `LocalSystem` yapmayın. Active Directory ortamında **Group Managed Service Accounts (gMSA)** veya yerelde `LocalService` kullanarak En Az Ayrıcalık ilkesini tavizsiz uygulayın.
