# GÜN 017: DERS NOTLARI
# İşletim Sistemi Çekirdeği (Kernel Mode) ve Kullanıcı Modu (User Mode): Düşük Seviyeli Güvenlik Sınırları ve BYOVD Tehditleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim  
> amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez,  
> satılamaz veya tersine mühendislik yapılamaz.

---

## BÖLÜM 1: Giriş ve Kavramsal Çerçeve

Modern siber güvenlik mimarisinde savunma hatlarının en derini, işletim sisteminin **çekirdeği (Kernel)** ile kullanıcı uygulamalarının koştuğu **kullanıcı modu (User Mode)** arasındaki fiziksel ve donanımsal sınırdır. Birçok sistem yöneticisi ve yazılımcı, "Yönetici (Administrator / root)" yetkisine sahip olmayı mutlak güç ve nihai güvenlik seviyesi zanneder. Oysa ki bu vahim bir kavram yanılgısıdır:
- Windows'ta bir komut satırını "Yönetici Olarak Çalıştır" (Run as Administrator) seçeneğiyle açtığınızda veya Linux'ta `sudo` ile bir kabuk başlattığınızda, süreciniz **hâlâ Kullanıcı Modundadır (Ring 3)**.
- Süreciniz yalnızca daha yüksek bir bütünlük seviyesine (High Integrity) ve bazı ayrıcalıklara (örneğin `SeDebugPrivilege` veya `CAP_SYS_ADMIN`) sahip olur; ancak donanıma doğrudan erişemez, bellek sayfalarının fiziksel eşlemesini değiştiremez ve CPU'nun korumalı kayıtçılarına (`CR0`, `CR3`, `MSR`) dokunamaz.

İşletim sistemi çekirdeği (Windows'ta `ntoskrnl.exe`, Linux'ta `vmlinuz`), donanımın sunduğu en yüksek ayrıcalık halkası olan **Ring 0** seviyesinde koşar. Ring 0, tüm fiziksel belleğe, işlemci çekirdeklerine ve bağlı donanımlara doğrudan ve sınırsız erişim gücüne sahiptir.

Bu dersimizin odak noktası; Kullanıcı Modu (Ring 3) ile Çekirdek Modu (Ring 0) arasındaki geçişlerin nasıl yapıldığı, saldırganların bu güvenlik sınırını aşarak nasıl **Ayrıcalık Yükselttiği (Privilege Escalation)** ve son yılların en yıkıcı saldırı tekniklerinden olan **BYOVD (Bring Your Own Vulnerable Driver - Kendi Savunmasız Sürücünü Getir)** metodolojisinin nasıl tespit edilip engelleneceğidir.

---

## BÖLÜM 2: Düşük Seviyeli Mimari ve Sistem Çağrıları (Syscalls)

### 2.1. Donanımsal Koruma Halkaları (x86/x64 Rings)

x86-64 mimarisinde işlemci her an belirli bir geçerli ayrıcalık seviyesinde (`CPL - Current Privilege Level`) bulunur:
- `CPL = 0` (Ring 0 / Supervisor Mode): İşletim sistemi çekirdeği ve aygıt sürücüleri çalışır.
- `CPL = 3` (Ring 3 / User Mode): Kullanıcı uygulamaları, servisler ve kabuklar çalışır.
- Ring 1 ve Ring 2 tarihsel olarak ayrılmış olsa da modern genel amaçlı işletim sistemlerinde kullanılmaz (sanal makinelerde Tip-1 hipervizörler ise Ring -1 olarak adlandırılan VMX root kipinde çalışır).

### 2.2. Kanonik Adres Ayrımı (Canonical Address Space Split)

64-bit mimarilerde 48-bit veya 57-bit sanal adresleme kullanılır. Adres alanı tam ortadan ikiye bölünmüştür:
1. **Kullanıcı Alanı (User Space):**  
   `0x0000000000000000` ile `0x00007FFFFFFFFFFF` (128 TB). Her sürecin kendine ait özel bir kullanıcı alanı vardır (CR3 sayfa tablosu ile izole edilir).
2. **Kanonik Olmayan Boşluk (Non-canonical Gap):**  
   Adreslerin geçerli olmadığı korumalı boşluk.
3. **Çekirdek Alanı (Kernel Space):**  
   `0xFFFF800000000000` ile `0xFFFFFFFFFFFFFFFF` (128 TB). Çekirdek kodu, çekirdek yığıtı ve sürücüler burada bulunur ve tüm süreçler için ortak bir haritaya sahiptir.

Ring 3'te çalışan bir program doğrudan `0xFFFF800000000000` üzerindeki bir adresi okumaya veya yazmaya çalışırsa, işlemci anında **Genel Koruma Hatası (General Protection Fault - #GP)** veya **Sayfa Hatası (#PF)** fırlatarak süreci işletim sistemine şikayet eder ve işletim sistemi o süreci sonlandırır (`Segmentation Fault` veya `Access Violation 0xC0000005`).

### 2.3. Güvenlik Sınırından Geçiş: Sistem Çağrıları (Syscalls)

Kullanıcı kipi uygulamaları diskten dosya okumak, ağdan paket göndermek veya yeni bir süreç başlatmak için çekirdeğin yardımına muhtaçtır. Bu geçiş rastgele adreslere zıplayarak değil, donanımın denetlediği tek bir kapıdan yapılır:
- Eski mimarilerde: Yazılımsal kesmeler (`int 0x80` veya `int 0x2e`).
- Modern 64-bit mimarilerde: `SYSCALL` (AMD/Intel) veya `SYSENTER` komutları.

Bir kullanıcı programı `syscall` komutunu çalıştırdığında:
1. CPU, Model Specific Register (`MSR_LSTAR`) içerisinde saklanan çekirdek giriş noktasına (`KiSystemCall64`) zıplar.
2. İşlemci CPL seviyesini anında Ring 3'ten Ring 0'a yükseltir.
3. Kullanıcı yığıtı (`RSP`) yerine güvenli çekirdek yığıtı (Kernel Stack) devreye alınır.
4. Çekirdek, `RAX` yazmacındaki sistem çağrısı numarasını (`SSN - System Service Number`) okuyarak ilgili çekirdek fonksiyonunu (örn: `NtReadFile`) yürütür.
5. İşlem bitince `SYSRET` komutuyla CPL yeniden Ring 3'e düşürülür ve kullanıcı koduna dönülür.

---

## BÖLÜM 3: Güvenlik Sınırı İhlalleri ve İstismar Vektörleri

### 3.1. Güvensiz İşaretçi Denetimi (Unchecked Pointer Dereference)

Bir kullanıcı programı çekirdeğe `syscall` ile bir bellek göstericisi (pointer) ve boyut ilettiğinde (örneğin okunacak verinin yazılacağı tampon adresi), çekirdek kodu bu göstericiyi **körü körüne açıp yazamaz!**
- Eğer kullanıcı programı tampon adresi olarak `0xFFFFF80012340000` (çekirdeğin kendi kod alanı) verirse ve çekirdek bunu denetlemeden yazarsa, kullanıcı süreci çekirdek kodunu ezerek keyfi kod çalıştırabilir (Arbitrary Kernel Write).
- Bu yüzden Windows çekirdeğinde `ProbeForRead` ve `ProbeForWrite`, Linux çekirdeğinde ise `access_ok` fonksiyonları zorunludur. Bu fonksiyonlar göstericinin kesinlikle kullanıcı alanı sınırları (`< 0x7FFFFFFFFFFF`) içinde olduğunu doğrular.

### 3.2. BYOVD (Bring Your Own Vulnerable Driver) Saldırıları

Modern Windows sistemlerinde çekirdeğe sürücü yükleyebilmek için sürücünün geçerli bir dijital sertifika ile imzalanmış olması gerekir (**DSE - Driver Signature Enforcement**). Bir saldırgan doğrudan kendi zararlı rootkit sürücüsünü sisteme yükleyemez.

Ancak saldırganlar dâhice ve sinsi bir yöntem geliştirmiştir: **BYOVD**.
1. Saldırgan yerel sistemde yönetici (Administrator) yetkisine erişir.
2. Geçmişte yasal bir donanım üreticisi (örneğin MSI, ASUS, Gigabyte) tarafından Microsoft onaylı olarak imzalanmış, ancak içinde ciddi bir güvenlik açığı (örn: kullanıcıdan gelen IOCTL ile doğrudan fiziksel bellek okuma/yazma izni veren bir hata) bulunan eski bir sürücüyü (`RTCore64.sys`, `gdrv.sys`, `mhyprot2.sys`) sisteme kopyalar.
3. Sürücü geçerli Microsoft imzasına sahip olduğu için DSE engeline takılmaz ve çekirdeğe (Ring 0) yüklenir!
4. Saldırgan kullanıcı modundaki zararlı yazılımından bu sürücüye özel IOCTL paketleri göndererek EDR/Antivirüs koruma sürücülerinin çekirdekteki süreç nesnelerini (`EPROCESS`) hafızadan siler veya kendi sürecini `NT AUTHORITY\SYSTEM` yetkisine yükseltir!

---

## BÖLÜM 4: Çekirdek Savunma Mimarisi ve Sertleştirme Standartları

Modern işletim sistemleri ve işlemci üreticileri çekirdek sınırını korumak için çok katmanlı donanım ve yazılım zırhları geliştirmiştir:

1. **SMEP (Supervisor Mode Execution Prevention):**
   - İşlemci Ring 0 kipindeyken, kullanıcı alanında (Ring 3) bulunan sayfalardaki kodları çalıştırmasını donanımsal olarak engeller. Saldırgan çekirdek akışını kullanıcı alanındaki kabuk koduna (shellcode) yönlendirirse işlemci sistemi anında mavi ekrana (BSOD) düşürür.
2. **SMAP (Supervisor Mode Access Prevention):**
   - Çekirdeğin açık bir izin (`STAC` komutu) olmaksızın kullanıcı belleğindeki verileri doğrudan okumasını veya yazmasını engeller.
3. **KASLR (Kernel Address Space Layout Randomization):**
   - Çekirdek kodlarının ve veri yapılarının her yeniden başlatmada farklı sanal adreslere yüklenmesini sağlayarak ROP (Return-Oriented Programming) saldırılarını zorlaştırır.
4. **KPTI (Kernel Page Table Isolation):**
   - Meltdown yan kanal zafiyetini önlemek amacıyla, kullanıcı modu çalışırken çekirdek sayfa tablolarının bellek eşlemesinden tamamen izole edilmesidir.
5. **HVCI (Hypervisor-Protected Code Integrity) ve VBS (Virtualization-based Security):**
   - Çekirdeğin altında çalışan Tip-1 Hyper-V hipervizörü (Virtual Trust Level 1 - VTL1), çekirdeğin (VTL0) bellek sayfalarının yürütme izinlerini kilitler. Bir sürücü çekirdeğe yüklense dahi kod sayfalarını değiştiremez (W^X kuralı - Write XOR Execute).
6. **Microsoft Önerilen Savunmasız Sürücü Engelleme Listesi (Driver Blocklist):**
   - Bilinen BYOVD sürücülerinin karmaları (hash) ve sertifikaları işletim sistemi ve WDAC (Windows Defender Application Control) tarafından engellenerek çekirdeğe yüklenmesi durdurulur.

---

## BÖLÜM 5: Uygulama Mimarisi ve Kod Açıklaması

Bu ünitede geliştirdiğimiz `portfolio/hafta_03/gun_017/uygulama/kernel_user_mode_boundary_analyzer.py` aracı, çekirdek/kullanıcı modu sınırlarını denetleyen 4 kritik bileşene sahiptir:

1. `get_current_process_privilege_context()`:
   - Yerel işletim sistemi API'si (`ctypes.windll.shell32.IsUserAnAdmin` veya `os.geteuid()`) aracılığıyla mevcut sürecin yetkisini ve bütünlük seviyesini (Integrity Level) canlı olarak sorgular.
2. `validate_syscall_pointer(address_str, size_bytes)`:
   - Çekirdeğe iletilen bir adresin NULL olup olmadığını, tamsayı taşması yaratıp yaratmadığını ve en önemlisi 64-bit kanonik kullanıcı sınırını (`0x00007FFFFFFFFFFF`) aşıp çekirdek alanına tecavüz edip etmediğini (`ProbeForRead` simülasyonu) doğrular.
3. `audit_byovd_drivers(driver_list)`:
   - Sistemde yüklenmek istenen sürücülerin bilinen istismar edilebilir BYOVD sürücüsü olup olmadığını kontrol eder.
4. `audit_kernel_security_baseline(config, baseline)`:
   - DSE, HVCI, VBS ve Savunmasız Sürücü Engelleme Listesi kurallarının aktifliğini denetler.

---

## BÖLÜM 6: Doğrulama, Test ve Güvenlik Kanıtları

Test paketimiz (`tests/test_kernel_user_mode_boundary_analyzer.py`) 14 adet kapsamlı birim testinden oluşur:
- **Pozitif Testler:** Geçerli kullanıcı işaretçisinin onaylanması (`0x7ffd12340000`), canlı süreç yetki sorgusunun doğrulanması, meşru imzalı sürücünün onaylanması, CLI alt süreç yürütülmesi.
- **Negatif Testler:** NULL pointer girişinin engellenmesi (CWE-476), çekirdek adresine sızma girişiminin SMEP/SMAP ihlali olarak reddedilmesi (`0xfffff800...`), tamsayı taşmasının yakalanması, var olmayan dosya yüklemesinde `FileNotFoundError` kontrolü.
- **Güvenlik Taban Çizgisi Testleri:** Sürücü engelleme listesi veya DSE kapalı olduğunda kural ihlallerinin üretilmesi.

Tüm testler **14/14 PASS (%100 Başarı)** ile tamamlanmış ve `kanit/gercek/` altına kaydedilmiştir.

---

## BÖLÜM 7: Usta Çırak Nasihatleri ve Saha Tecrübeleri

1. **"Administrator Yetkisi Her Şeyi Yapar" Sanma:**
   - Bir yazılımın yönetici olarak çalışması, çekirdeğin iç dinamiklerine erişebileceği anlamına gelmez. Eğer bir saldırgan yönetici haklarına sahip bir sistemde EDR'ı kapatamıyorsa (çünkü EDR sürücüsü Ring 0'da ve ELAM korumalıdır), BYOVD tekniğine başvuracaktır.
2. **HVCI ve Savunmasız Sürücü Engelleme Listesini Mutlaka Açın:**
   - Kurumsal ortamlarda Windows Güvenliği panelinde "Bellek Bütünlüğü (Memory Integrity / HVCI)" ayarını ve Grup İlkesi'nde (GPO) "Microsoft Vulnerable Driver Blocklist" politikasını açmak, fidye yazılımlarının (BlackCat, LockBit) kullandığı sürücü istismarlarını %99 oranında engeller.
3. **Kendi Yazdığınız Sürücülerde IOCTL Denetimini Asla Atlamayın:**
   - Çekirdek sürücüsü geliştirirken kullanıcıdan gelen her adresi `ProbeForRead` / `ProbeForWrite` ile süzün. Kullanıcıdan gelen bir göstericiye doğrudan `RtlCopyMemory` uygulamak, sisteminize kendi elinizle uzaktan kod çalıştırma (RCE) arka kapısı koymak demektir.
