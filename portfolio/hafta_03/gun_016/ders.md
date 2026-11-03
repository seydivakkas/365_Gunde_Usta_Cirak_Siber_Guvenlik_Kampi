# GÜN 016: DERS NOTLARI
# CPU, RAM ve Depolama Ayrımı: Düşük Seviyeli Güvenlik Mimarisi, Uçuculuk ve Veri Kalıntısı

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim  
> amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez,  
> satılamaz veya tersine mühendislik yapılamaz.

---

## BÖLÜM 1: Giriş ve Kavramsal Çerçeve

Siber güvenlik operasyonlarında en ölümcül yanılgılardan biri, verinin "program kapandığında" veya "dosya silindiğinde" yok olduğunu varsaymaktır. Modern bilgi işlem sistemleri, John von Neumann'ın temellerini attığı mimari prensipler üzerine kuruludur. Bu mimaride donanım bileşenleri üç temel katmana ayrılır:
1. **Merkezi İşlem Birimi (CPU - Central Processing Unit):** Komutları yorumlayan ve çalıştıran, yazmaçlar (registers) ve çok katmanlı önbelleklerden (L1, L2, L3) oluşan ultra-hızlı, ultra-uçucu yürütme motoru.
2. **Rastgele Erişimli Bellek (RAM - Random Access Memory):** İşletim sisteminin ve çalışan süreçlerin dinamik kod ve verilerini tutan, milisaniyeler yerine nanosaniyeler seviyesinde erişim sağlayan uçucu (volatile) çalışma alanı.
3. **Kalıcı İkincil Depolama (Storage - SSD, HDD, NVMe):** Bilgisayar kapatıldığında veya elektrik kesildiğinde dahi verinin korunmasını sağlayan kalıcı (non-volatile) manyetik veya flash hafıza ortamı.

Siber savunma ve adli bilişim (digital forensics) uzmanları için bu üç katman yalnızca hız ve kapasite farkı değil; **veri yaşam döngüsü**, **yetki sınırları (protection rings)**, **uçuculuk derecesi (order of volatility)** ve **veri kalıntısı (data remanence)** açısından kritik güvenlik sınırları oluşturur.

Bir kriptografik özel anahtar CPU yazmacında işlenirken, heap belleğe kopyalandığında ve işletim sisteminin bellek yetersizliği nedeniyle bu heap bloğunu sabit diskteki `pagefile.sys` (takas/sayfalama) dosyasına yazması durumunda; mikro saniyelik bir geçici veri birdenbire aylarca diskte kalacak kalıcı bir istismar hedefine dönüşür. Bu derste, donanım katmanlarının sınırlarını, bu sınırlar arasındaki sızıntı vektörlerini ve kurumsal sertleştirme prensiplerini inceleyeceğiz.

---

## BÖLÜM 2: Düşük Seviyeli Mimari ve Bellek Hiyerarşisi

### 2.1. Donanım Katmanları ve Erişim Gecikmeleri (Latency Pyramid)

Bir verinin işlemci çekirdeğine olan fiziksel mesafesi arttıkça erişim gecikmesi (latency) katlanarak büyürken, kalıcılık (persistence) artar:

| Donanım Katmanı | Tipik Kapasite | Erişim Gecikmesi | Uçuculuk Karakteri | Tipik İçerik |
|---|---|---|---|---|
| **CPU Yazmaçları (RAX, RBX...)** | Baytlar (ör. 16 x 64-bit) | ~0.5 - 1 ns | Ultra-Uçucu | Anlık işlenen değişken, gösterici, parola parçası |
| **L1 / L2 / L3 Önbellek** | 64 KB - 32 MB | ~1 - 15 ns | Ultra-Uçucu | Sık erişilen kod satırları, veri blokları |
| **Ana Bellek (DRAM / RAM)** | 8 GB - 512 GB | ~50 - 100 ns | Uçucu (DRAM) | Süreç bellek alanları (Stack, Heap, BSS) |
| **NVMe / SSD Depolama** | 256 GB - 8 TB | ~10 - 100 µs | Kalıcı (NAND) | Dosya sistemleri, İşletim sistemi çekirdeği, Pagefile |
| **Manyetik HDD / Teyp** | 1 TB - 20 TB+ | ~5 - 15 ms | Kalıcı (Manyetik) | Arşivler, yedekler, günlük kayıtları |

### 2.2. İşlemci Koruma Halkaları (Protection Rings)

x86 ve x86-64 mimarilerinde donanım güvenliği **Halka Hiyerarşisi (Privilege Rings)** ile sağlanır:
- **Ring 0 (Kernel Mode / Çekirdek Kipi):** İşletim sistemi çekirdeği (kernel) ve donanım sürücüleri çalışır. Tüm fiziksel belleğe, CPU komut setlerine (`CR0`, `CR3`, `MSR` kayıtçıları) ve I/O portlarına doğrudan erişim hakkına sahiptir.
- **Ring 1 ve Ring 2:** Tarihsel olarak aygıt sürücüleri veya hipervizör servisleri için ayrılmış olsa da modern genel amaçlı işletim sistemlerinde (Windows, Linux, macOS) doğrudan kullanılmaz.
- **Ring 3 (User Mode / Kullanıcı Kipi):** Kullanıcı uygulamaları (tarayıcı, veritabanı, ofis araçları, Python yorumlayıcısı) bu halkada çalışır. Fiziksel donanıma veya doğrudan bellek adreslerine erişemezler; tüm erişimler çekirdek sistem çağrıları (`syscall`, `sysenter`) aracılığıyla denetlenir.

---

## BÖLÜM 3: Uçuculuk (Volatility) ve Veri Kalıntısı (Data Remanence) Dinamikleri

### 3.1. Uçuculuk Sıralaması (RFC 3227 - Order of Volatility)

Olay müdahalesi (Incident Response) ve adli bilişim incelemelerinde delil toplama sırası, verinin kaybolma hızına göre belirlenir:
1. **CPU Yazmaçları ve Önbellek (En Uçucu):** Sistem kapandığı veya yeniden başlatıldığı anda anında silinir.
2. **Yönlendirme Tabloları, ARP Önbelleği, Süreç Tablosu, Çekirdek Belleği**
3. **Geçici Dosya Sistemleri ve RAM İçeriği**
4. **Kalıcı Depolama (Diskler, SSD, Harici Medya - En Az Uçucu)**

### 3.2. Bellek Hijyeni ve Güvenli Sıfırlama (Secure Zeroing vs. Plain Free)

C veya C++ gibi dillerde bir bellek bloğu `malloc()` ile tahsis edilip iş bittiğinde `free(ptr)` fonksiyonu çağrıldığında, işletim sistemi ve bellek yöneticisi o bloğu yalnızca "kullanılabilir" olarak işaretler; **içindeki baytları temizlemez!**

```c
// GÜVENSİZ YAKLAŞIM (Plain Free)
char *password = malloc(32);
strcpy(password, "SuperGizliParola123");
// ... parola kullanıldı ...
free(password); // FELAKET: "SuperGizliParola123" heap bellekte aynen duruyor!
```

Eğer bir saldırgan `Use-After-Free` (UAF) zaafiyeti tetiklerse veya `procdump` / `Mimikatz` ile sürecin bellek dökümünü alırsa, bu açık metin parolayı kolaylıkla okur.

**Güvenli Yaklaşım:**
Bellek serbest bırakılmadan önce sıfırlanmalıdır. Ancak standart `memset(password, 0, 32)` derleyici optimizasyonları (Dead Code Elimination) tarafından "bu bellek zaten serbest bırakılıyor, yazmaya gerek yok" denilerek silinebilir! Bu nedenle işletim sistemlerinin optimize edilmeyen güvenli fonksiyonları kullanılmalıdır:
- Windows: `SecureZeroMemory(password, 32);`
- C11 Standartı: `memset_s(password, 32, 0, 32);`
- Linux: `explicit_bzero(password, 32);`

### 3.3. RAM'den Depolamaya Sızıntı: Sayfalama (Paging/Swap) ve Hazırda Beklet (Hibernation)

İşletim sistemi RAM tükendiğinde veya optimizasyon amacıyla etkin olmayan bellek sayfalarını diske yazar:
- Windows: `C:\pagefile.sys` ve `C:\swapfile.sys`
- Linux: `/swapfile` veya Swap Bölümü
- Hibernation: `C:\hiberfil.sys` (Bilgisayar uykuya geçerken tüm RAM disk dosyasına kopyalanır).

Eğer yazılımınız RAM'deki hassas bir oturum belirtecini `VirtualLock()` (Windows) veya `mlock()` (Linux) fonksiyonlarıyla belleğe kilitlemezse, işletim sistemi bu anahtarı açık metin olarak diske kaydeder. Disk şifrelenmemişse veya bilgisayar kapalıyken disk sökülürse, saldırgan `pagefile.sys` içerisinden açık metin kimlik bilgilerini çeker!

### 3.4. Depolamada Veri Kalıntısı ve Dosya Kurtarma (File Carving)

Bir dosya işletim sisteminde "silindiğinde" (örneğin Windows'ta Shift+Delete veya Linux'ta `rm dosya.txt`), diskin ilgili sektörlerindeki veriler ezilmez. Yalnızca dosya sistemi tablosundaki (NTFS MFT veya Linux Inode) dosya göstericisi boş olarak işaretlenir.

Adli bilişim uzmanları `PhotoRec`, `TestDisk` veya `Autopsy` gibi araçlarla **File Carving** uygulayarak dosya başlığı (`magic bytes`) ve alt sektörleri tarar ve silinmiş dosyaları eksiksiz geri getirir. NIST SP 800-88 standardı, diskler elden çıkarılmadan önce verilerin çoklu geçişle ezilmesini (Clear/Purge) veya fiziksel olarak yok edilmesini (Destroy) zorunlu kılar.

---

## BÖLÜM 4: Savunma Mimarisi ve Sertleştirme Standartları

1. **DEP / NX (Data Execution Prevention / No-Execute):**
   - Bellek sayfalarına `PAGE_EXECUTE_READ` veya `PAGE_READWRITE` bayrakları atanarak yığıt (Stack) ve öbek (Heap) alanlarında kod çalıştırılması donanımsal olarak engellenir.
2. **ASLR (Address Space Layout Randomization):**
   - Programın yürütülebilir kodu, kütüphaneleri, yığıtı ve öbeği her çalıştırmada rastgele bellek adreslerine yerleştirilir. Saldırganın sabit adreslere zıplaması (`buffer overflow` ve ROP zincirleri) zorlaştırılır.
3. **Tam Disk Şifreleme (FDE - Full Disk Encryption):**
   - Windows BitLocker (XTS-AES-256) veya Linux LUKS. Çalınan dizüstü bilgisayarlarda `pagefile.sys` veya silinmiş verilerin doğrudan okunmasını engeller.
4. **ClearPageFileAtShutdown Sertleştirmesi:**
   - Windows Kayıt Defteri ayarı: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown = 1`. Sistem kapanırken sayfalama dosyasının üzerine sıfır yazılarak RAM kalıntılarının diskte kalması engellenir.

---

## BÖLÜM 5: Uygulama Mimarisi ve Kod Açıklaması

Bu modülde geliştirdiğimiz `portfolio/hafta_03/gun_016/uygulama/system_hardware_boundary_auditor.py` aracı, donanım katmanlarını ayrıştıran ve veri kalıntısı risklerini denetleyen bir güvenlik analizörüdür:

1. `get_live_hardware_inventory()`:
   - Standart Python `platform`, `os` ve `shutil` kütüphanelerini kullanarak harici bağımlılık olmadan yerel makinenin CPU mimarisini, çekirdek sayısını, 32/64 bit bellek genişliğini ve kök disk kullanım alanını canlı olarak sorgular.
2. `evaluate_data_remanence(memory_object)`:
   - Verilen bir bellek nesnesinin hangi katmanda olduğunu, şifreli olup olmadığını, `mlock` kullanılıp kullanılmadığını ve güvenli sıfırlama (`SecureZeroMemory`) yapılıp yapılmadığını denetler.
3. `audit_hardware_security(hardware_data, baseline_data)`:
   - CIS Benchmarks ve NIST kontrollerine göre CPU yan kanal yamalarını, ASLR/DEP durumunu, tam disk şifrelemeyi ve sayfalama dosyası kapanış temizleme ayarlarını puanlar.
4. `simulate_memory_lifecycle(secret_bytes, use_secure_zero)`:
   - Bellek üzerinde bir bayt dizisinin tahsisini ve `use_secure_zero=True` (tüm baytların `0x00` ile ezilmesi) ile `use_secure_zero=False` (tamponun dokunulmadan bırakılması) arasındaki adli kalıntı farkını hex düzeyinde kanıtlar.

---

## BÖLÜM 6: Doğrulama, Test ve Güvenlik Kanıtları

Test paketimiz (`tests/test_system_hardware_boundary_auditor.py`) 14 bağımsız birim testinden oluşur:
- **Pozitif Testler:** Canlı CPU, RAM ve depolama metriklerinin okunması, güvenli bellek sıfırlamada sıfır kalıntı kaldığının (`00` hex) doğrulanması, CLI alt süreç yürütmesi.
- **Negatif Testler:** Var olmayan dosya istendiğinde `FileNotFoundError` fırlatılması, `plain_free` senaryosunda hassas verinin bellekte aynen kaldığının adli olarak kanıtlanması.
- **Sertleştirme Testleri:** Kapanışta pagefile temizliğinin kapalı olması durumunda denetleyicinin `RULE-STORAGE-002` kural ihlalini yakalaması.

Tüm testler **14/14 PASS (%100 Başarı)** ile tamamlanmış ve `kanit/gercek/` altına işlenmiştir.

---

## BÖLÜM 7: Usta Çırak Nasihatleri ve Saha Tecrübeleri

1. **"Bellek Uçucudur" Efsanesine İnanma:**
   - 2008 yılındaki meşhur Princeton Üniversitesi araştırması (Cold Boot Attack), bilgisayar kapatıldıktan sonra dahi sıvı nitrojen veya soğutucu sprey sıkılarak RAM yongalarının dakikalarca veri tutabildiğini ve başka bir makinede okunabildiğini kanıtlamıştır.
2. **Kapanışta Takas Temizliğini Aç:**
   - Kurumsal sunucu ve istemcilerde `ClearPageFileAtShutdown` politikasını mutlaka etkinleştirin. Bilgisayarın kapanması 10-15 saniye uzayabilir; ancak diskten LSASS kimlik dökümü alınmasını engellemenin bedeli bu küçük beklemedir.
3. **Parolaları String (Dize) Olarak Tutma:**
   - Java, C# veya Python'da `String` nesneleri değiştirilemezdir (immutable). Parolayı bir String nesnesine atadığınızda, çöp toplayıcı (Garbage Collector) çalışana kadar o veri bellek havuzunda (String Pool) açık metin olarak yatar ve siz onu `zeroize` edemezsiniz. Hassas verileri her zaman değiştirilebilir bayt dizilerinde (`bytearray`, `char[]`) tutun ve işiniz biter bitmez sıfırlayın.
