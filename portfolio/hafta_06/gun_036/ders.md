# GÜN 36: BELLEK, SANAL BELLEK VE SWAP GÜVENLİĞİ
## Usta-Çırak / Hoca Dersi Notları (Hafta 06 Başlangıcı)

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
Evlat, Hafta 06'ya hoş geldin. Artık işletim sisteminin yüzeysel dosyalarından ve süreç pencerelerinden çıkıp donanımın kalbine, yani **Bellek Mimarisine (RAM, Sanal Bellek ve Swap)** iniyoruz.

Birçok acemi yazılımcı ve sistem yöneticisi belleği (RAM) "uçucu" (volatile), yani bilgisayar kapandığında sıfırlanan geçici bir karalama defteri zanneder. Bu yüzden en gizli verilerini (kullanıcı parolaları, veri tabanı bağlantı şifreleri, kriptografik özel anahtarlar, oturum çerezleri) bellekte açık metin (cleartext) olarak tutmakta hiçbir sakınca görmezler.

İşte tam bu noktada sistemin "hayat kurtarıcısı" olarak tasarlanan **Sayfalama (Paging)** ve **Takas Alanı (Swap / Pagefile)** mekanizması, güvenlik dünyasının en büyük kabusuna dönüşebilir!

Bugün seninle şu temel ilkeyi derinlemesine inceleyeceğiz:
> **"Sanal bellek adresleme, bellek izolasyonu ve sayfalama için kullanılır; swap kalıcı depoda hassas veri kalıntısı (Data Remanence) oluşturabilir."**

---

### 2. Sanal Bellek (Virtual Memory) ve Bellek İzolasyonu

Modern işletim sistemlerinde hiçbir kullanıcı süreci fiziksel RAM çiplerinin adreslerine doğrudan erişemez. Bunun yerine her sürece sanki makinedeki tüm bellek yalnızca kendisine aitmiş gibi devasa bir **Sanal Adres Uzayı (Virtual Address Space)** sunulur.

#### A. Süreç Bellek İzolasyonu (Process Isolation)
64-bit bir işletim sisteminde her süreç kendi sanal dünyasında yaşar:
- **Kullanıcı Modu (User Space - Ring 3):** Sürecin kendi kodunun, yığınının (Stack) ve öbeğinin (Heap) bulunduğu alandır.
- **Çekirdek Modu (Kernel Space - Ring 0):** İşletim sistemi çekirdeğinin ve sürücülerinin çalıştığı, kullanıcı süreçlerinin doğrudan yazamadığı korumalı alandır.

İki süreç aynı sanal adresi kullansa dahi (örneğin her iki süreçte de `0x00007FFF1000` adresi olsa bile), donanımsal **Bellek Yönetim Birimi (MMU - Memory Management Unit)** ve her sürece özel **Sayfa Tabloları (Page Tables)** bu adresleri fiziksel RAM'de tamamen farklı alanlara eşler. Bu sayede Süreç A, Süreç B'nin verisini doğrudan okuyamaz veya ezemez.

---

### 3. Sayfalama (Paging) ve Swap / Pagefile Mekanizması

Fiziksel RAM sınırlı bir kaynaktır (Örn: 8 GB veya 16 GB). Sistemde çalışan yüzlerce süreç ve servis aynı anda RAM talep ettiğinde ne olur? İşletim sistemi çöker mi?

Hayır! İşletim sistemi belleği **Sayfa (Page)** adı verilen sabit boyutlu bloklara (genellikle 4 KB) böler:
1. **Aktif Sayfalar:** İşlemcinin o an üzerinde işlem yaptığı kod ve veri sayfaları fiziksel RAM'de tutulur.
2. **İnaktif Sayfalar (Page-Out / Swapping):** Uzun süredir erişilmeyen veya arka planda uyuyan süreçlerin sayfaları, fiziksel RAM'de yer açmak için sabit diske yazılır.
   - Windows'ta bu dosya: `C:\pagefile.sys` (ve modern Windows'ta UWP için `swapfile.sys`)
   - Linux'ta bu alan: Özel bir swap bölümü (partition) veya `/var/swapfile` dosyasıdır.
3. **Sayfa Hatası (Page Fault):** Süreç, diske aktarılmış bir sayfaya erişmek istediğinde donanım bir kesme (Interrupt 14 - Page Fault) üretir. İşletim sistemi çekirdeği sayfayı diskten okuyup tekrar RAM'e taşır (Page-In).

---

### 4. Güvenlik Riski: Kalıcı Depoda Hassas Veri Kalıntısı (Data Remanence)

İşte zurnanın zırt dediği yer burasıdır evlat!
- **RAM uçucudur:** Güç kesildiğinde içerik kaybolur.
- **Swap / Pagefile KALICIDIR (Non-Volatile):** Sabit disktedir!

Diyelim ki bir kripto para cüzdanı, bir VPN istemcisi ya da bir web tarayıcısı kullanıcının parolasını veya SSL/TLS özel anahtarını bellekte tutuyor. Sistem bellek baskısı yaşadığında, işletim sistemi bu sürecin bellek sayfasını alır ve **şifresiz olarak diskteki swap alanına yazar!**

#### Saldırı Senaryosu (Offline Disk Analysis / Cold Forensics):
Saldırgan sunucuyu veya dizüstü bilgisayarı ele geçirdiğinde:
1. Bilgisayarı kapatır ve diski söker.
2. Diski adli bilişim iş istasyonuna bağlar.
3. `/var/swapfile` veya `pagefile.sys` dosyasını açıp basit bir dize arama komutu çalıştırır:
   ```bash
   strings /var/swapfile | grep -E "BEGIN RSA|password=|API_KEY="
   ```
4. Şifresiz takas alanı sayesinde, oturumu kapanmış kullanıcıların bile tüm açık metin sırları, oturum çerezleri ve parolaları ele geçirilir!

---

### 5. Bellek Saldırı Vektörleri

1. **Bellek Kazıma (Memory Scraping / OS Credential Dumping - MITRE T1003.001):**
   Saldırgan yüksek yetki elde ettikten sonra işletim sistemi API'lerini (`OpenProcess`, `ReadProcessMemory`, `MiniDumpWriteDump`) kullanarak `lsass.exe` (Local Security Authority) sürecinin belleğini diske döker. Mimikatz veya benzeri araçlarla NTLM hash'lerini ve Kerberos biletlerini çalar.
2. **Kapanışta Sayfa Dosyasının Temizlenmemesi:**
   Windows varsayılan olarak performansı düşürmemek için bilgisayar kapanırken `pagefile.sys` dosyasını sıfırlamaz (üzerine sıfır yazmaz). Bu durum saldırgana kalıntı veriyi inceleme fırsatı verir.
3. **Bellek Kilitleme (Memory Locking) İhmali:**
   Geliştiriciler hassas anahtarları işlerken işletim sistemine "Bu sayfayı asla diske yazma, RAM'de kilitle" demeyi unuturlar.

---

### 6. Defansif Sıkılaştırma ve Karşı Önlemler

1. **Swap Şifreleme (Encrypted Swap):**
   - **Linux:** Swap alanı `dm-crypt` / `cryptsetup` veya sistem başlatılırken rastgele bir anahtarla şifrelenen `/dev/mapper/cryptswap` ile korunmalıdır. Bilgisayar kapandığında şifreleme anahtarı yok olduğu için diskteki swap verisi anlamsız gürültüye dönüşür.
   - **Windows:** BitLocker tüm sürücüyü şifrelediği için `pagefile.sys` dosyasını da korur. Ayrıca bağımsız sayfa dosyası şifrelemesi açılabilir:
     ```cmd
     fsutil behavior set EncryptPagingFile 1
     ```
2. **Kapanışta Sayfa Dosyasını Sıfırlama:**
   Windows sistemlerde kapatma anında pagefile'ın üzerine sıfır yazılarak artık verilerin silinmesi sağlanmalıdır:
   ```reg
   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
   ClearPageFileAtShutdown = 1 (DWORD)
   ```
3. **Yazılım Geliştiriciler İçin Bellek Kilitleme (mlock / VirtualLock):**
   Hassas veri (parola, API anahtarı, private key) işleyen yazılımlar:
   - Linux C/C++: `mlock(ptr, size)`
   - Windows Win32 API: `VirtualLock(ptr, size)`
   - Bu çağrılar işletim sistemi çekirdeğine o bellek sayfasını asla swap'e taşımaması talimatını verir.
4. **LSASS Koruması:**
   - **LSA Protection (RunAsPPL):** LSASS sürecini "Korumalı Süreç Işığı" (Protected Process Light) moduna alarak yönetici dahi olsa harici süreçlerin bellek okumasını bloke eder.
   - **Windows Defender Credential Guard:** LSASS kimlik doğrulama sırlarını sanallaştırma tabanlı güvenlik (VBS / Hyper-V) ile izole edilmiş bir mikro çekirdeğe taşır.

---

### Resmî Kaynaklar
- Microsoft Learn: [Virtual Memory Architecture](https://learn.microsoft.com/en-us/windows/win32/memory/about-memory-management)
- Microsoft Learn: [Configuring Additional LSA Protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- MITRE ATT&CK: [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- NIST SP 800-88: [Guidelines for Media Sanitization (Data Remanence)](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
