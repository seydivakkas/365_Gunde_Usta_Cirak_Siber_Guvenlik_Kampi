# G041 — Mini Proje 5: Windows ve Linux Karşılaştırmalı Güvenlik Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Giriş ve Usta-Çırak Açılışı

> **Usta:**  
> *"Evlat, siber güvenlik dünyasına yeni adım atanlar genellikle bir 'fanatizme' kapılır. Kimi çıkar 'Linux asla hacklenmez, Windows delik deşiktir' der; kimi de 'Windows'ta her şey entegre, Linux'ta güvenlik yönetilemez' iddiasında bulunur. Her iki yaklaşım da siber güvenlik mühendisliği açısından cehalettir.  
> Bir güvenlik mimarı hiçbir işletim sistemine duygusal yaklaşmaz. Bizim için bir işletim sistemi, çekirdeği (kernel), bellek modeli, erişim denetimi ve servis yönetim mekanizmalarıyla değerlendirilmesi gereken bir **'Saldırı Yüzeyi' (Attack Surface)** ve **'Savunma Düzlemidir' (Defense Plane)**.  
> Bugün Hafta 06'nın mini projesinde; kurumsal dünyada sırt sırta çalışan Microsoft Windows Server ile Linux'u (Ubuntu Server) masaya yatırıyoruz. Onları fanatikçe değil; CIS Benchmarks ve NIST standartlarında belirlediğimiz **10 Nesnel Güvenlik Göstergesi** üzerinden ölçeceğiz, kodlayacağız ve raporlayacağız."*

---

## 2. Karşılaştırmalı Güvenlik Analizinde 10 Standart Gösterge

İki taban tabana zıt felsefeyle tasarlanmış işletim sistemini adil ve nesnel biçimde karşılaştırmak için aynı fonksiyonel güvenlik hedeflerini temsil eden 10 gösterge seçilmiştir:

```
               [10 STANDART GÜVENLİK GÖSTERGESİ]
 1. Kimlik Doğrulama & Parola Politikası  (PAM vs. Active Directory / LAPS)
 2. Erişim Kontrolü & Yetkilendirme       (POSIX ACL & MAC vs. NTFS DACL/SACL)
 3. Ayrıcalık Yönetimi & Yetki Yükseltme  (sudoers vs. UAC / Token Privileges)
 4. Çekirdek ve Bellek Koruması           (KASLR / Lockdown vs. VBS / HVCI)
 5. Servis ve Süreç İzolasyonu            (systemd Sandboxing vs. NT SERVICE & PPL)
 6. Ağ Güvenlik Duvarı & Port Filtreleme  (nftables vs. Windows Defender WFAS)
 7. Disk Şifreleme & Veri Bütünlüğü       (LUKS2 vs. BitLocker TPM)
 8. Güvenlik Olay Günlüğü & İzleme        (auditd / journald vs. Event Log / Sysmon)
 9. Yama ve Güvenlik Açığı Yönetimi       (APT / Livepatch vs. WSUS / CBS)
10. Uç Nokta Savunması & EDR Entegrasyonu (Wazuh / ClamAV vs. Defender / ASR)
```

---

## 3. Göstergelerin Derinlemesine Teknik İncelemesi

### Gösterge 1: Kimlik Doğrulama ve Parola Politikası
- **Windows Server Yaklaşımı:** Kurumsal ağlarda Active Directory Domain Services (AD DS) ve Kerberos v5 merkezdedir. Yerel parola güvenliği için **LAPS v2 (Local Administrator Password Solution)** kullanılarak her makinenin yerel `Administrator` parolası merkezi olarak dinamik ve benzersiz üretilir. Parola geçmişi, uzunluğu ve karmaşıklığı Grup İlkesi (GPO) ile merkezi dağıtılır.
- **Linux Yaklaşımı:** Kimlik doğrulama omurgası **PAM (Pluggable Authentication Modules)** mimarisine dayanır. `/etc/pam.d/common-password` altında `pam_pwquality` modülü ile entropi ve karmaşıklık zorlanır. Parola ile uzaktan erişim yerine SSH Ed25519 açık/gizli anahtar çiftleri ve FIDO2 belirteçleri tercih edilir; `pam_faillock` ile kaba kuvvet saldırılarına karşı hesap kilitleme uygulanır.

### Gösterge 2: Erişim Kontrolü ve Yetkilendirme Modeli
- **Windows Server Yaklaşımı:** Nesne tabanlı gelişmiş erişim denetimi uygulanır. Her nesne (dosya, kayıt defteri anahtarı, servis) bir **Güvenlik Tanımlayıcısına (SID)** ve **İsteğe Bağlı Erişim Denetim Listesine (DACL)** sahiptir. İzinler okuma, yazma, çalıştırmanın ötesinde 14 farklı granüler izin bayrağına (Delete, ChangePermissions, TakeOwnership vb.) bölünmüştür.
- **Linux Yaklaşımı:** Klasik UNIX modeli olan kullanıcı/grup/diğerleri (`u:g:o`) ve `rwx` bitleri temeldir. Ancak modern sıkılaştırmada bu yetersiz kalır; POSIX ACL (`getfacl`/`setfacl`) ve en önemlisi **Zorunlu Erişim Kontrolü (MAC - AppArmor veya SELinux)** kullanılır. AppArmor, bir süreç root yetkisi kazansa dahi yalnızca profiline tanımlı dosyalara erişebilmesini zorunlu kılar.

### Gösterge 3: Ayrıcalık Yönetimi ve Yetki Yükseltme
- **Windows Server Yaklaşımı:** **Kullanıcı Hesabı Denetimi (UAC)**, yöneticilerin rutin işleri standart belirteçle (standard token) yürütmesini sağlar; idari işlem gerektiğinde onay kutusu çıkar. Ancak yerel yöneticiler grubundaki bir kullanıcının belirteç ayrıcalıkları (`SeDebugPrivilege`, `SeImpersonatePrivilege`) saldırganlar tarafından Potato aileleri (PrintSpoofer, SweetPotato) ile SYSTEM yetkisine yükseltilmek için sıkça istismar edilir.
- **Linux Yaklaşımı:** `root` kullanıcısının doğrudan oturum açması (`PermitRootLogin no`) engellenir. İdari işlemler `/etc/sudoers` ve `/etc/sudoers.d/` altındaki granüler kurallarla yönetilir. Kullanıcıya yalnızca ihtiyacı olan belirli komutları çalıştırma yetkisi verilir ve her yetki yükseltme `auth.log` dosyasına tam komut satırıyla yazılır.

### Gösterge 4: Çekirdek ve Bellek Bütünlüğü Koruması
- **Windows Server Yaklaşımı:** Windows 10/11 ve Server 2022'de çığır açan **Sanallaştırma Tabanlı Güvenlik (VBS - Virtualization-Based Security)** ve **Hypervisor Korumalı Kod Bütünlüğü (HVCI)** yer alır. Windows çekirdeği sanallaştırılmış ayrı bir güvenli dünyada (VTL 1) çalışır; böylece ring 0 seviyesinde bir zafiyet olsa bile imzasız veya kötü niyetli çekirdek kodunun yürütülmesi engellenir.
- **Linux Yaklaşımı:** **KASLR (Kernel Address Space Layout Randomization)** ile çekirdek bellek adresleri rastgeleleştirilir. **Kernel Lockdown** modu ile `/dev/mem`, BPF ve kexec gibi doğrudan çekirdeğe müdahale eden mekanizmalar kısıtlanır. `sysctl` üzerinden `fs.protected_hardlinks=1`, `fs.protected_symlinks=1` ve `kernel.dmesg_restrict=1` ayarları uygulanır.

### Gösterge 5: Servis ve Süreç İzolasyonu / Kum Havuzu (Sandboxing)
- **Windows Server Yaklaşımı:** Servisler uzun yıllar boyunca aşırı yetkili `LocalSystem` altında çalıştırılmıştır. Modern Windows mimarisinde **Hizmet Yalıtımı (Service Isolation)** ile her servis için sanal bir SID (`NT SERVICE\ServiceName`) oluşturulur. Kritik güvenlik süreçleri için **Korumalı Süreç Işığı (PPL - Protected Process Light)** kullanılarak Mimikatz gibi araçların LSASS belleğini okuması çekirdek seviyesinde engellenir.
- **Linux Yaklaşımı:** **systemd** modern Linux'ta olağanüstü bir kum havuzlama yeteneği sunar. Bir servis biriminde:
  ```ini
  [Service]
  ProtectSystem=strict
  ProtectHome=true
  PrivateTmp=true
  NoNewPrivileges=true
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  ```
  yönergeleri eklenerek servisin dosya sisteminin geri kalanına yazması, ev dizinlerini okuması ve yeni ayrıcalıklar kazanması tek satırla engellenir.

### Gösterge 6: Ağ Güvenlik Duvarı ve Port Sınırlandırması
- **Windows Server Yaklaşımı:** **Gelişmiş Güvenlik Özellikli Windows Defender Güvenlik Duvarı (WFAS)**; Etki Alanı, Özel ve Ortak olmak üzere üç farklı ağ profiline göre dinamik kurallar işletir. IPsec kurallarını doğrudan entegre eder ve etki alanı kimlik doğrulamasına dayalı bağlantı filtrelemesi yapabilir.
- **Linux Yaklaşımı:** **nftables** çekirdek düzeyinde yüksek performanslı paket sınıflandırma ve filtreleme sağlar. Girdi (input) zincirinde varsayılan politika `DROP` yapılır; yalnızca belirli kaynak IP'lere izin verilir. `fail2ban` veya `crowdsec` ile log tabanlı dinamik engelleme kuralları anlık olarak nftables tablolarına enjekte edilir.

### Gösterge 7: Dosya Sistemi Bütünlüğü ve Şifreleme
- **Windows Server Yaklaşımı:** **BitLocker Sürücü Şifreleme**, anakart üzerindeki TPM (Trusted Platform Module 2.0) çipi ile donanımsal olarak anahtarlanır ve XTS-AES 256 bit şifreleme sunar. Dosya bütünlüğü için ReFS dosya sistemi bütünlük akışları (Integrity Streams) kullanılır.
- **Linux Yaklaşımı:** **LUKS2 (Linux Unified Key Setup)** ve `dm-crypt` çekirdek modülü üzerinden tam disk şifreleme sağlanır. Çekirdek bütünlüğü için `dm-verity` kullanılır; işletim sistemi ve yapılandırma dosyalarının değiştirilmediğini denetlemek için **AIDE (Advanced Intrusion Detection Environment)** periyodik SHA256 taraması yapar.

### Gösterge 8: Güvenlik Olay Günlükleme ve Denetim
- **Windows Server Yaklaşımı:** Windows Güvenlik Olay Günlüğü (Security Event Log) ve Microsoft'un ücretsiz aracı **Sysmon (System Monitor)** eşsiz bir görünürlük sağlar. Sysmon; İşlem Oluşturma (Event ID 1), Ağ Bağlantısı (Event ID 3), Sürücü Yükleme (Event ID 6) ve LSASS Bellek Erişimi (Event ID 10) gibi saldırgan hareketlerini en ince ayrıntısına kadar kaydeder.
- **Linux Yaklaşımı:** **auditd** Linux Denetim Sistemi, çekirdek sistem çağrılarını (syscalls - `execve`, `ptrace`, `openat`) yakalar. `audit.rules` içine tanımlanan kurallarla belirli dosyaların (`/etc/shadow`, `/etc/sudoers`) okunması veya değiştirilmesi anında loglanır ve `syslog-ng` ile TLS üzerinden merkezi SIEM'e aktarılır.

### Gösterge 9: Yama ve Güvenlik Açığı Yönetimi
- **Windows Server Yaklaşımı:** **WSUS (Windows Server Update Services)** veya Microsoft Endpoint Configuration Manager ile yamalar test gruplarına dağıtılır. Güvenlik bültenleri (Patch Tuesday) ayda bir toplu (cumulative) olarak yayınlanır. En büyük operasyonel zorluk, çekirdek güncellemelerinin sunucunun yeniden başlatılmasını (reboot) zorunlu kılmasıdır.
- **Linux Yaklaşımı:** Paket yöneticisi (APT / DNF) üzerinden paket bazlı hızlı yama dağıtımı yapılır. `unattended-upgrades` ile güvenlik açıkları gecikmeksizin otomatik kapatılır. **Livepatch (Canlı Çekirdek Yamalama)** teknolojisi sayesinde sistem yeniden başlatılmadan çekirdek güvenlik açıkları çalışan bellek üzerinde giderilir.

### Gösterge 10: Zararlı Yazılım ve Uç Nokta (EDR) Savunması
- **Windows Server Yaklaşımı:** Yerleşik **Microsoft Defender Antivirus**, **AMSI (Antimalware Scan Interface)** ve **ASR (Attack Surface Reduction)** kuralları Windows'u bu alanda son derece güçlü kılar. Bellekte yürütülen PowerShell veya VBScript kodları AMSI sayesinde çalışmadan önce taranır; ASR kuralları ise Office belgelerinin alt süreç (child process) başlatmasını engeller.
- **Linux Yaklaşımı:** Açık kaynaklı geleneksel tarayıcılar (ClamAV, rkhunter) genellikle imza tabanlıdır ve gerçek zamanlı engellemede Windows Defender kadar agresif değildir. Bu açık, modern kurumsal ortamlarda **Wazuh**, **Falco** (eBPF tabanlı çekirdek izleme) veya ticari EDR ajanları (CrowdStrike, SentinelOne) ile kapatılır.

---

## 4. Karşılaştırma Sonuçlarının Özeti

| Kriter | Windows Server 2022 | Ubuntu 22.04 LTS | Usta Yorumu |
|---|---|---|---|
| **Toplam Puan (100)** | **81.0** | **85.0** | İki sistem de yetkin yapılandırmayla çok güçlüdür. |
| **En Güçlü Yön** | Çekirdek Koruması (VBS/HVCI) & EDR/AMSI Entegrasyonu | Servis İzolasyonu (systemd), Canlı Yamalama ve Açık Mimari | Windows uç nokta savunmasında, Linux servis kum havuzlamasında öndedir. |
| **En Zayıf Yön** | SYSTEM yetki alanı karmaşıklığı & Yeniden başlatma bağımlılığı | Yerleşik gerçek zamanlı antivirüs eksikliği & EDR gereksinimi | Windows'ta ayrıcalık yönetimi, Linux'ta ek EDR yatırımı dikkat ister. |

---

## 5. Usta-Çırak İpuçları ve Laboratuvar Notu

> **Usta Diyor ki:**  
> *"Evlat, bu mini projede öğrendiğin en büyük ders şudur: 'Daha güvenli işletim sistemi yoktur; doğru sıkılaştırılmış, izlenen ve yama alan işletim sistemi vardır.'  
> Bir Windows sunucuyu varsayılan ayarlarla internete bırakırsan 24 saat içinde ele geçirirler. Bir Linux sunucuda SSH parolasını açık bırakırsan ilk saatte botnet'e döner.  
> Güvenlik bir ürün ya da işletim sistemi tercihi değil; bir **disiplin, sürekli denetim ve en az ayrıcalık felsefesidir**."*
