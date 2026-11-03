# GÜN 021: Mini Proje 2 — İşletim Sistemi Güvenlik Envanteri

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu eğitim materyali Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır. İzinsiz kopyalanamaz, çoğaltılamaz ve ticari amaçla kullanılamaz.*

---

## 1. Derse Giriş ve Kavramsal Çerçeve: "Bilemediğin Şeyi Koruyamazsın"

Sevgili öğrencim, bugün Hafta 03'ün (İşletim Sistemi Temelleri ve Güvenliği) taçlandığı haftalık **Mini Proje 2** günündeyiz. Hafta boyunca CPU/RAM ayrımından çekirdek mimarisine, süreç ve hizmetlerden Windows NTFS ve Linux FHS dosya sistemlerine kadar işletim sistemlerinin tüm derinliklerine indik.

Bugünkü büyük sorumuz şudur: Kurumsal bir siber savunma ekibi (SOC/Blue Team), emrinde bulunan yüzlerce sunucu ve binlerce uç noktayı nasıl denetler ve nasıl güvende tutar?

Siber güvenliğin en temel aforizması şudur: **"Varlığından haberdar olmadığın bir sistemi koruyamazsın; envanterini tutamadığın bir saldırı yüzeyini savunamazsın."**

Küresel güvenlik standartlarının tamamında ilk sırada envanter yer alır:
- **CIS Control 1:** Kurumsal Varlıkların Envanteri ve Denetimi (Inventory and Control of Enterprise Assets).
- **CIS Control 2:** Yazılım Varlıklarının Envanteri ve Denetimi (Inventory and Control of Software Assets).
- **NIST SP 800-53 Rev. 5 (CM-8):** Bilişim Sistemi Bileşen Envanteri (Information System Component Inventory).
- **ISO/IEC 27001:2022 (Madde A.8.1):** Uç Nokta Aygıtları ve Varlıkların Korunması.

Bu mini projede amacımız, hem Windows hem de Linux işletim sistemlerinden standart 5 güvenlik boyutunda envanter toplayan, kurallara göre güvenlik açığı tarayan ve iki farklı dünyayı tek bir analitik pencerede buluşturan **karşılaştırmalı bir envanter motoru** inşa etmektir.

---

## 2. 5 Zorunlu Güvenlik Envanteri Boyutu (G021-SC1)

Güvenlik amaçlı bir işletim sistemi envanteri sıradan bir BT tablosu değildir. Soru bankamızdaki `G021-SC1` gereğince envanter aşağıdaki 5 kritik alanı bağımsız bölümlerde tutmak zorundadır:

### A. İşletim Sistemi ve Sürüm Bilgisi (OS & Kernel)
- **Kapsam:** İşletim sistemi ticari adı, edisyonu (Datacenter, Pro, LTS), çekirdek sürümü (Kernel version / Windows Build), donanım mimarisi (x86_64, ARM64) ve hostname.
- **Güvenlik Önemi:** Destek ömrü bitmiş (End-of-Life - EOL) sistemlerin tespiti. Çekirdek sürümüne göre bilinen Yerel Yetki Yükseltme (Local Privilege Escalation - LPE) açıklarının (örn. Dirty COW, PrintNightmare) varlığı doğrudan bu alandan anlaşılır.

### B. Donanım ve Depolama Mimarisi (Hardware & Storage)
- **Kapsam:** CPU çekirdek sayısı, toplam RAM miktarı, disk bölümleri, dosya sistemi formatları (NTFS/ext4) ve en kritiği **Tam Disk Şifreleme** (BitLocker / LUKS) durumu.
- **Güvenlik Önemi:** Çalınan veya fiziksel erişime uğrayan sunucularda durağan verinin (Data at Rest) korunup korunmadığını doğrular. Ayrıca CPU ve bellek anomalileri izinsiz kripto madencilik zararlılarını (Cryptojacking) açığa çıkarır.

### C. Hesap Yönetimi ve Ayrıcalıklı Erişim (Users & Privileges)
- **Kapsam:** Sistemdeki tüm kullanıcı hesapları, benzersiz kimlikler (SID / UID), yönetici/sudo hakları, hesabın aktiflik/kilitli durumu ve parola son değiştirilme tarihi.
- **Güvenlik Önemi:** En Az Ayrıcalık (Least Privilege) ilkesinin denetimi. Yetkisiz oluşturulmuş "backdoor" hesapların, varsayılan etkin konuk (Guest) hesaplarının ve parolası hiç değiştirilmemiş servis hesaplarının anında yakalanmasını sağlar.

### D. Servisler ve Daemon'lar (Services & Daemons)
- **Kapsam:** Sistemde kayıtlı servisler, çalışma durumları (Running/Stopped), başlangıç türleri (Automatic/Manual/Disabled) ve servisi yürüten kullanıcı hesabı bağlamı (LocalSystem, NetworkService, root).
- **Güvenlik Önemi:** Saldırı yüzeyinin (Attack Surface) daraltılması. Ağ üzerinden şifresiz veri aktaran çağdışı protokollerin (Telnet, FTP, SMBv1, TFTP, Rsh) açık olup olmadığının kontrolü.

### E. Yama ve Güncelleme Yönetimi (Patches & Hotfixes)
- **Kapsam:** Son başarılı güncelleme tarihi, yüklü yama/paket adedi, bekleyen kritik güvenlik yaması sayısı ve yeniden başlatma gereksinimi.
- **Güvenlik Önemi:** Zafiyet Yönetimi (Vulnerability Management). Kurumsal SLA'lar (30 gün içinde kritik yama uygulanması şartı) ve sıfır-gün açıklarına karşı koruma durumu bu alandan takip edilir.

---

## 3. Windows ve Linux Sistem Envanter Mimarilerinin Karşılaştırılması

İki işletim sistemi ailesi aynı güvenlik bilgilerini çok farklı mekanizmalarla depolar ve sunar:

| Güvenlik Alanı | Windows Ortamı Kaynağı | Linux Ortamı Kaynağı |
|---|---|---|
| **OS & Sürüm** | `WMI (Win32_OperatingSystem)`, `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `/etc/os-release`, `uname -r`, `/proc/version` |
| **Donanım & Disk** | `Get-PhysicalDisk`, `Get-BitLockerVolume`, WMI | `/proc/cpuinfo`, `/proc/meminfo`, `lsblk`, `cryptsetup status` |
| **Kullanıcı Hesapları** | `Get-LocalUser`, SAM Veritabanı, Active Directory | `/etc/passwd`, `/etc/shadow`, `getent passwd` |
| **Servisler** | `Get-Service`, Windows Service Control Manager (SCM), Registry | `systemctl list-units --type=service`, `/etc/systemd/system/` |
| **Yamalar** | `Get-HotFix`, Windows Update Agent (WUA API) | `apt list --upgradable`, `dnf check-update`, Unattended-Upgrades logları |

Güvenlik mühendisinin görevi, bu heterojen kaynaklardan gelen veriyi ortak bir veri modeline (JSON şeması) dönüştürmek (Normalizasyon) ve merkezi SIEM/SOAR platformuna beslemektir.

---

## 4. Karşılaştırmalı CSV Şablonu Mimarisi (G021-SC2)

Soru bankası `G021-SC2` gereğince geliştirdiğimiz motor, Windows ve Linux envanterlerini yan yana kıyaslayan 5 kolonlu standart bir analitik matris üretir:
1. `kategori`: Envanter boyutu (OS Bilgisi, Donanım, Hesap Yönetimi, Servisler, Yama Yönetimi).
2. `ozellik_adi`: Kıyaslanan parametre (örn. Birincil Dosya Sistemi ve Şifreleme).
3. `windows_degeri`: Windows sunucusunun mevcut durumu (örn. NTFS - BitLocker Etkin).
4. `linux_degeri`: Linux sunucusunun mevcut durumu (örn. ext4 - LUKS2 Etkin).
5. `guvenlik_onemi_ve_etkisi`: Bulgunun siber güvenlik açısından anlamı ve CIS/NIST riski.

Bu çıktı sayesinde bir denetçi tek bir raporda kurumun hem Windows hem de Linux ortamlarındaki güvenlik duruşunu (security posture) eksiksiz görebilir.

---

## 5. Saldırı Vektörleri ve Envanter Kör Noktaları

Saldırganlar envanter açıklarından nasıl yararlanır?
1. **Gölge BT (Shadow IT) ve Unmanaged Assets:** Güvenlik ekiplerinin envanterinde kayıtlı olmayan bir test sunucusu saldırganın ilk sızma noktası olur.
2. **Kapatılması Unutulan Güvensiz Servisler:** Sistem yöneticisinin geçici olarak açıp unuttuğu bir Telnet veya SMBv1 servisi üzerinden parola koklama (sniffing) ve EternalBlue tarzı RCE saldırıları yapılır.
3. **Yetkisiz Yönetici Hesapları:** Bir geliştiriciye geçici verilen Local Admin yetkisi geri alınmadığında saldırgan Pass-the-Hash veya token impersonation ile yetki yükseltir.
4. **Yama Gecikmesi (Patch Lag):** "Sistem çalışıyorsa dokunma" anlayışıyla 6 aydır güncellenmeyen bir sunucu bilinen N-Day zafiyetleriyle saniyeler içinde ele geçirilir.

---

## 6. Savunma, Denetim ve Otomasyon Stratejileri

Modern kurumsal savunmada envanter yönetimi şu adımlarla icra edilir:
1. **Sürekli Otomatik Keşif (Continuous Discovery):** Ağ tabanlı pasif dinleyiciler ve aktif ajanlar (Agent-based) aracılığıyla ağa katılan her yeni cihaz anında CMDB'ye kaydedilmelidir.
2. **Fark Raporlama (Diff / Baseline Auditing):** Sistemler altın imaj (Golden Image) ile periyodik olarak karşılaştırılmalı; onaylanmamış yeni bir servis veya kullanıcı açıldığında SOC'a anında alarm düşmelidir.
3. **Otomatik İyileştirme (Automated Remediation):** Karalistedeki bir servis (Telnet) tespit edildiğinde SOAR betiği servisi otomatik durdurmalı ve portunu güvenlik duvarından engellemelidir.

---

## 7. Usta Notu, Haftalık Aşama Özeti ve Hafta 04'e Geçiş

> **Usta Diyor ki:**  
> "Evlat, 3 haftalık zorlu yolculuğumuzda Aşama 01'i (Güvenlik Temelleri) ve ardından Aşama 02'nin ilk haftasını (İşletim Sistemleri Mimarisi) başarıyla tamamladın. Artık bir dosyanın uzantısına değil sihirli baytlarına bakan, NTFS izinleri ile Linux FHS izolasyonunu ayırt edebilen ve hem Windows hem Linux sunucuların güvenlik röntgenini çekebilen bir mühendis bakış açısına sahipsin.  
> 
> Yarın başlayacağımız **Hafta 04** ile birlikte sistemlerin birbiriyle konuştuğu devasa dünyaya, **Ağ Temelleri, TCP/IP, OSI Modeli ve Ağ Paket Analizi** diyarına adım atacağız. Hazır ol; işletim sistemleri kale ise, ağ o kaleleri birbirine bağlayan köprülerdir!"
