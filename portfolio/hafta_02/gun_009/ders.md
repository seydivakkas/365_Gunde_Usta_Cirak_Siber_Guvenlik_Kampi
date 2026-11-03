# GÜN 009: Windows Üzerinde Laboratuvar Hazırlığı
**Aşama 01: Temel Kavramlar ve Tehdit Ortamı | Hafta 02: Güvenli Ortam ve Temel Altyapı**

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Süre](https://img.shields.io/badge/s%C3%BCre-90%20dakika-blue?style=flat-square)
![Seviye](https://img.shields.io/badge/seviye-Temel%20%2F%20Orta-orange?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, hoş geldin. Dün sanallaştırmanın felsefesini, Hypervisor katmanını ve BSL-4 eldivenli cam kabin analojisini zihnimize nakış gibi işledik. Bugün ise doğrudan kendi fiziksel çalışma masamıza oturuyoruz: **Windows İşletim Sistemi Üzerinde Güvenli Bir Siber Güvenlik Laboratuvarı Kurmak.**

Dünya üzerindeki son kullanıcı ve kurumsal iş istasyonlarının %70'ten fazlası Windows üzerinde koşuyor. Dolayısıyla bir siber güvenlik uzmanı olarak analiz edeceğin zararlı yazılımların, inceleyeceğin olayların (incident response) ve sızma testlerinde hedef alacağın mekanizmaların ezici çoğunluğu Windows mimarisindedir.

Peki, Windows bilgisayarında bir zararlı yazılımı veya şüpheli bir aracı nasıl güvenle inceleyebilirsin?
Sana harika bir zihinsel model vereyim: **Kimya Laboratuvarındaki Çekerocak (Fume Hood)!**

Düşün ki evinde veya laboratuvarında zehirli gaz çıkaran bir kimyasal deney yapacaksın. Bunu odanın ortasındaki masada yaparsan tüm evi zehirlersin. Ne yaparsın? Odaya özel havalandırmalı, cam panelli bir **Çekerocak (Fume Hood)** koyarsın. Gaz sadece o kabinin içinde kalır, dışarıya sızamaz.

İşte Windows işletim sistemi, Windows 10/11 ile birlikte kendi içinde olağanüstü yerleşik güvenlik çekerocakları sunmaya başladı:
1. **Windows Sandbox (WSB):** Dünyanın en pratik, tek kullanımlık (disposable) mikro-laboratuvarıdır. Çift tıklarsın, 15 saniyede tertemiz bir Windows açılır; zararlıyı içine atar, patlatır, izlersin; pencereyi kapattığın an içindeki her bir bit ve bayt geri getirilemez şekilde yok olur!
2. **Hyper-V İzolasyonlu Sanal Anahtar (vSwitch):** Laboratuvarındaki sanal makineleri (Flare-VM, Kali, REMnux) fiziksel ev modeminden ve şirket ağından tamamen koparan sanal hava boşluğu (Air-Gap) kalkanı.
3. **WSL2 (Windows Subsystem for Linux 2):** Linux tabanlı siber güvenlik araçlarını (Nmap, Wireshark, Radare2, GDB) yerel Windows sistemini bozmadan, Hyper-V mikro-çekirdeğinde çalıştırma konforu.
4. **Windows Defender Antivirüs Dışlama Kalkanı (Exclusion Hardening):** Güvenlik araçlarının (Mimikatz, Sysinternals vb.) Defender tarafından silinmesini engellerken, saldırganların bu dışlamayı istismar etmesini (**Exclusion Hijacking**) önleyen katı NTFS erişim denetimi (ACL).

Fakat dikkat et evlat: Windows Sandbox'ın ağını açık bırakırsan veya Defender'a *"C:\ diskini tarama"* dersen; çekerocağın camını kırmış olursun ve zehirli gaz doğrudan konak sistemine dolar! Bugün bu derste Windows'u kurşun geçirmez bir analiz kalesine dönüştürmeyi öğreneceksin.

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### A. Windows Çekirdeğinde Sanallaştırma: VBS ve HVCI

Modern bir Windows 11/10 sisteminde güvenlik, sadece bir antivirüs programından ibaret değildir; doğrudan işlemci donanımına yaslanır:
* **Hyper-V Hipervizörü:** Windows açılırken donanım üzerinde ilk başlayan yazılımdır (Tip-1 mimari). Windows'un ana işletim sistemi bile aslında Hyper-V'nin *Root Partition* (Kök Bölümü) üzerinde çalışır.
* **VBS (Virtualization-Based Security - Sanallaştırma Tabanlı Güvenlik):** Windows çekirdeğinin kritik bellek alanlarını ve güvenlik servislerini (örneğin kullanıcı parolalarını ve oturum anahtarlarını tutan `LSASS.exe`) donanımsal olarak izole edilmiş güvenli bir bölgeye (**Trustlet / VSM - Virtual Secure Mode**) hapseder. Bir saldırgan Ring 0 çekirdek yetkisi alsa dahi, VBS kalkanı sayesinde LSASS belleğini doğrudan okuyamaz (Mimikatz gibi araçlar pass-the-hash saldırısı yapamaz).
* **HVCI (Hypervisor-Protected Code Integrity - Bellek Bütünlüğü):** Çekirdek modunda çalışacak tüm sürücülerin kriptografik olarak imzalanmış ve onaylanmış olduğunu doğrular. Saldırganların güvenlik açıklarına sahip eski sürücüleri kullanarak konak çekirdeğini ele geçirmesini (**BYOVD - Bring Your Own Vulnerable Driver**) engeller.

### B. Windows Sandbox (WSB) Mimarisi ve `.wsb` Yapılandırması

Windows Sandbox, geleneksel ağır sanal makinelerden (VirtualBox, VMware) çok farklı bir mühendislik harikasıdır:
* **Dinamik Temel İmaj (Dynamic Base Image):** Sandbox için ayrı bir 30 GB'lık disk imajı indirmezsin! Konak Windows işletim sisteminin halihazırda var olan sistem dosyalarını salt-okunur olarak bağlar; sadece misafirde değişen baytları RAM tabanlı geçici bir katmana (Copy-on-Write) yazar. Bu yüzden 100 MB disk tüketir ve saniyeler içinde açılır.
* **Tek Kullanımlık Yaşam Döngüsü (Disposable Lifecycle):** Sandbox kapatıldığı anda o oturuma ait tüm RAM sayfaları ve geçici disk katmanı kalıcı olarak bellekten silinir. Sıfırlama işlemi donanımsal düzeyde gerçekleşir; virüsün kalıcılık (persistence) sağlama şansı sıfırdır.
* **`.wsb` Dosya Mimarisi:** Windows Sandbox, XML formatında bir `.wsb` dosyası ile yönetilir. Bir güvenlik laboratuvarında bu dosyanın kritik ayarları şunlardır:

```xml
<Configuration>
  <!-- 1. vGPU İzolasyonu: Grafik sürücüsü açıklarından kaçışı önlemek için Disable -->
  <VGpu>Disable</VGpu>
  
  <!-- 2. Ağ İzolasyonu: Zararlının C2 iletişimi ve veri kaçırmasını önlemek için Disable -->
  <Networking>Disable</Networking>
  
  <!-- 3. Eşlenen Klasörler: Numuneleri aktarırken KONAK DİSKİNİ KORUMAK İÇİN ReadOnly=true -->
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Guvenli_Lab\Incelenecek_Numuneler</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\Numuneler</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  
  <!-- 4. Bellek Sınırı: Konak sistemin kilitlenmesini önlemek için RAM kotası -->
  <MemoryInMB>4096</MemoryInMB>
</Configuration>
```

### C. Hyper-V Sanal Anahtar (vSwitch) Türleri ve Ağ Bölümleme

Windows üzerinde çok düğümlü laboratuvarlar (Active Directory saldırı simülasyonu, SIEM izleme ortamı) kurarken Hyper-V sanal anahtarlarını doğru yapılandırmak hayati önem taşır:

```
+-----------------------------------------------------------------------------+
|                     HYPER-V SANAL ANAHTAR (vSWITCH) TÜRLERİ                 |
+-----------------------------------------------------------------------------+

 1. EXTERNAL (DIŞ - KÖPRÜLENMİŞ) [LAB İÇİN YASAK & TEHLİKELİ]:
    [VM 1 (Zararlı)] ---> [vSwitch External] ---> [Fiziksel Wi-Fi / Ethernet] ---> ŞİRKET AĞI
    Risk: Zararlı yazılım evindeki modeme ve şirketindeki diğer bilgisayarlara yayılır!

 2. INTERNAL (İÇ - YALNIZCA KONAK VE VM'LER):
    [VM 1 (Kali)] <---> [vSwitch Internal] <---> [Konak Windows (Analist)]
                             |
                             x (Fiziksel ağa ve dış internete kapalı)
    Kullanım: Analist konak makineden VM'e güvenle SSH/RDP yapabilir; internete sızmaz.

 3. PRIVATE (ÖZEL - TAM HAVA BOŞLUKLU / AIR-GAPPED):
    [VM 1 (Saldırgan)] <---> [vSwitch Private] <---> [VM 2 (Kurban DC)]
                                  |
                                  x (Konak işletim sistemine bile kapalı!)
    Kullanım: Zararlı yazılım patlatma ve iki sanal makine arası simülasyon.
```

### D. Windows Defender Dışlama (Exclusion) Tehlikesi ve Exclusion Hijacking

Siber güvenlik laboratuvarında çalışırken en sık karşılaşılan sorun: Kendi yazdığın exploit veya analiz aracının (ör. `mimikatz.exe`, `nc.exe`) Windows Defender tarafından "Tehdit bulundu" denilerek silinmesidir.

Yeni başlayanların yaptığı en korkunç hata:
`Windows Defender -> Ayarlar -> Dışlamalar -> C:\ sürücüsünü dışla!`  
Bunu yaptığın anda bilgisayarındaki tüm korumayı çöpe atmış olursun.

**Saldırgan Bu Hatayı Nasıl Sömürür (Exclusion Hijacking)?**
Saldırgan sisteme sızdığında ilk çalıştırdığı komutlardan biri şudur:
```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```
Eğer ekranda `C:\` veya `C:\Users` veya `C:\Temp` görürse; internetten indirdiği fidye yazılımını doğrudan bu dışlanan klasörün içine yazar. Windows Defender bu klasörü taramaktan muaf tuttuğu için zararlı hiçbir engelle karşılaşmadan konak makinede çalışır!

**Doğru Savunma Kuralı:**
1. Dışlama yalnızca tek bir izole klasöre verilir: `C:\Guvenli_Lab\Araclar`.
2. Bu klasörün NTFS Erişim Denetim Listesi (ACL) sıkılaştırılır:
   * **SYSTEM:** Tam Denetim (Full Control)
   * **Administrators:** Tam Denetim (Full Control)
   * **Users (Standart Kullanıcılar):** YAZMA VE DEĞİŞTİRME YASAK! (Yalnızca Okuma).  
   Böylece kısıtlı yetkideki hiçbir zararlı betik bu taranmayan dizine dosya yazamaz.

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### 🔴 Saldırganın Gözü (Offensive Perspective)

Bir saldırgan Windows üzerinde çalışan bir laboratuvar veya analist ortamı gördüğünde şu zafiyetleri kovalar:
1. **Exclusion Hijacking:** `Get-MpPreference` ile Defender'ın taranmayan dizinlerini tespit edip payload'unu doğrudan oraya bırakır.
2. **Sandbox Ağ Sızıntısı:** Analist Sandbox'ın `<Networking>` ayarını `Default` bırakmışsa, zararlı derhal DNS tünelleme veya HTTPS üzerinden dışarıdaki C2 sunucusuna sinyal gönderir ve analistin gerçek IP adresini tespit eder.
3. **WSL2 /mnt/c Sıçraması:** Eğer analist WSL2 içinde çalışırken `/mnt/c` bağlantısını yazılabilir bırakmışsa; Linux içinde çalışan bir zararlı, konak Windows'un `C:\Users\<Kullanici>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` dizinine zararlı bir `.bat` veya `.vbs` dosyası bırakarak konak Windows yeniden başladığında kalıcı kod yürütür.

---

### 🔵 Savunmacının Kalkanı (Defensive Perspective)

Biz savunmacılar olarak Windows ortamımızı 4 katmanlı kalkanla koruruz:
1. **Windows Sandbox Kalkanı:**
   * Ağ ayarı daima `<Networking>Disable</Networking>` tutulur.
   * Numune klasörleri daima `<ReadOnly>true</ReadOnly>` olarak bağlanır. Konak dosya sistemi dokunulmazdır.
2. **Hyper-V vSwitch Kalkanı:**
   * Laboratuvar makineleri asla `External` sanal anahtara bağlanmaz.
   * `Internal` veya `Private` anahtarlar kullanılır; Windows Güvenlik Duvarında bu sanal adaptörler için genel ağdan gelen tüm istekler engellenir (`Block_Public_Inbound`).
3. **ACL ile Korumalı Defender Dışlaması:**
   * Yalnızca `C:\Guvenli_Lab\Araclar` dışlanır; `icacls` komutu ile standart kullanıcıların yazma yetkisi tamamen kaldırılır.
4. **Çekirdek Yalıtım:**
   * Windows 11 üzerinde VBS ve HVCI (Bellek Bütünlüğü) açık tutularak çekirdek seviyesi sürücü saldırıları engellenir.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Geliştirdiğimiz `windows_lab_provisioner.py` CLI aracı; Windows laboratuvar yapılandırma dosyalarını satır satır denetler ve BSL-4 seviyesinde tam izole bir `.wsb` profili üretir.

### A. İncelenen Laboratuvar Profilleri

`portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json` dosyasında iki zıt profil modelledik:
* `WIN-LAB-SEC-01 (Sertleştirilmiş Windows Lab)`: VBS açık, Hyper-V etkin, Windows Sandbox ağı kapalı ve salt-okunur, vSwitch Internal, Defender dışlaması dar ve sıkı ACL'li.
* `WIN-LAB-RISK-99 (Güvensiz Windows Lab)`: VBS kapalı, Sandbox ağı açık ve C:\ tam yetkiyle bağlı, External vSwitch ile fiziksel ağa bağlı, Defender'da `C:\Users` dışlanmış.

### B. Canlı Denetimin Çalıştırılması

Öğrenci olarak terminalinde şu komutu çalıştır:

```bash
python portfolio/hafta_02/gun_009/uygulama/windows_lab_provisioner.py --config portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json
```

Bu komut çalıştığında:
* `WIN-LAB-SEC-01`: Güvenlik Skoru **100/100** | Durum: **GÜVENLİ (SERTLEŞTİRİLMİŞ LABORATUVAR)** | 0 Bulgu.
* `WIN-LAB-RISK-99`: Güvenlik Skoru **0/100** | Durum: **KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)** | 8 Kritik Bulgu! (C:\ Sandbox eşlemesi, External vSwitch, C:\Users Defender dışlaması vb.).

### C. Güvenli Windows Sandbox (.wsb) Dosyasının Üretilmesi

Sertleştirilmiş laboratuvar profilimiz için BSL-4 seviyesinde `.wsb` dosyasını tek komutla üretebilirsin:

```bash
python portfolio/hafta_02/gun_009/uygulama/windows_lab_provisioner.py --config portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json --lab-id WIN-LAB-SEC-01 --generate-wsb --output-dir portfolio/hafta_02/gun_009/ornek_veri
```

Üretilen [Izole_Zararli_Inceleme.wsb](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_02/gun_009/ornek_veri/Izole_Zararli_Inceleme.wsb) dosyasına Windows Gezgini'nde çift tıkladığında; tamamen izole, sıfır internet çıkışlı ve konak diskini asla bozamayacak güvenli mikro-analiz ortamın saniyeler içinde açılacaktır!

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, bu 5 ölümcül hatayı iş hayatında asla yapmayacaksın:

1. **"Windows Sandbox'ta Ağı Açık Bırakmak (`<Networking>Default</Networking>`)"**:
   * *Felaket:* Sandbox içindeki zararlı yazılım dışarıdaki C2 sunucusuna sinyal gönderir, analistin gerçek IP adresini tespit eder veya evindeki yerel ağa port taraması yapar!
   * *Doğrusu:* Daima `<Networking>Disable</Networking>`.

2. **"Windows Defender'da `C:\` veya `C:\Users` Dizinini Dışlamak"**:
   * *Felaket:* Saldırganlar `Get-MpPreference` ile bu açığı görür ve zararlılarını doğrudan buraya atarak hiçbir güvenlik uyarısı üretmeden çalıştırır (Exclusion Hijacking).
   * *Doğrusu:* Yalnızca tek bir izole klasör (`C:\Guvenli_Lab\Araclar`) dışlanır ve standart kullanıcıların buraya yazması yasaklanır.

3. **"Hyper-V vSwitch'i 'External' Olarak Oluşturup Zararlı Analiz Etmek"**:
   * *Felaket:* VM fiziksel ağ kartına bağlandığı için bir fidye yazılımı (WannaCry gibi) şirket ağındaki tüm sunucuları şifreler.
   * *Doğrusu:* Laboratuvarda daima `Internal` veya `Private` vSwitch kullanılır.

4. **"Windows Sandbox'a Konak Klasörünü Salt-Okunur Olmadan Bağlamak (`<ReadOnly>false</ReadOnly>`)"**:
   * *Felaket:* Sandbox içindeki fidye yazılımı, konak sistemdeki klasörün içindeki tüm dosyaları şifreler!
   * *Doğrusu:* Mapped folder'larda daima `<ReadOnly>true</ReadOnly>` tanımlanır.

5. **"WSL2 İçinde Windows Diskine Tam Yetki Vermek"**:
   * *Felaket:* Kali Linux içinde çalıştırdığın bir exploit betiği, `/mnt/c` üzerinden konak Windows başlangıç klasörüne arka kapı yerleştirir.
   * *Doğrusu:* `/etc/wsl.conf` içinde automount `ro` (salt-okunur) yapılır.

---

## 6. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` içinde yer alan `G009-SC1`, `G009-SC2` ve `G009-SC3` numaralı soruların usta-çırak derinliğindeki yanıtları:

* **Soru 1 (G009-SC1):** Windows üzerinde laboratuvar hazırlığı: Temel mekanizmayı ve güvenlik önemini açıkla.
  * *Hocanın Yanıt Özeti:* Windows üzerinde laboratuvar hazırlığı; Hyper-V mikro-çekirdek sanallaştırması, tek kullanımlık Windows Sandbox ve ağ bölümleme (vSwitch) kalkanları ile konak işletim sistemini tehlikeli analiz süreçlerinden izole etme sanatıdır. Kimya laboratuvarındaki çekerocak gibi patlatma alanını sınırlar ve adli incelemeler için kalıntısız bir ortam sunar.
* **Soru 2 (G009-SC2):** Windows üzerinde laboratuvar hazırlığı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
  * *Hocanın Yanıt Özeti:* Girdisi laboratuvar profili JSON dosyası, işlemi VBS durumu, Sandbox ağ/klasör izolasyonu, Hyper-V vSwitch türü ve Defender dışlama ACL'lerinin denetlenmesi; beklenen sonucu 100/100 güvenlik skoru ve güvenli `.wsb` profili üretilmesi; negatif kontrolü ise External vSwitch veya `C:\Users` Defender dışlaması tanımlandığında sistemin işlemi FELAKET seviyesinde reddetmesidir.
* **Soru 3 (G009-SC3):** 'Windows üzerinde laboratuvar hazırlığı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
  * *Hocanın Yanıt Özeti:* Risk; gevşek Sandbox ağ ayarları, köprülenmiş vSwitch adaptörleri ve geniş Defender dışlamalarının (Exclusion Hijacking) açtığı sızıntı yüzeylerinden doğar. Denetim araçlarıyla yapılandırmalar taranarak tespit edilir. `<Networking>Disable`, `<ReadOnly>true`, `Internal` vSwitch ve katı NTFS ACL kuralları ile önlenir.

*(Detaylı kurumsal yanıtların tamamı `soru_cevap.md` dosyasında yer almaktadır.)*

---

## 7. Ödev & Bir Sonraki Güne Hazırlık

1. **Günün Pratik Ödevi:**
   Kendi Windows 11/10 bilgisayarında `Windows Özelliklerini Aç veya Kapat` menüsünden **Windows Sandbox** ve **Hyper-V** bileşenlerinin açık olup olmadığını kontrol et. Bugün ürettiğimiz `Izole_Zararli_Inceleme.wsb` dosyasını çalıştırarak ağ bağlantısının gerçekten kapalı olduğunu (`ping 8.8.8.8` atarak) test et!
2. **Yarın Bizi Ne Bekliyor (GÜN 010)?**
   Yarın Windows dünyasından siber güvenliğin diğer ana vatanı olan **Linux Üzerinde Laboratuvar Hazırlığı** konusuna geçeceğiz. KVM/QEMU, iptables ağ izolasyonu ve izole kullanıcı yetkilendirmelerini inceleyeceğiz.

Tebrikler evlat, Windows kalen artık hazır!
