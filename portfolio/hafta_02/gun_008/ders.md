# GÜN 008: Sanallaştırmanın Güvenlikteki Rolü
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

Evlat, kahveni veya çayını tazelediysen masamıza otur. Geçtiğimiz hafta siber güvenliğin anayasasını yazdık: CIA üçlüsünü iliklerimize kadar hissettik, tehdit ile riskin farkını kavradık, etik yetkilendirmeyi öğrendik ve ilk haftalık projemizde güvenli laboratuvar sözleşmemizi imzaladık. 

Bugün 2. Haftaya adım atıyoruz. Masamızda siber güvenlik mühendisliğinin en hayati kalkanı ve aynı zamanda en çok yanlış anlaşılan konusu duruyor: **Sanallaştırma (Virtualization)**.

Sana sorsam: *"Sanallaştırma nedir?"* Bana muhtemelen *"Hocam, bilgisayar içinde başka bir bilgisayar açmak, VirtualBox veya VMware çalıştırmak"* dersin. Bu cevap bir son kullanıcı için doğrudur; fakat bir siber güvenlik uzmanı için **ölümcül derecede yüzeyseldir**.

Sanallaştırma siber güvenlikte ne anlama gelir, biliyor musun?
**Biyolojik Tehlike Seviye 4 (BSL-4) laboratuvarındaki hermetik eldivenli cam kabindir (Glovebox)!**

Düşün ki elinde ölümcül bir virüs örneği var (Ebola virüsü gibi). Sen bu virüsü mutfak masanda çıplak elle inceleyebilir misin? İncelediğin anda enfekte olursun, ailene bulaştırırsın, oradan tüm şehre yayılır. İşte internetten indirdiğin, dark web forumlarından topladığın veya bir saldırıda ele geçirdiğin bir zararlı yazılım (malware, ransomware, trojan) da tam olarak o Ebola virüsüdür!

Eğer o zararlıyı kendi fiziksel bilgisayarında (konak/host işletim sisteminde) çift tıklayıp çalıştırırsan:
1. Fiziksel diskin şifrelenir.
2. Web tarayıcındaki kayıtlı şifreler ve oturum çerezleri (session cookies) çalınır.
3. Evindeki modem veya şirketindeki yerel ağ (LAN) üzerinden diğer tüm sunuculara yayılır.

İşte sanallaştırma, bize o **çift katlı, negatif basınçlı, kurşun geçirmez cam kabini** sunar. Biz zararlı yazılımı o kabinin içine koyarız, camın dışından kalın eldivenlerle dokunur, çalıştırır, ne yaptığını izleriz. İncelememiz bittiğinde ise tek bir tuşla kabinin içine 1000 derece alev basar, her şeyi sıfırlar ve kabini ilk temiz haline geri döndürürüz (**Snapshot & Rollback**).

Fakat dikkat et evlat: Eğer o cam kabinin havalandırma deliğini açık unutursan (örneğin sanal makineye **Bridged Ağ** verirsen) veya kabinin içine konak sisteminin masaüstünü bağlarsan (**Yazılabilir Paylaşılan Klasör** açarsan), o cam kabin seni korumaz; virüs doğrudan ciğerlerine dolar!

Bugün bu ders bittiğinde; sanallaştırmanın işlemci (CPU) ve bellek seviyesinde nasıl çalıştığını, Tip-1 ile Tip-2 hypervisor arasındaki derin uçurumu, bir saldırganın sanal makineden konak sisteme nasıl sızdığını (**VM Escape**) ve zararlının sanal makinede olduğunu anladığında nasıl uykusuna yattığını (**Anti-VM Evasion**) nakış gibi zihnine işleyeceksin.

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### A. Donanım Katmanından Çekirdeğe: Sanallaştırma Nasıl Mümkündür?

Klasik bir x86/x64 bilgisayar mimarisinde işlemci (CPU) ayrıcalık seviyeleri halkalar (Rings) şeklinde yapılandırılmıştır:
* **Ring 3 (Kullanıcı Alanı / User Mode):** Web tarayıcıları, metin düzenleyiciler, hesap makineleri burada çalışır. Doğrudan donanıma (RAM, disk, ağ kartı) dokunamazlar; her istek için işletim sistemi çekirdeğine sistem çağrısı (syscall) yaparlar.
* **Ring 0 (Çekirdek Alanı / Kernel Mode):** İşletim sisteminin kalbi (Windows `ntoskrnl.exe`, Linux `vmlinuz`) burada oturur. Donanıma sınırsız erişim hakkına sahiptir. Tüm bellek sayfalarını ve işlemci kayıtlarını (registers) yönetir.

Peki bir bilgisayar içinde ikinci bir işletim sistemi (Guest OS) çalıştırmak istediğimizde ne olur?
Misafir işletim sistemi de kendi çekirdeğini Ring 0'da çalıştırmak ister! İki farklı çekirdeğin aynı donanım Ring 0'ında birbirini ezmeden çalışması fiziksel olarak imkansızdı. İşte bu yüzden modern işlemci üreticileri (Intel ve AMD) donanım seviyesinde sanallaştırma komut setlerini geliştirdiler:
* **Intel VT-x** (Virtualization Technology) ve **AMD-V**
* **Root Mode vs Non-Root Mode (Ring -1 / VMM):**
  İşlemciye yeni bir süper yetki halkası eklendi: **Ring -1**. Burada **Hypervisor** (Sanal Makine Monitörü - VMM) oturur. Misafir işletim sistemi Ring 0'da çalıştığını zannederken, aslında işlemci tarafından *Non-Root Ring 0* moduna hapsedilmiştir. Misafir çekirdek donanımı manipüle etmeye kalktığında işlemci bir **VM-Exit** kesmesi üretir, kontrolü Ring -1'deki Hypervisor'a devreder. Hypervisor talebi inceler, simüle eder ve kontrolü tekrar sanal makineye (**VM-Entry**) verir.

### B. Tip-1 (Bare-Metal) vs Tip-2 (Hosted) Hypervisor Mimarisi

Siber güvenlik operasyonlarında iki ana hypervisor türüyle karşılaşırsın:

```
+------------------------------------+    +------------------------------------+
|   TİP-1 (BARE-METAL) HYPERVISOR    |    |      TİP-2 (HOSTED) HYPERVISOR     |
+------------------------------------+    +------------------------------------+
|  [VM 1]   [VM 2]   [VM 3 (SOC/SIEM)]|    |  [VM 1 (Malware)]   [VM 2 (Kali)]  |
+------------------------------------+    +------------------------------------+
| HYPERVISOR (ESXi, Proxmox, Xen, KVM)|    | HYPERVISOR YAZILIMI (VirtualBox)   |
+------------------------------------+    +------------------------------------+
| FİZİKSEL DONANIM (Sunucu, CPU, RAM)|    | KONAK İŞLETİM SİSTEMİ (Win 11 / Mac)|
|                                    |    +------------------------------------+
|                                    |    | FİZİKSEL DONANIM (Laptop, PC)      |
+------------------------------------+    +------------------------------------+
```

1. **Tip-1 (Bare-Metal Hypervisor - Doğrudan Donanım Üzerinde):**
   * *Örnekler:* VMware ESXi, Proxmox VE, KVM, Xen, Microsoft Hyper-V (Core).
   * *Mimarisi:* Altında hiçbir genel amaçlı işletim sistemi (Windows/Ubuntu) yoktur. Hypervisor doğrudan donanımın üstüne kurulur.
   * *Güvenlik Üstünlüğü:* Saldırı yüzeyi (attack surface) son derece küçüktür. Konak işletim sisteminde çalışan bir tarayıcı, Office yazılımı veya üçüncü parti servis olmadığı için, konak üzerinden zafiyet istismarı neredeyse imkansızdır. Şirketlerin sunucu altyapıları ve SOC ortamları Tip-1 üzerinde yaşar.

2. **Tip-2 (Hosted Hypervisor - İşletim Sistemi Üzerinde):**
   * *Örnekler:* Oracle VirtualBox, VMware Workstation / Fusion.
   * *Mimarisi:* Senin günlük kullandığın Windows 11 veya macOS işletim sisteminin üzerine normal bir uygulama gibi kurulur. Donanım çağrıları önce konak işletim sisteminin sürücülerine, oradan fiziksel CPU'ya iletilir.
   * *Güvenlik Riski:* Konak işletim sistemi çökerse veya hacklenirse, tüm sanal makineler düşer. Ayrıca hypervisor ile konak arasındaki zengin entegrasyon özellikleri (Pano, Sürükle-Bırak, 3D Hızlandırma), saldırganın sanal makineden konak sisteme sızması için devasa bir zafiyet yüzeyi oluşturur. Bireysel güvenlik araştırmalarında Tip-2 kullanılır, ancak **sertleştirilmesi şarttır**.

### C. Konteyner (Docker) vs Sanal Makine (VM): Güvenlik Sınırı Farkı

Sıkça duyacağın bir tuzak: *"Konteyner varken sanal makineye ne gerek var?"*
Evlat, bu cümleyi kuran biri güvenlik sınırlarının (security boundaries) ne olduğunu bilmiyordur!

| Özellik | Sanal Makine (VM) | Konteyner (Docker / Podman) |
| :--- | :--- | :--- |
| **Çekirdek (Kernel)** | **Ayrı ve Bağımsız:** Her VM kendi çekirdeğini (Linux, Windows) yükler. | **Paylaşılan:** Tüm konteynerler konak işletim sisteminin çekirdeğini paylaşır. |
| **İzolasyon Mekanizması**| Donanım destekli (Intel VT-x, SLAT, Hypervisor VMM). | Mantıksal ayrıştırma (Linux Namespaces & Cgroups). |
| **Güvenlik Sınırı** | **Çok Güçlü:** Çekirdek çökmesi sadece o VM'i etkiler. | **Zayıf:** Çekirdekte bir zafiyet (Kernel Exploit) tüm konteynerleri ve konağı düşürür. |
| **Zararlı Analizi** | **Zorunlu:** Bilinmeyen bir rootkit/ransomware asla konteynerde analiz edilmez! | Sadece güvenilir mikroservisleri paketlemek için uygundur. |

### D. Sanallaştırmanın Güvenlikteki 5 Temel Sütunu

1. **Patlatma Alanı Kontrolü (Blast Radius Limitation):**
   Bir test başarısız olduğunda veya bir zararlı infilak ettiğinde, hasar yalnızca o sanal makinenin sınırları içinde kalır. Şirket ağına veya ana bilgisayara sıçrayamaz.
2. **Değişmezlik ve Geri Alma (Snapshot & Rollback):**
   Analiz öncesi tertemiz bir işletim sistemi durumu kaydedilir (**Clean Snapshot**). Zararlı makinede 1 saat çalıştırılır, kayıt defteri ve dosya hareketleri loglanır; iş bittiğinde tek komutla snapshot geri yüklenir. Sıfır kirlilik, sıfır kalıntı!
3. **Aldatma ve Bal Küpleri (Honeypot & HoneyVM):**
   Saldırganları yanıltmak için bilerek zafiyetli bırakılmış sanal makineler ağa yerleştirilir. Saldırgan buraya girdiğinde gerçek bir sunucuyu ele geçirdiğini sanır; oysa attığı her adım hypervisor seviyesinde sessizce kaydedilmektedir.
4. **Sanal Ağ İzolasyonu (vSwitch & Micro-Segmentation):**
   Fiziksel kablolara dokunmadan; izole sanal anahtarlar (Internal Network / Host-Only) kurularak laboratuvar ortamı fiziksel modemden ve şirket ağından tamamen koparılır.
5. **Ajan-Bağımsız Canlı Adli Bilişim (Agentless Memory Forensics):**
   Sanal makinenin içine hiçbir casus yazılım kurmadan, hypervisor katmanından sanal makinenin tüm RAM belleği tek bir dosya (.vmem / .dmp) olarak dışarıdan çekilebilir (Hypervisor Introspection). Gelişmiş rootkit'ler işletim sistemi içindeki araçları kör etse bile, hypervisor seviyesindeki bellek dökümünden kaçamazlar!

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### 🔴 Saldırganın Gözü (Offensive Perspective)

Bir zararlı yazılım geliştiricisi veya sızma testi uzmanı sanallaştırma katmanına iki farklı amaçla yaklaşır:

#### 1. Anti-VM ve Tespitten Kaçınma (Evasion & Anti-Analysis)
Gelişmiş bir tehdit aktörü (APT grubu), yazdığı zararlı yazılımın güvenlik araştırmacıları veya otomatik sandbox sistemleri (VirusTotal, Any.Run, Cuckoo Sandbox) tarafından analiz edilmesini istemez. Bu yüzden zararlının ilk satırlarına **Anti-VM kontrolleri** koyar:
* **MAC Adresi Kontrolü:** Ağ kartının OUI önekine bakar. Eğer `08:00:27` (VirtualBox), `00:05:69` (VMware) veya `00:15:5D` (Hyper-V) görürse, anında anlar ki burası bir tuzaktır.
* **CPUID Talimatı:** `CPUID` assembly komutunu çalıştırır. ECX register'ının 31. bitine (Hypervisor Present Bit) bakar. Bit 1 ise *"Sanal makinedeyim!"* der.
* **Zamanlama Analizi (RDTSC - Time Stamp Counter):** Fiziksel bir CPU'da iki komut arasındaki saat vuruşu mikrosaniyeler mertebesindedir. Sanal makinede ise VM-Exit kesmeleri yüzünden komutlar gecikmeli yürütülür. Zararlı bu gecikmeyi ölçer.
* **İnsan Varlığı Kanıtı:** Gerçek bir bilgisayarda fare hareket eder, klavyeye basılır, ekranda en az 1080p çözünürlük vardır ve arka planda Spotify, Chrome, Steam açıktır. Analiz VM'inde fare kımıldamıyorsa ve disk 30 GB ise, zararlı uyku moduna (`Sleep(86400)`) geçer veya zararsız bir hesap makinesi gibi davranır!

#### 2. Sanal Makineden Kaçış (VM Escape)
Bu, bir siber saldırganın ulaşabileceği en tepe noktalardan biridir. Saldırgan sanal makinenin içinde SYSTEM/root yetkisi aldıktan sonra, hypervisor'ın konak işletim sistemiyle haberleştiği kanallardaki zafiyetleri istismar eder:
* **Pano İstismarı (Shared Clipboard Overflow):** Misafir VM panoya devasa veya bozuk bir UTF-16 payload kopyalar. Konak işletim sistemindeki hypervisor pano ayrıştırıcısı tampon bellek taşması (buffer overflow) yaşar ve konak makinede saldırganın kodu çalışır!
* **3D Grafik Emülasyonu:** Hypervisor'ların misafire sunduğu sanal grafik kartı sürücüleri (VBoxSharedCrOpenGL, VMware SVGA3D), konak GPU'suna doğrudan çağrı yapar. Geçmişte düzinelerce uzaktan kod yürütme (RCE) açığı bu emülasyon katmanından çıkmıştır.
* **Paylaşılan Klasör Enjeksiyonu:** Eğer analist konak makinenin `C:\` sürücüsünü VM ile paylaşmışsa, fidye yazılımı doğrudan konak diskinin ana MBR/GPT ve kullanıcı dosyalarını şifreler!

---

### 🔵 Savunmacının Kalkanı (Defensive Perspective)

Bir savunmacı (ve analist) olarak görevimiz, BSL-4 kabinimizi kurşun geçirmez hale getirmektir:

1. **Entegrasyon Kanallarını Tamamen Kapat (Zero-Trust VM):**
   * Pano Paylaşımı (Shared Clipboard) -> **Disabled** (Kesinlikle devre dışı).
   * Sürükle-Bırak (Drag & Drop) -> **Disabled**.
   * 3D Grafik Hızlandırma -> **Kapalı** (Sadece temel 2D emülasyon).
   * Paylaşılan Klasörler -> **Sıfır klasör**. Dosya aktarımı gerekiyorsa sadece salt-okunur (ReadOnly) geçici sanal ISO imajı bağlanmalıdır.
2. **Ağ Segmentasyonu ve Karantina:**
   * Analiz VM'i asla fiziksel ağa köprülenmez (**Asla Bridged Network kullanılmaz**).
   * Ağ bağdaştırıcısı **Internal Network** veya **Host-Only** moduna alınır.
   * VM'in dış internete çıkışı engellenir; DNS ve HTTP sorguları içeride sahte yanıt üreten araçlara (**INetSim / FakeNet-NG**) yönlendirilir.
3. **Anti-VM Maskeleme (Hardened VM):**
   * MAC adresi bilinen bir donanım üreticisinin (Intel, Realtek) önekiyle değiştirilir.
   * Hypervisor CPUID bayrağı gizlenir (`hv_vendor_id` maskelenir).
   * Sanal makineye en az 4 vCPU, 8 GB RAM ve 120 GB sahte dolu disk tahsis edilir; içine rastgele Word belgeleri, tarayıcı geçmişi ve resimler serpiştirilir (Gerçek kullanıcı ortamı simülasyonu).
4. **Zorunlu Snapshot ve Geri Yükleme Otomasyonu:**
   * Her patlatma işleminden önce temiz bir kontrol noktası dondurulur.
   * Analiz bittiği an bellek dökümü alınır ve disk durumu otomatik olarak geri alınır (**Rollback**).

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Şimdi teoriyi geride bırakıp canlı sisteme geçiyoruz.
Bugünkü laboratuvarımızda geliştirdiğimiz `vm_security_auditor.py` aracı; verilen sanal makine yapılandırma profillerini CIS Sanallaştırma Sertleştirme Kılavuzlarına göre satır satır denetler.

### A. İncelenen Sanal Makine Güvenlik Profilleri

`portfolio/hafta_02/gun_008/ornek_veri/vm_guvenlik_profili.json` dosyamızda üç farklı mimari profil tanımladık:
1. `VM-SEC-01 (Sertleştirilmiş Analiz VM)`: BSL-4 seviyesinde. Pano, sürükle-bırak kapalı; ağ izole; snapshot zorunlu; anti-VM maskelemeleri eksiksiz.
2. `VM-RISK-99 (Tehlikeli Geliştirici VM)`: Tam bir siber güvenlik felaketi. Bridged ağ, çift yönlü pano, konak `C:\` sürücüsü paylaşımlı, snapshot yok, 3D hızlandırma açık.
3. `VM-HONEY-03 (Kontrollü Bal Küpü HoneyVM)`: Saldırganı çekmek için hypervisor izleri açık bırakılmış, ancak ağ ve izolasyon sınırları sıkı sıkıya kilitlenmiş özel aldatma düğümü.

### B. Denetleyici Kodunun Çalıştırılması

Öğrenci olarak terminalini aç ve şu komutu yürüt:

```bash
python portfolio/hafta_02/gun_008/uygulama/vm_security_auditor.py --profile portfolio/hafta_02/gun_008/ornek_veri/vm_guvenlik_profili.json
```

Bu komutu çalıştırdığında ekranda şu gerçek denetim raporunu göreceksin:
* `VM-SEC-01`: Güvenlik Skoru **100/100** | Durum: **GÜVENLİ (SERTLEŞTİRİLMİŞ)** | 0 Bulgu.
* `VM-RISK-99`: Güvenlik Skoru **0/100** | Durum: **KRİTİK FELAKET (ACİL MÜDAHALE)** | 10 Kritik Bulgu! (Bridged ağ, C:\ paylaşımı, çift yönlü pano, snapshot eksikliği vb.).
* `VM-HONEY-03`: Güvenlik Skoru **85/100** | Durum: **ORTA RİSK (İYİLEŞTİRME GEREKLİ)** (Anti-VM izleri bilerek açık tutulmuştur).

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, bu bölümü kırmızı kalemle defterine yaz. Sektörde "uzmanım" diyenlerin yaptığı ve şirketleri milyonlarca dolar zarara uğratan en büyük 5 sanallaştırma hatası şunlardır:

1. **"Analiz Makinesinde Bridged (Köprülenmiş) Ağ Kullanmak":**
   * *Hata:* VM'in internete çıksın diye ağ modunu "Bridged" yapmak.
   * *Felaket:* Çalıştırdığın fidye yazılımı (WannaCry gibi), fiziksel ağındaki SMB (445) portuna sıçrar ve şirketteki tüm muhasebe ve sunucu sistemlerini şifreler!
   * *Doğrusu:* Asla Bridged kullanma. İzole analiz için **Internal Network** veya **Host-Only** kullan; internet simülasyonunu yerel sahte servislerle çöz.

2. **"Çift Yönlü Panoyu (Bidirectional Clipboard) Açık Bırakmak":**
   * *Hata:* VM'den konak sisteme kod veya yazı kopyalamak kolay olsun diye panoyu çift yönlü açmak.
   * *Felaket:* Konak sistemde kopyaladığın parola yöneticisi master şifresi veya API token'ı anında sanal makinedeki zararlının eline geçer. Ayrıca pano tampon taşması zafiyetiyle saldırgan konağa sızar (VM Escape).
   * *Doğrusu:* Pano paylaşımını daima **Disabled** tut. Metin aktarımı gerekiyorsa tek yönlü (Host to Guest) dahi dikkatle yönetilmeli; tercihen hiç açılmamalıdır.

3. **"Konak Sistemin Kök Dizinini (C:\ veya /) Misafirle Paylaşmak":**
   * *Hata:* Dosyalara kolay erişmek için konak `C:\` sürücüsünü sanal makineye bağlamak.
   * *Felaket:* Sanal makinede patlattığın fidye yazılımı, `\\vboxsrv\Host_C_Drive` yolunu tarar ve fiziksel bilgisayarındaki tüm kişisel ve sistem dosyalarını şifreler. Sanallaştırma kalkanın sıfırlanmış olur!
   * *Doğrusu:* Konak diski asla bağlanmaz. Dosya aktarımı sadece salt-okunur sanal disk/ISO ile yapılır.

4. **"Snapshot Almadan Zararlı Analizi Yapmak":**
   * *Hata:* Temiz bir sistem görüntüsü (Clean Snapshot) dondurmadan zararlıyı çalıştırmak ve sonra makineyi "yeniden başlatmak".
   * *Felaket:* Zararlı yazılım MBR'a veya sistem servislerine kalıcılık (persistence) bırakır. Sonraki testlerde makineyi temiz zannedersin; oysa sistem zehirlenmiştir ve sonraki tüm analiz raporların çöp olur.
   * *Doğrusu:* Her analiz oturumundan önce dondurulmuş altın snapshot'a dönülür (`Revert to Snapshot`).

5. **"Anti-VM Gizlemesi Yapmadan 'Bu Dosya Temiz' Raporu Vermek":**
   * *Hata:* Varsayılan VirtualBox ayarlarına zararlı atıp "hiçbir zararlı aktivite göstermedi, dosya temizdir" demek.
   * *Felaket:* Zararlı yazılım `08:00:27` MAC adresini gördüğü için kendini kapatmıştır. Sen dosyaya "temiz" deyip şirketin sunucularına yüklersin ve ertesi gün şirket hacklenir!
   * *Doğrusu:* Sanallaştırma ortamı fiziksel bir bilgisayar gibi gizlenmeli (MAC spoofing, CPUID maskeleme, gerçekçi disk boyutu).

---

## 6. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Bu bölüm, müfredatımızın `SORU BANKASI` içinde yer alan `G008-SC1`, `G008-SC2` ve `G008-SC3` numaralı kritik mekanizma sorularının usta-çırak derinliğindeki yanıtlarını içerir:

* **Soru 1 (G008-SC1):** Sanallaştırmanın güvenlikteki rolü: Temel mekanizmayı ve güvenlik önemini açıkla.
  * *Hocanın Yanıt Özeti:* Sanallaştırma; Ring -1 donanım destekli Hypervisor katmanı sayesinde işlemci, bellek ve ağ kaynaklarını donanımsal olarak izole eden bir güvenlik kalkanıdır. BSL-4 laboratuvar cam kabini gibi patlatma alanını sınırlar ve adli bilişim incelemelerinde geri alınabilir (immutable) temiz ortam sunar.
* **Soru 2 (G008-SC2):** Sanallaştırmanın güvenlikteki rolü: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
  * *Hocanın Yanıt Özeti:* Girdisi sanal makine yapılandırma profili (JSON), işlemi ağ izolasyonu, hypervisor escape vektörleri (pano, 3D, paylaşılan disk), snapshot ve anti-VM kontrolleri; beklenen sonucu 100 üzerinden güvenlik skoru ve bulgu matrisi; negatif kontrolü ise Bridged ağ veya yazılabilir kök dizin paylaşımı tanımlandığında sistemin işlemi KRİTİK İHLAL ve FELAKET seviyesinde reddetmesidir.
* **Soru 3 (G008-SC3):** 'Sanallaştırmanın güvenlikteki rolü' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
  * *Hocanın Yanıt Özeti:* Risk, hypervisor entegrasyon kanallarının (pano, paylaşılan disk, 3D GPU emülatörü) veya köprülenmiş ağların misafirden konağa sızma (VM Escape) veya yerel ağa yayılma (Lateral Movement) yüzeyi açmasıyla oluşur. Denetim araçlarıyla yapılandırma dosyaları taranarak tespit edilir. Pano ve sürükle-bırakın devre dışı bırakılması, Host-Only/Internal izole ağ kullanımı ve non-persistent disk modu ile önlenir.

*(Detaylı, 4 aşamalı kurumsal yanıtların tamamı `soru_cevap.md` dosyasında yer almaktadır.)*

---

## 7. Ödev & Bir Sonraki Güne Hazırlık

1. **Günün Pratik Ödevi:**
   Geliştirdiğimiz `vm_security_auditor.py` aracını kullanarak kendi bilgisayarında kullandığın VirtualBox veya VMware üzerindeki bir sanal makinenin yapılandırma ayarlarını incele. Ağ modunun "Bridged" mı yoksa "NAT/Host-Only" mi olduğunu kontrol et; pano paylaşımının açık olup olmadığını doğrula.
2. **Yarın Bizi Ne Bekliyor (GÜN 009)?**
   Yarın teoriyi geride bırakıp somut adımlarla **Windows Üzerinde Güvenli Laboratuvar Hazırlığı** konusuna geçeceğiz. Windows Sandbox, Hyper-V bileşenleri ve izolasyon ayarlarını canlı sistem üzerinde adım adım ayağa kaldıracağız.

Hazırlıklarını tamamla evlat, yarın laboratuvarımızı sıfırdan kuruyoruz!
