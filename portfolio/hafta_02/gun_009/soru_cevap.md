# GÜN 009: Soru & Cevap Bankası — Windows Üzerinde Laboratuvar Hazırlığı

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Soru Sayısı](https://img.shields.io/badge/sorular-3%20Soru-blue?style=flat-square)
![Format](https://img.shields.io/badge/format-4%20B%C3%B6l%C3%BCml%C3%BC%20Kat%C4%B1%20Standart-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G009-SC1): Windows üzerinde laboratuvar hazırlığı: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Windows üzerinde güvenlik laboratuvarı hazırlığı; kimya alanında zehirli gaz ve patlayıcı maddelerin incelendiği **Özel Havalandırmalı Çekerocak (Fume Hood)** mimarisidir. Nasıl ki bir kimyager zehirli bir reaksiyonu laboratuvarın ortasındaki açık masada yapmayıp cam kalkanlı ve negatif hava basınçlı çekerocağın içine koyuyorsa; bir güvenlik analisti de şüpheli dosyaları kendi fiziksel Windows işletim sisteminde değil, yerleşik **Windows Sandbox (WSB)** çekerocağında ve izole **Hyper-V vSwitch** bölmesinde açar. Deney tamamlandığında Sandbox penceresi kapatılır ve çekerocağın içindeki her bir molekül (bellek sayfası ve geçici dosya) otomatik olarak imha edilir.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Windows üzerindeki bu güvenlik mekanizması 4 ana katmandan oluşur:
* **Hyper-V Tabanlı Mikro-İzolasyon (VBS / HVCI):** Windows 11/10 üzerinde çalışan Hyper-V hipervizörü; çekirdeğin kritik süreçlerini (LSASS vb.) Virtual Secure Mode (VSM) içinde korurken, Windows Sandbox için donanım tabanlı hafif bir sanal makine alanı açar.
* **Dinamik Temel İmaj ve Kopyala-Yaz (Copy-on-Write):** Windows Sandbox, konak sistemin sistem dosyalarını salt-okunur (ReadOnly) olarak ödünç alır; misafirdeki tüm değişiklikler geçici RAM diskine yazılır. Kapatıldığında misafir durumu kalıcı olarak sıfırlanır (Zero-Persistence).
* **Ağ ve Klasör İzolasyonu:** `.wsb` profili içindeki `<Networking>Disable</Networking>` etiketi ile sanal makinenin dış dünyayla olan tüm fiziksel ve mantıksal bağlantısı kesilir. Eşlenen klasörlere konulan `<ReadOnly>true</ReadOnly>` bayrağı ile konak diskine yazma engellenir.
* **Defender Dışlama Kalkanı (Exclusion Hardening):** Analiz araçlarının silinmesini önlemek için yalnızca dar bir dizin (`C:\Guvenli_Lab\Araclar`) dışlanır ve katı NTFS ACL kurallarıyla standart kullanıcıların bu dizine yazması engellenir.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan bir Windows sistemine sızdığında ortamın analiz amaçlı mı yoksa gerçek bir kurban mı olduğunu anlamak için Windows Sandbox veya Hyper-V izlerini arar. Ancak saldırgan için asıl büyük ödül, hatalı yapılandırılmış savunma mekanizmalarıdır:
* **Exclusion Hijacking:** Saldırgan `powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"` komutu ile antivirüsün taramadığı dizinleri listeler. Eğer analist dikkatsizce `C:\` veya `C:\Users` dizinini dışlamışsa, saldırgan fidye yazılımını doğrudan bu yola kopyalar ve antivirüs motorunu sıfır eforla atlatır (AV Evasion).
* **Sandbox Ağ Sızıntısı:** Analist `<Networking>Default</Networking>` bırakmışsa, zararlı yazılım C2 sunucusuna sinyal gönderir, tersine kabuk (reverse shell) açar veya yerel ağdaki 445 (SMB) portlarını tarar.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2020 yılında büyük bir sağlık kuruluşu siber saldırıya uğradığında; olay müdahale ekibindeki bir analist, gelen şüpheli fidye yazılımı örneğini incelemek için kendi Windows iş istasyonunda Windows Defender dışlamalarına `C:\Users\<Kullanici>` klasörünü eklemiştir. Aynı bilgisayarda arka planda çalışan ve kimlik avı bağlantısına tıklayan başka bir kısıtlı kullanıcı süreci, zararlı dosyayı analistin bu dışlanmış kullanıcı klasörüne bırakmış; Defender taramayı atladığı için fidye yazılımı tüm hastane ağını şifrelemiştir.  
**Çıkarılan Ders:** Bir laboratuvar kurulurken kullanıcı ve sistem dizinleri (C:\, C:\Users, Temp) asla güvenlik duvarı veya antivirüs dışlamalarına eklenemez. Dışlamalar mikroskobik ölçekte tutulmalı ve ACL ile kilitlenmelidir.

---

### Soru 2 (G009-SC2): Windows üzerinde laboratuvar hazırlığı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Bir nükleer reaktörün kontrol çubukları ve acil durum soğutma vanalarının devreye alma testini düşün: Girdi olarak reaktörün işletim parametrelerini verirsin; işlem olarak soğutma vanalarının açık olup olmadığını ve sızıntı dedektörlerini denetlersin; beklenen sonuç reaktörün "Sıfır Radyasyon Sızıntısı" ile devreye alınmasıdır; negatif kontrol ise bilerek soğutma vanasını kapattığında sistemin acil durum alarmı verip reaktörü derhal kapatmasıdır (SCRAM). Windows laboratuvar denetleyicisi de aynı şekilde sızıntı kapılarını kilitler.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Geliştirdiğimiz `windows_lab_provisioner.py` ve `test_windows_lab_provisioner.py` mimarisinde bu 4 adım şu şekilde çalışır:
* **Girdi (Input):** Windows laboratuvar yapılandırma parametrelerini (VBS/HVCI durumu, Windows Sandbox ağ ve klasör ayarları, Hyper-V vSwitch türleri, Defender dışlama listeleri ve ACL doğrulama verileri) içeren makinece okunabilir JSON dosyası (`windows_lab_yapilandirmasi.json`).
* **İşlem (Process):** Motorun Windows güvenlik çekirdeğini 5 aşamada denetlemesi:
  1. *Sanallaştırma Denetimi:* Hyper-V, VBS ve HVCI durumlarının doğrulanması.
  2. *Sandbox Denetimi:* `<Networking>` etiketinin `Disable` ve eşlenen klasörlerin `salt_okunur=True` olduğunun denetimi.
  3. *vSwitch Denetimi:* Sanal anahtarın `Internal` veya `Private` olduğunun doğrulanması (`External` engellenir).
  4. *Defender Dışlama Denetimi:* Yasaklı kök dizinlerin (`C:\`, `C:\Users`, `%TEMP%`) dışlama listesinde olmadığının ve ACL'de standart kullanıcı yazma yasağının teyidi.
  5. *WSL2 Denetimi:* Sürüm 2 ve `/mnt/c` salt-okunur mod kontrolü.
* **Beklenen Sonuç (Expected Output):** Sertleştirilmiş `WIN-LAB-SEC-01` profili için 100/100 güvenlik skoru, sıfır bulgu, durumun "GÜVENLİ" olarak onaylanması ve standartlara uygun `Izole_Zararli_Inceleme.wsb` XML profilinin üretilmesi.
* **Negatif Kontrol (Negative Control):** Kasıtlı olarak Sandbox ağı `Default` yapıldığında veya konak `C:\` dizini eşlendiğinde ya da vSwitch `External` olarak ayarlandığında; motorun derhal 30-50 puan ceza keserek işlemi "FELAKET / KRİTİK" seviyesinde durdurması ve çıkış kodu 2 (`Exit Code 2`) vermesidir.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan bir laboratuvarda "External" vSwitch'e bağlanmış bir analiz sanal makinesini tespit ettiğinde; sanal makinenin dışarıdaki konak ağ kartıyla aynı yayın (broadcast) etki alanında olduğunu anlar. Ağ kartına ARP Spoofing veya LLMNR/NBT-NS Poisoning saldırısı yaparak laboratuvar dışındaki konak Windows makinenin NTLMv2 kimlik doğrulama hash'lerini yakalar ve kırarak konak sisteme sıçrar.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
Bir siber güvenlik eğitim kampında eğitmen, öğrencilerin makinelerinde Hyper-V üzerinde "External" vSwitch oluşturarak bir zafiyetli Windows Server (Metasploitable) imajı başlatmıştır. Öğrencilerden biri eğitim sırasında sanal makineye sızdığında; zafiyetli makineden yerel Wi-Fi ağına sızmış ve eğitim salonundaki diğer tüm öğrencilerin bilgisayarlarına doğru ağ taraması başlatmıştır.  
**Çıkarılan Ders:** Eğitim ve analiz sanal makineleri asla fiziksel ağa bağlı `External` vSwitch üzerinde koşulmamalıdır. Laboratuvar ortamları her zaman `Internal` veya `Private` vSwitch arkasında izole edilmelidir.

---

### Soru 3 (G009-SC3): 'Windows üzerinde laboratuvar hazırlığı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Risk, zırhlı bir ameliyathanenin kapısına ameliyathane terlikleriyle girilmesini şart koşup, arka kapıyı çamurlu botlarla giren temizlikçilere açık bırakmaya benzer. Ana kapı (Windows Sandbox) son teknolojiyle donatılmıştır; ancak arka kapıdaki ayarlar (Defender'a verilen `C:\` dışlaması veya Sandbox'a verilen yazılabilir `C:\` eşlemesi) ameliyathanenin sterilliğini tamamen yok eder. Windows üzerinde risk; güvenlik araçlarının kullanım kolaylığı adına aşırı geniş yetkilerle yapılandırılmasından doğar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
* **Risk Nasıl Oluşur?**
  1. *Aşırı Geniş Dışlamalar (Over-Permissive Exclusions):* Defender'ın güvenlik araçlarını silmesini önlemek adına `C:\` veya `C:\Users` gibi kök dizinlerin taranmaktan muaf tutulması.
  2. *Gevşek Sandbox Ağ Ayarı:* Windows Sandbox'ın `<Networking>Default</Networking>` ile dış internete ve konak yerel ağına bağlı bırakılması.
  3. *Köprülenmiş vSwitch (External Bridging):* Hyper-V sanal anahtarının fiziksel adaptöre bağlanarak yanal yayılma (Lateral Movement) yolu açması.
  4. *Çekirdek Yalıtımının Kapatılması:* Eski oyunlar veya imzasız sürücüler çalışsın diye VBS ve HVCI'nin kapatılması.
* **Risk Nasıl Tespit Edilir?**
  * PowerShell ile Defender Dışlama Denetimi: `Get-MpPreference | Select-Object -ExpandProperty ExclusionPath` komutuyla dışlanan yolların otomatik taranması.
  * Hyper-V Ağ Denetimi: `Get-VMSwitch | Select-Object Name, SwitchType` ile `External` anahtarların listelenmesi.
  * `.wsb` XML Statik Analizi: `windows_lab_provisioner.py` gibi araçlarla `<Networking>` ve `<ReadOnly>` etiketlerinin doğrulanması.
  * NTFS ACL Denetimi: `icacls <Dizin>` komutuyla taranmayan klasöre `Users` grubunun yazma yetkisi olup olmadığının kontrolü.
* **Hangi Kontrolle Önlenir?**
  * *NIST CSF PR.AC (Kimlik ve Erişim Yönetimi):* Dışlanan klasörlere katı ACL uygulanması (Yalnızca SYSTEM ve Administrators yazabilir).
  * *NIST CSF PR.PT (Koruyucu Teknoloji):* Windows Sandbox'ta `<Networking>Disable</Networking>` ve `<ReadOnly>true</ReadOnly>` zorunluluğu; Hyper-V'de yalnızca `Internal` veya `Private` vSwitch kullanımı.
  * *NIST CSF PR.DS (Veri Güvenliği):* VBS ve HVCI açık tutularak çekirdek bütünlüğünün donanımsal olarak kilitlenmesi.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan bir kullanıcı hesabını ele geçirdiğinde, `icacls "C:\Guvenli_Lab\Araclar"` çıktısını inceler. Eğer bu dizinde `BUILTIN\Users:(OI)(CI)(F)` (Standart kullanıcılar için tam yetki) görürse; antivirüsün burayı taramadığını bildiği için zararlı dosyasını buraya yazar ve çalıştırır. Savunmacı antivirüs kurduğunu sanırken, saldırgan sistemde aylarca fark edilmeden barınır (Persistence).

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2021 yılında SolarWinds ve benzeri tedarik zinciri saldırılarının ardından yayınlanan siber güvenlik raporlarında; tehdit aktörlerinin kurban sistemlerde ayrıcalık kazandıktan sonra ilk iş olarak Windows Defender'ın dışlama listesine geçici dizinleri (`%APPDATA%` ve `%TEMP%`) ekledikleri ve tüm ikinci aşama yüklerini (Cobalt Strike Beacon) bu dışlanan dizinlerden yürüttükleri belgelenmiştir.  
**Çıkarılan Ders:** Bir sistemde dışlama tanımlamak, saldırgana doğrudan güvenli bir sığınak sağlamak anlamına gelebilir. Dışlamalar her zaman merkezi olarak izlenmeli, en az ayrıcalık ilkesiyle sınırlandırılmalı ve sıradan kullanıcıların yazmasına kesinlikle kapatılmalıdır.
