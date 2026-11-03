# Gün 145: Group Policy Güvenlik Etkileri — Soru & Cevap

Bu belgede Active Directory Group Policy (GPO) güvenlik mimarisi, SYSVOL cpassword zafiyeti (MS14-025), GPO yetkilendirme suistimalleri (GPO Hijacking), LSDOU miras çatışmaları ve LAPS sertleştirmesi usta-çırak diyaloguyla derinlemesine incelenmiştir.

---

### Soru 1: GPP cpassword Açığı (MS14-025), Kriptografik Zafiyet ve SYSVOL Adli Analizi

#### 1. Soru Başlığı ve Tanımı
**Group Policy Preferences (GPP) ve cpassword Felaketi:** Group Policy Preferences aracılığıyla dağıtılan yerel hesap parolaları AES-256 gibi güçlü bir algoritmayla şifrelenmesine rağmen neden tamamen güvensiz kabul edilmektedir? MS14-025 bülteniyle kapatılan bu açık kurumsal bir Active Directory ortamında adli olarak nasıl taranır ve bertaraf edilir?

#### 2. Derinlemesine Teknik Analiz
Group Policy Preferences (GPP), 2008 yılında yöneticilerin etki alanındaki tüm uç noktalara yerel yönetici veya servis hesapları tanımlamasını kolaylaştırmak amacıyla tanıtılmıştır:
1. **Şifreleme Mimarisi:** GPP, parolayı `cpassword` özniteliği adı altında AES-256 CBC algoritmasıyla şifreler ve `\\domain\sysvol\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml` içinde saklar.
2. **Zafiyetin Kök Nedeni:**
   - **SYSVOL Erişim İzni:** `SYSVOL` klasörü tüm etki alanı kullanıcılarına (Authenticated Users) varsayılan olarak okuma (`Read`) yetkisiyle açıktır.
   - **Sabit Statik Anahtar (Static Key Leak):** Microsoft, geliştiriciler için hazırladığı MSDN belgelerinde bu AES-256 şifrelemesinde kullanılan simetrik özel anahtarı yanlışlıkla açıkça yayınlamıştır:
     `4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`
3. **Saldırı Mekanizması:** Saldırgan ağdaki en düşük yetkili bir kullanıcı hesabıyla SYSVOL içindeki XML dosyalarını tarar (`findstr /S /I cpassword \\domain\sysvol\*.xml`). Bulunan `cpassword` dizgisi, bilinen bu 32 baytlık statik anahtarla saniyeler içinde düz metne (plaintext) çözülür (`gpp-decrypt`). Bu parola genellikle tüm uç noktalardaki yerel `Administrator` parolası olduğundan, saldırgan tüm ağda yerel yönetici haklarına kavuşur.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir enerji dağıtım kurumunda yapılan sızma testinde kırmızı takım, hiçbir açık portu istismar etmeden, doğrudan SYSVOL içindeki 2012 yılından kalma unutulmuş bir `Groups.xml` dosyasından `cpassword` çekmiş ve 10 dakika içinde tüm sunucularda yerel yönetici olmuştur.

**Pratik Çözüm ve Temizlik Adımları:**
1. **SYSVOL'deki Tüm XML Tercih Dosyalarını Tarama ve Temizleme:**
   ```powershell
   # SYSVOL içindeki cpassword kalıntılarını tespit etme
   Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Include *.xml | Select-String "cpassword"
   # Zafiyetli XML dosyalarını silme veya cpassword alanını kaldırma
   ```
2. **Parolaların Derhal Sıfırlanması:** Sızan XML dosyalarında adı geçen tüm yerel ve etki alanı hesaplarının parolaları istisnasız değiştirilmelidir.
3. **KB2962486 (MS14-025) Yamasının Doğrulanması:** Bu yama GPMC konsolunun yeni cpassword oluşturmasını engeller.
4. **LAPS Mimarisine Geçiş:** Yerel parolalar asla GPO ile dağıtılmamalı; her makine için rastgele parola üreten **Windows LAPS** ilkesi devreye alınmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, unutma: Dünyanın en güçlü şifreleme algoritmasını kullansan bile, anahtarı kapının paspasının altına bırakırsan kilit anlamsızlaşır. Microsoft'un statik anahtarı tüm internetin ezberindedir. SYSVOL'ü periyodik olarak tara; geçmiş yöneticilerin unuttuğu tek bir XML dosyası, tüm kurumsal savunmanı yerle bir edebilir."

---

### Soru 2: GPO Yetkilendirme Suistimali (GPO Hijacking) ve WriteDacl Haklarının İstismarı

#### 1. Soru Başlığı ve Tanımı
**GPO ACL Suistimali ve Etki Alanı Yetki Yükseltme (Privilege Escalation):** Bir saldırgan, düşük yetkili bir kullanıcı veya grup üzerinden belirli bir GPO nesnesi üzerinde `WriteDacl`, `WriteOwner` veya `GenericAll` iznine sahip olduğunu keşfederse, bu yetkiyi kullanarak etki alanındaki binlerce bilgisayarda nasıl `NT AUTHORITY\SYSTEM` haklarına sıçrar? Bu saldırı yolu Active Directory'de nasıl engellenir?

#### 2. Derinlemesine Teknik Analiz
Group Policy nesneleri Active Directory'de `CN=Policies,CN=System,DC=kurum,DC=local` konteyneri altında birer nesnedir ve üzerlerinde standart Windows DACL izinleri bulunur:
1. **Tehlikeli İzinler:**
   - `WriteDacl`: Bir nesnenin erişim kontrol listesini (izinlerini) değiştirme hakkıdır. Saldırgan bu hakka sahipse kendine hemen `Full Control (GenericAll)` verir.
   - `WriteOwner`: Nesnenin sahibini değiştirme hakkıdır. Sahip olan kullanıcı da kendine tüm izinleri atayabilir.
   - `GenericAll` / `GenericWrite`: GPO'nun içeriğini ve ayarlarını doğrudan değiştirme yetkisidir.
2. **GPO Hijacking Mekanizması (T1484.001):**
   - Saldırgan GPO üzerinde yazma yetkisini aldıktan sonra iki yöntemle zararlı yük ekler:
     - **Anında Çalışan Zamanlanmış Görev (Immediate Scheduled Task):** GPO Tercihleri içine bir XML ekleyerek bilgisayarların `SYSTEM` haklarıyla bir Powershell/Reverse Shell komutunu anında koşturmasını sağlar.
     - **Başlangıç Betiği (Startup Script):** Bilgisayar yeniden başladığında veya 90 dakikalık varsayılan GPO yenileme aralığında arka planda çalışan komut.
   - O GPO hangi OU'ya (örneğin Domain Controllers veya Member Servers) bağlıysa, o OU altındaki tüm makineler saldırganın komutunu en yüksek sistem yetkileriyle icra eder.
3. **BloodHound Tespiti:** BloodHound aracı bu saldırıyı `GenericAll -> GPO -> OU -> Computer` çizge yoluyla anında ortaya çıkarır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kamu kuruluşunda yardım masası (HelpDesk) ekibine işlerini kolaylaştırmak amacıyla "Tüm GPO'ları Yönetme" izni verilmiştir. Yardım masası çalışanlarından birinin bilgisayarı oltalandığında saldırgan, yardım masası yetkilerini kullanarak kök GPO'ya bir reverse shell betiği eklemiş ve 1 saat içinde 4.000 makinede tam hakimiyet kurmuştur.

**Pratik Çözüm ve Sertleştirme:**
1. **GPO ACL İzinlerinin Denetlenmesi ve Daraltılması:**
   ```powershell
   # GPO üzerinde standart kullanıcılara ait tehlikeli izinleri listeleme
   Import-Module ActiveDirectory
   Get-Acl "AD:\CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=kurum,DC=local" | Select -Expand Access
   ```
2. **Tier Modeli ve En Az Ayrıcalık (Least Privilege):** GPO oluşturma, düzenleme ve bağlama (GPLink) yetkileri yalnızca Tier 0 (Domain Admins / Enterprise Admins) yöneticilerine verilmelidir.
3. **SYSVOL Dosya İzinleri:** SYSVOL altındaki GPO klasörlerinde standart kullanıcıların yalnızca `Read` ve `Execute` hakkı olmalı; `Write` veya `Modify` kesinlikle kaldırılmalıdır.
4. **GPO Değişiklik Denetimi:** Olay Günlüğü 5136 (Dizin Hizmeti Nesnesi Değiştirildi) ve 5137 kayıtları SIEM'de GPO modifikasyonları için anlık tetikleyici yapılmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, GPO'ya yazma yetkisi vermek, o kişiye kalenin tüm anahtarlarını, şifreli kasalarını ve mancınıklarını teslim etmektir. Bir stajyere veya yardım masası personeline 'GPO düzenlesin' diye yetki verirsen, o personel üzerinden tüm ormanın düşmesini garanti etmiş olursun. GPO'lar Tier 0 kutsal alanıdır; oraya sadece tam donanımlı etki alanı yöneticileri adım atabilir."

---

### Soru 3: LSDOU Miras Sırası, Block Inheritance ve Enforced (NoOverride) Güvenlik Çatışmaları

#### 1. Soru Başlığı ve Tanımı
**LSDOU Öncelik Sırası ve Güvenlik Çatışması:** Active Directory organizasyonel birimlerinde (OU) alt birim yöneticileri `Block Inheritance` (Miras Engelleme) açtığında üstten gelen kurumsal güvenlik politikaları (örneğin LAPS, Antivirüs, USB engelleme) devre dışı kalabilir mi? Kurumsal güvenlik yöneticileri bu riski `Enforced` (NoOverride) bayrağıyla nasıl aşar?

#### 2. Derinlemesine Teknik Analiz
Group Policy motoru ilkeleri uygularken **LSDOU (Local -> Site -> Domain -> OU)** sırasını takip eder.
1. **Varsayılan Çakışma Kuralı:** Hiyerarşide en son işlenen ilke, önceki ilkelerdeki çakışan ayarları ezer. Eğer Domain seviyesinde "Parola karmaşıklığı açık" denilmiş, fakat alt OU seviyesindeki GPO'da "Parola karmaşıklığı kapalı" denilmişse; alt OU'daki GPO en son işlendiği için o OU'daki kullanıcılar için kural ezilir!
2. **Block Inheritance (Miras Engelleme) Riski:**
   - Bir OU üzerinde "Block Inheritance" etkinleştirilirse, yukarıdan (Site, Domain ve üst OU'lar) gelen tüm ilkeler o noktada durdurulur ve alt nesnelere uygulanmaz.
   - Bu durum, alt birim yöneticilerinin istemeden kurumsal EDR, LAPS veya firewall ilkelerinden muaf 'kör noktalar' (shadow IT) oluşturmasına neden olur.
3. **Enforced (Zorunlu / NoOverride) Gücü:**
   - Bir üst GPO (örneğin CIS Baseline GPO) 'Enforced' olarak işaretlendiğinde iki kritik kural devreye girer:
     1. **Miras Engeli Geçersiz Kılınır:** Alt OU'larda `Block Inheritance` açık olsa bile, Enforced olan ilke o engeli deler ve zorla uygulanır!
     2. **Öncelik Üste Geçer:** Alt OU'lardaki GPO'lar çakışan bir ayar içerse dahi Enforced olan üst ilkeyi ezemez; üst ilke daima kazanır.
4. **WMI Filtreleme:** İlkelerin yalnızca belirli işletim sistemi sürümlerine (örn. Windows Server 2022 veya Windows 11) uygulanması için WMI filtreleri kullanılmalıdır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir holdingin Ar-Ge departmanı, yazılım testleri sırasında kısıtlamalara takılmamak için kendi OU'larında `Block Inheritance` bayrağını açmıştır. Bu durum kurumun LAPS ilkesini ve Defender ATP yapılandırmasını devre dışı bırakmış; Ar-Ge ağına sızan fidye yazılımı (ransomware) tüm makinelerin yerel parolasını aynı bularak holdingin sunucularını kilitlemiştir.

**Pratik Çözüm ve Kurumsal Mimari:**
1. **Kritik Güvenlik İlkelerinin Enforced Yapılması:**
   ```powershell
   # Temel güvenlik taban çizgisini Domain kökünde Enforced yapma
   Set-GPLink -Name "GPO-Enforce-Windows-LAPS" -Target "DC=kurum,DC=local" -Enforced Yes
   Set-GPLink -Name "CIS-Core-Security-Baseline" -Target "DC=kurum,DC=local" -Enforced Yes
   ```
2. **Miras Blokajı Olan OU'ları Otomatik Tarama:**
   ```powershell
   # Etki alanında Block Inheritance aktif olan OU'ları listeleme
   Get-ADOrganizationalUnit -Filter * -Properties gpOptions | Where-Object { $_.gpOptions -eq 1 }
   ```
3. **İstisna Yönetimi:** Güvenlik ilkeleri engellenerek istisna verilmemeli; gerekirse Güvenlik Filtrelemesi (Security Filtering) veya WMI Filtreleri ile kontrollü muafiyet sağlanmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, 'Block Inheritance' alt birimlerin bağımsızlık ilan etmesidir. Ancak siber güvenlikte bağımsızlık, federasyonun en zayıf halkası haline gelir. Kurumun omurgasını oluşturan güvenlik politikalarını (LAPS, Audit, Antivirüs) mutlaka etki alanı köküne bağla ve üzerlerine 'Enforced' mührünü vur. Enforced mührü olan kuralın önünde hiçbir alt miras engeli duramaz!"
