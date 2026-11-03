# Gün 143: Active Directory Etki Alanı — Soru & Cevap

Bu belgede Active Directory Domain Services (AD DS) mimarisi, kimlik doğrulama altyapısı, etki alanı denetleyicisi (DC) sertleştirme ve kritik saldırı vektörlerine karşı kurumsal savunma mekanizmaları usta-çırak pedagojik diyaloguyla derinlemesine incelenmiştir.

---

### Soru 1: KRBTGT Hesabı Yaşam Döngüsü ve Golden Ticket Saldırılarına Karşı Savunma

#### 1. Soru Başlığı ve Tanımı
**KRBTGT Parolası ve Çift Sıfırlama Mekanizması:** Active Directory etki alanında Kerberos biletlerinin (TGT) şifrelenmesinde kullanılan `krbtgt` hesabının parolası neden periyodik olarak ve aralıklı çift adımda sıfırlanmalıdır? Bu işlem yapılmadığında saldırganların kalıcılık (persistence) sağlama stratejisi (Golden Ticket) nasıl işler?

#### 2. Derinlemesine Teknik Analiz
Active Directory Kerberos KDC (Key Distribution Center) mekanizmasında, istemcilerin kimlik doğrulaması sonrasında aldığı TGT (Ticket Granting Ticket) biletleri etki alanına özel `krbtgt` servis hesabının NTLM veya AES-256 anahtarı ile imzalanır ve şifrelenir.
1. **Golden Ticket Mekanizması:** Saldırgan etki alanı denetleyicisinde NTDS.dit dosyasını elde ederse veya `dcsync` yetkisiyle `krbtgt` hash değerini çıkarırsa (Mimikatz `lsadump::dcsync /domain:lab.local /user:krbtgt`), sahte bir TGT bileti üretebilir. Bu bilet içine istediği kullanıcı adını (örn. Administrator), istediği SID değerini ve Enterprise Admins (RID 519) grup üyeliğini enjekte edebilir. Bilet KDC tarafından değil, saldırgan tarafından imzalanmış olsa bile KDC kendi simetrik anahtarıyla doğruladığı için bileti sorgusuz kabul eder.
2. **Neden Çift Sıfırlama (Double Reset) Zorunludur?** Active Directory, kullanıcı ve servis hesaplarının mevcut parolasıyla birlikte bir önceki parolasını da (password history) `krbtgt` hesabında saklar. Bu tasarım, replikasyon gecikmelerinde aktif istemcilerin hizmet kesintisi yaşamamasını sağlar. Dolayısıyla `krbtgt` parolası tek bir kez sıfırlandığında, önceki parola geçmişte kalır ve saldırganın ürettiği Golden Ticket'lar geçerliliğini korumaya devam eder!
3. **Bekleme Süresi (Cooldown Interval):** Parola ilk kez sıfırlandıktan sonra, tüm DC'lere replike olması beklenir ve etki alanındaki geçerli TGT'lerin maksimum ömrü kadar (varsayılan 10 saat) beklenmelidir. İkinci sıfırlama yapıldığında ilk parola tarih olur ve saldırganın elindeki tüm Golden Ticket'lar anında geçersiz kılınır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kurumunun kırmızı takım (Red Team) tatbikatında, dış kaynaklı bir test kullanıcısı üzerinden DCSync saldırısıyla `krbtgt` hash'i sızdırılmıştır. Saldırgan ortamda tespit edilip bağlantısı kesilse bile, 10 yıl geçerli Golden Ticket oluşturarak kalıcılık sağlamıştır.

**Pratik Çözüm ve Kurtarma:**
1. Microsoft'un resmi `New-KrbtgtKeys.ps1` scripti veya PowerShell ile kontrollü çift sıfırlama icra edilir:
   ```powershell
   # 1. Aşama: İlk KRBTGT sıfırlaması
   Reset-KrbtgtAccount -Domain "kurum.local" -PassLength 64 -CooldownPeriodHours 12
   # Replikasyonun tamamlanması için bekleme ve denetim
   repadmin /syncall /AdeP
   # 2. Aşama: 12-24 saat sonra ikinci sıfırlama
   Reset-KrbtgtAccount -Domain "kurum.local" -PassLength 64
   ```
2. **AES-256 Şifreleme Zorlaması:** Etki alanında DES ve RC4 şifreleme süitleri devre dışı bırakılmalı, `msDS-SupportedEncryptionTypes` değeri `0x18` (AES128 + AES256) veya `0x38` olarak yapılandırılmalıdır.
3. **Olay Günlüğü Takibi:** Olay Kimliği 4768 (TGT İstendi) ve 4769 (Hizmet Bileti İstendi) günlüklerinde kullanılan şifreleme türü (Ticket Options / Encryption Type: `0x12` = AES256) yakından izlenmelidir.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, Active Directory ortamında bir kez etki alanı yöneticisi hakları sızdırıldıysa, o etki alanının tüm şifreleri değişse bile `krbtgt` sıfırlanmadıkça temizlendiğini iddia edemezsin. `krbtgt` parolasını yılda en az iki kez (örneğin 180 günde bir) rutin bir takvimle ve kontrollü çift sıfırlamayla yenilemeyi kurumsal güvenlik politikanın değişmez maddesi yap."

---

### Soru 2: SPN Kayıtları, Kerberoasting Riski ve gMSA Mimarisi

#### 1. Soru Başlığı ve Tanımı
**Hizmet Asıl Adları (SPN) ve Kerberoasting Tehdidi:** Active Directory ortamlarında Service Principal Name (SPN) kaydı bulunan kullanıcı hesapları nasıl Kerberoasting saldırısının hedefi haline gelir? Bu zafiyetin kök nedeni nedir ve Group Managed Service Accounts (gMSA) mimarisi bu riski nasıl tamamen ortadan kaldırır?

#### 2. Derinlemesine Teknik Analiz
Kerberos protokolünde bir istemci, ağdaki bir servise (örn. SQL Server, IIS Web) erişmek istediğinde KDC'den bir TGS (Ticket Granting Service) bileti talep eder:
1. **Kerberoasting Mekanizması:** İstemci, etki alanındaki geçerli herhangi bir domain kullanıcısı hesabıyla KDC'ye başvurarak `MSSQLSvc/db01.lab.local:1433` SPN'i için TGS ister. KDC bu talebi yetki kontrolü yapmaksızın onaylar ve TGS biletini servisi çalıştıran hesabın parola özetiyle (NTLM/RC4 veya AES hash) şifreleyerek istemciye döner.
2. **Çevrimdışı Kırma (Offline Cracking):** Saldırgan aldığı bu TGS biletini bellekten dışa aktarır (Mimikatz, Rubeus) ve kendi yerel makinesine taşıyarak Hashcat veya John the Ripper ile çevrimdışı parola kırma saldırısı yürütür. Bu aşamada etki alanına hiçbir ağ trafiği gitmez; kırma işlemi tamamen yerel GPU gücüyle gerçekleşir.
3. **Neden Yönetici Hesaplarında SPN Olmamalıdır?** Eğer bir Domain Admin veya Enterprise Admin üyesi olan hesaba yanlışlıkla bir SPN tanımlandıysa, saldırgan etki alanındaki en yetkili hesabın parola özetini tek bir standart kullanıcı sorgusuyla elde etmiş olur. Parola zayıfsa dakikalar içinde tam etki alanı kontrolü ele geçer.
4. **gMSA (Group Managed Service Accounts) Çözümü:**
   - gMSA, Active Directory KDS (Key Distribution Service) tarafından yönetilen 120 karakterlik, son derece karmaşık rastgele parolalara sahiptir.
   - Parola her 30 günde bir Active Directory tarafından otomatik olarak değiştirilir.
   - Hiçbir insan operatör parolayı bilmez ve manuel olarak oturum açılamaz.
   - Parola o kadar karmaşıktır ki, saldırgan TGS biletini ele geçirse dahi çevrimdışı kırma işlemi matematiksel olarak imkansızdır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir sağlık kuruluşunda veritabanı sunucusu için `sqlservice` adında bir kullanıcı hesabı açılmış ve hızlı kurulum amacıyla `Domain Admins` grubuna eklenmiştir. Saldırgan iç ağa sızdığı ilk 15 dakikada etki alanındaki SPN'leri sorgulamış, `sqlservice` hesabının TGS biletini alarak 1 saat içinde "Hastane2024!" parolasını kırıp tüm etki alanını ele geçirmiştir.

**Pratik Çözüm ve Sertleştirme Adımları:**
1. **SPN Denetimi ve Yönetici Gruplarından Arındırma:**
   ```powershell
   # Ayrıcalıklı grupta olup SPN taşıyan hesapları listeleme
   Get-ADUser -Filter {AdminCount -eq 1 -and ServicePrincipalNames -like "*"} -Properties ServicePrincipalNames, MemberOf
   # SPN kaydını ayrıcalıklı hesaptan kaldırma
   Set-ADUser -Identity "sqlservice" -Clear ServicePrincipalNames
   ```
2. **gMSA Kurulumu ve Geçiş:**
   ```powershell
   # KDS Kök Anahtarı oluşturma (etki alanında bir kez yapılır)
   Add-KdsRootKey -EffectiveImmediately
   # Yeni gMSA hesabı açma
   New-ADServiceAccount -Name "gMSASQLSvc" -DNSHostName "sql01.kurum.local" -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers-Group"
   # SQL servisini gMSA hesabına devretme
   ```
3. **AES Zorunluluğu:** SPN taşıyan servis hesaplarında `msDS-SupportedEncryptionTypes` değeri ayarlanarak RC4 şifreleme devre dışı bırakılmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, unutma: Servis hesaplarını standart Domain Admin hesaplarıyla çalıştırmak kurumsal bir günahtır. Bir hesaba SPN veriyorsan, o hesabın parolasının en az 30 karakter karmaşık olduğunu bilmeli veya doğrudan gMSA'ya geçmelisin. Ayrıcalıklı hesapta SPN görmek, kasayı açık bırakıp üzerine 'içinde altın var' tabelası asmaya benzer."

---

### Soru 3: Orman (Forest) Güvenlik Sınırı ve SID Filtering Koruması

#### 1. Soru Başlığı ve Tanımı
**Orman Güvenlik Sınırları ve SID History İstismarı:** "Active Directory'de etki alanı (Domain) değil, orman (Forest) gerçek güvenlik sınırıdır" ilkesinin altında yatan teknik gerçek nedir? Farklı ormanlar veya etki alanları arasında güven ilişkisi (Trust) kurulurken SID Filtering neden hayati bir koruma sağlar?

#### 2. Derinlemesine Teknik Analiz
Active Directory mimarisinde güvenlik sınırları kavramı sıklıkla yanlış anlaşılır:
1. **Domain vs Forest Güvenlik Sınırı:** Bir orman içindeki farklı alt etki alanları (child domains) birbirinden bağımsız gibi görünse de, alt etki alanındaki bir Domain Admin, ormanın kök etki alanındaki (Forest Root) Enterprise Admins haklarına sıçrayabilir (SID History saldırıları ve Schema Manipulation sayesinde). Bu nedenle Microsoft resmi olarak **tek gerçek güvenlik sınırının ORMAN (Forest)** olduğunu ilan etmiştir.
2. **SID History ve Güven İstismarı (SID Injection):** Bir kullanıcı bir etki alanından diğerine taşındığında (örneğin şirket satın alımlarında), eski kaynaklara erişimini kaybetmemesi için `sIDHistory` özniteliği kullanılır. Bir kullanıcı bilet aldığında, PAC (Privilege Attribute Certificate) içine hem kendi güncel SID'si hem de `sIDHistory` içindeki eski SID'ler yazılır.
3. **Trust Geçişinde Risk:** Eğer A etki alanı B etki alanına güveniyorsa ve A'daki bir saldırgan PAC'indeki `sIDHistory` alanına B etki alanının Domain Admin SID'sini (`S-1-5-21-...-512`) yazarsa, B etki alanı bu bileti doğrularken saldırganı kendi yöneticisi olarak görebilir!
4. **SID Filtering Mekanizması:** SID Filtering aktif olduğunda, güven ilişkisi üzerinden gelen kimlik doğrulama isteklerindeki PAC incelenir. Güvenilen etki alanının yetki alanına girmeyen veya hedef etki alanının etki alanına ait olan SID'ler (özellikle `-500`, `-512`, `-519` gibi ayrıcalıklı RID'ler) paketten filtrelenerek atılır. Böylece yabancı ormandan gelen sahte yönetici SID'leri reddedilir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Holding yapısında bulunan iki farklı şirket arasında iş ortaklığı nedeniyle iki yönlü harici güven (Two-Way External Trust) kurulmuştur. Ancak alt şirketteki bir test sunucusu ele geçirilmiş ve saldırgan, güven ilişkisi üzerinden `netdom trust` yapılandırmasındaki SID Filtering gevşekliğinden faydalanarak ana holding ormanına Enterprise Admin yetkileriyle erişim sağlamıştır.

**Pratik Çözüm ve Sertleştirme:**
1. **Forest Trust ve SID Filtering Zorlaması:**
   ```powershell
   # Dış orman güven ilişkisinde SID Filtering'i aktif etme (Karantina modu)
   netdom trust KurumHolding.local /domain:AltSirket.local /quarantine:yes
   # Forest Trust durumunu doğrulama
   netdom trust KurumHolding.local /domain:AltSirket.local /verify
   ```
2. **Seçici Kimlik Doğrulama (Selective Authentication):** Tüm kullanıcıların otomatik kimlik doğrulaması yapması engellenmeli, yalnızca belirli güvenlik gruplarına atanmış sunuculara erişim verilmelidir (`/selectiveauth:yes`).
3. **SID History Denetimi:** Etki alanındaki tüm kullanıcılarda izinsiz `sIDHistory` kalıntıları düzenli taranmalı ve temizlenmelidir.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, sana 'bizim holdingde 10 tane etki alanı var, her biri ayrı güvenlik bölgesi' diyen bir sistem yöneticisi görürsen hafifçe tebessüm et. Aynı ormanın altındaki bir child domain ele geçirilirse, root forest ele geçirilmiş demektir. Başka bir kurumla güven kuracaksan da orman seviyesinde kur, SID Filtering'i asla kapatma ve seçici kimlik doğrulamayı zorunlu tut."
