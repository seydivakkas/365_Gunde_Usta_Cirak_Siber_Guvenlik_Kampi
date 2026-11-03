# Gün 147: Mini Proje 20 — IAM Politika Matrisi: 3 Derin Teknik Soru ve Kapsamlı Yanıtlar

**Modül:** Hafta 21 — Gün 147 (Excel Satır 151 — Haftalık Mini Proje 20)  
**Konu:** Kurumsal IAM Politika Matrisi, Katmanlama (Tiering), Kerberos RBCD ve Sıfır Güven (Zero Trust)  
**Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas) — Özel Lisans (Tüm Hakları Saklıdır)

---

### Soru 1: Microsoft Enterprise Access Katmanlama (Tiering Model) Mimarisi ve Pass-the-Hash / Credential Dumping Savunması

#### 1. Soru Başlığı ve Tanımı
Microsoft'un Privileged Access mimarisinde tanımladığı **Katmanlama Modeli (Tier 0, Tier 1, Tier 2)** nedir? Bu modelde en kritik güvenlik kuralı olan *"Üst katman hesapları asla alt katman makinelerinde oturum açamaz"* ilkesi, saldırganların **Kimlik Bilgisi Sızdırma (Credential Dumping / LSASS)** ve **Karma Aktarımı (Pass-the-Hash / Overpass-the-Hash)** teknikleriyle etki alanını ele geçirmesini mimari düzeyde nasıl engeller?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Geleneksel kurumsal ağlarda etki alanı yöneticileri (Domain Admins), kullanıcıların bilgisayarlarında ortaya çıkan yazılım ve donanım sorunlarını çözmek amacıyla doğrudan standart iş istasyonlarına (Tier 2) RDP veya yerel konsol üzerinden kendi ayrıcalıklı hesaplarıyla oturum açarlar.

Bu davranış şu zincirleme saldırı riskini doğurur:
1. **LSASS Bellek İhlali (Credential Theft):** Windows işletim sisteminde bir kullanıcı oturum açtığında, Local Security Authority Subsystem Service (LSASS) süreci oturum biletlerini, Kerberos anahtarlarını ve NTLM parola karmalarını belleğinde önbelleğe alır.
2. **Yatay Geçiş ve Yetki Yükseltme (Lateral Movement & Privilege Escalation):** Eğer o iş istasyonu daha önceden oltalama (phishing) veya zararlı yazılımla ele geçirilmişse, saldırgan yerel yönetici yetkisiyle `Mimikatz` veya benzeri araçları çalıştırarak bellekteki Domain Admin kimlik bilgilerini (NTLM hash veya TGT bileti) çalar.
3. **Ormanın Tamamı Ele Geçer (Full Forest Compromise):** Çalınan NTLM hash'i Pass-the-Hash tekniğiyle, çalınan Kerberos bileti ise Pass-the-Ticket tekniğiyle doğrudan Domain Controller'a karşı kullanılır. Saldırgan hiçbir şifre kırmadan saniyeler içinde tüm etki alanının mutlak hakimi haline gelir.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Katmanlama modelinin uygulanması ve teknik izolasyon şu mimari adımlarla sağlanır:

```text
[Tier 0 Yönetici (Domain Admin)]
       │
       ├─── X [YASAK!] ───> [Tier 2 İş İstasyonu] (LSASS Belleğinde Hash Kalır!)
       │
       └─── [İZİNLİ] ────> [Tier-0 PAW (Ayrıcalıklı Erişim İstasyonu)] ───> [Domain Controller]
```

1. **Katman Tanımları ve Ayrımı:**
   - **Tier 0 (Kimlik Düzlemi):** Domain Controller'lar, Kurumsal CA, ADFS, Azure AD Connect ve özel Tier-0 PAW (Privileged Access Workstation) makineleri.
   - **Tier 1 (Sunucu Düzlemi):** Kurumsal veritabanları (SQL/Oracle), web sunucuları, dosya paylaşımları ve iş uygulamaları.
   - **Tier 2 (Uç Nokta Düzlemi):** Kullanıcı dizüstü/masaüstü bilgisayarları, yazıcılar ve mobil cihazlar.
2. **GPO Tabanlı Oturum Engelleme Politikaları (User Rights Assignment):**
   - Tier-1 ve Tier-2 OU'larına bağlanan Group Policy nesneleriyle Tier-0 hesapları için şu kısıtlamalar zorunlu kılınır:
     * `Deny log on locally` (Yerel oturum açmayı reddet)
     * `Deny log on through Remote Desktop Services` (RDP oturum açmayı reddet)
     * `Deny log on as a batch job / service` (Servis/Toplu iş olarak çalıştırmayı reddet)
3. **Üç Ayrı Hesap Prensibi:**
   - Her sistem yöneticisine 3 ayrı hesap verilir:
     * `ahmet.user` (Tier-2: E-posta okuma, internet, ofis işleri)
     * `ahmet.srv` (Tier-1: Sunucu ve veritabanı yönetimi)
     * `ahmet.adm` (Tier-0: Yalnızca PAW üzerinden DC ve kimlik yönetimi)
4. **LAPS Entegrasyonu:**
   - Tier-1 ve Tier-2 makinelerin yerel yönetici parolaları Windows LAPS ile rastgele ve benzersiz hale getirilir; böylece bir bilgisayar ele geçirilse dahi saldırgan aynı yerel parolayla diğer makinelere sıçrayamaz.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Domain Admin hesabı ameliyathane neşteridir; onunla mutfakta soğan doğranmaz! Bir etki alanı yöneticisinin standart bilgisayara oturum açtığı an, şirketin şifresi internete düşmüş demektir."
- *Altın Kural:* Tier-0 yöneticileri asla internete bağlı genel iş istasyonlarından yönetici işlemi yapmamalı; yönetim yalnızca internet erişimi ve e-posta istemcisi bulunmayan, donanım düzeyinde kilitlenmiş PAW (Privileged Access Workstation) üzerinden icra edilmelidir.

---

### Soru 2: Kerberos Kısıtlamasız Yetki Devrinden (Unconstrained Delegation) Kaynak Tabanlı Kısıtlı Yetki Devrine (RBCD) Geçiş ve Bilet Güvenliği

#### 1. Soru Başlığı ve Tanımı
Kerberos kimlik doğrulama mimarisinde **Kısıtlamasız Yetki Devri (Unconstrained Delegation)** ile **Kaynak Tabanlı Kısıtlı Yetki Devri (Resource-Based Constrained Delegation - RBCD)** arasındaki fark nedir? Kısıtlamasız yetki devri neden kritik bir güvenlik açığıdır ve kurumsal sistemlerde RBCD modeline geçiş nasıl kurgulanır?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Çok katmanlı kurumsal uygulamalarda (örneğin kullanıcı -> IIS Web Sunucusu -> SQL Veritabanı), web sunucusunun kullanıcının kimliğiyle arka plandaki veritabanına sorgu atabilmesi için Kerberos Delegation mekanizması kullanılır.

Kısıtlamasız yetki devrinin ürettiği devasa risk şudur:
1. **TGT Biletinin Sunucuya Kopyalanması:** Bir kullanıcı Kısıtlamasız Yetki Devri (`TRUSTED_FOR_DELEGATION`) aktif olan bir web sunucusuna bağlandığında, Kerberos istemcisi kullanıcının TGT (Ticket Granting Ticket) biletini bizzat web sunucusunun LSASS belleğine teslim eder.
2. **Yönetici Biletinin Belleğe Düşmesi:** Eğer bir Domain Admin veya ayrıcalıklı hesap o web sitesini ziyaret ederse, etki alanı yöneticisinin sınırsız yetkili TGT bileti web sunucusunun belleğine yazılır.
3. **Bilet Çalma ve DC Ele Geçirme (Ticket Harvesting):** Web sunucusundaki bir güvenlik açığından (RCE veya yerel yönetici) yararlanan bir saldırgan, bellekteki bu TGT biletini alarak (`sekurlsa::tickets /export`) doğrudan etki alanı denetleyicisine bağlanabilir ve sahte bilet akışıyla tüm sistemi fetheder.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Bu kritik açığın kapatılması için modern çözüm **Kaynak Tabanlı Kısıtlı Yetki Devridir (RBCD)**:

```text
GELENEKSEL KISITSIZ (TEHLİKELİ):
[İstemci] ──(TGT Biletini Verir)──> [Web Sunucusu (Ele Geçirilirse TGT Çalınır!)] ──> [SQL]

KAYNAK TABANLI KISITLI (RBCD - GÜVENLİ):
[İstemci] ──(Yalnızca Web Servis Bileti)──> [Web Sunucusu]
                                                  │ (S4U2Self & S4U2Proxy)
                                                  ▼
                                            [SQL Veritabanı]
  (SQL Sunucusu Kendi msDS-AllowedToActOnBehalfOfOtherIdentity Özniteliğinde İzin Verir)
```

1. **RBCD Mimarisinin Üstünlüğü:**
   - RBCD'de ön yüzdeki sunucuya hiçbir global yetki devri hakkı verilmez.
   - İzin kuralı hedef kaynağın (SQL) Active Directory nesnesi üzerindeki `msDS-AllowedToActOnBehalfOfOtherIdentity` güvenlik tanımlayıcısına (Security Descriptor) yazılır.
   - Yani SQL sunucusu şunu söyler: *"Ben yalnızca WEB01 sunucusunun bana yetki devriyle bağlanmasına izin veriyorum."*
2. **PowerShell ile RBCD Yapılandırması:**
   ```powershell
   # 1. Web sunucusunun AD bilgisayar nesnesini al
   $WebComputer = Get-ADComputer -Identity "IIS-WEB01"

   # 2. SQL sunucusu üzerinde RBCD izni tanımla
   Set-ADComputer -Identity "SQL-PROD01" -PrincipalsAllowedToDelegateToAccount $WebComputer

   # 3. Kısıtlamasız yetki devrini web sunucusundan tamamen kaldır
   Set-ADComputer -Identity "IIS-WEB01" -TrustedForDelegation $false
   ```
3. **Korumalı Kullanıcılar (Protected Users) Grubu:**
   - Kritik hesaplar (Domain Admins vb.) `Protected Users` grubuna eklenir. Bu gruptaki hesapların TGT biletleri hiçbir koşulda sunuculara devredilemez (`NOT_DELEGATED`).

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Kısıtlamasız delegasyon, evinin anahtarını apartman kapıcısına 'isteyen gelsin girsin' diye bırakmaktır. Yetki devri yapacaksan, izni anahtarı taşıyana değil, kapının bizzat kendisine (kaynağa) vereceksin!"
- *Altın Kural:* Dizin denetimlerinde `userAccountControl:1.2.840.113556.1.4.803:=524288` (TRUSTED_FOR_DELEGATION) bayrağına sahip tüm nesneler taranmalı ve derhal RBCD modeline geçirilmelidir.

---

### Soru 3: Sıfır Güven (Zero Trust) Mimarisi: RBAC, ABAC ve Sürekli Risk Değerlendirmesinin (Continuous Access Evaluation) Bütünleştirilmesi

#### 1. Soru Başlığı ve Tanımı
Geleneksel Rol Tabanlı Erişim Kontrolü (RBAC) neden modern siber tehditler karşısında yetersiz kalmaktadır? Öznitelik Tabanlı Erişim Kontrolü (ABAC), Cihaz Sağlığı, Ağ Güvenilirliği ve **Sürekli Erişim Değerlendirmesi (Continuous Access Evaluation - CAE)** parametreleriyle zenginleştirilmiş bir **Sıfır Güven (Zero Trust)** IAM politika matrisi nasıl çalışır?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Geleneksel RBAC modellerinde bir kullanıcıya "Finans Müdürü" veya "Sistem Yöneticisi" rolü verildiğinde, bu rol statik bir hak tanır. Kullanıcı kullanıcı adı ve parolasını doğru girdiği anda, nereden ve nasıl bağlandığına bakılmaksızın sistem kapıları ardına kadar açar.

Bu statik yaklaşımın açıkları şunlardır:
1. **Çalınan Kimlik Bilgileri (Credential Compromise):** Parola çalındığında veya oturum çerezi (session cookie) çalındığında, saldırgan Rusya'daki bir Tor çıkış noktasından veya ele geçirilmiş şahsi bir bilgisayardan şirket veritabanına bağlanabilir. Statik RBAC bu isteği onaylar çünkü rol geçerlidir!
2. **Güvensiz ve Zafiyetli Cihazlar (BYOD / Compromised Devices):** Çalışan kurumsal hesabı ile yamalanmamış, antivirüsü olmayan şahsi bir bilgisayardan bağlandığında, o makinedeki bir keylogger şirketin tüm verilerini kaydedebilir.
3. **Oturum İçi Değişen Koşullar (Session Hijacking):** Kullanıcı oturum açtıktan sonra ağ konumu değişse veya hesabı şüpheli hareketler sergilese bile, oturum süresi (örn. 8 saat) bitene kadar yetkileri sorgulanmaz.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Sıfır Güven IAM Politika Matrisi, erişim kararını dinamik ve çok değişkenli bir denklem olarak hesaplar:

```text
[GELEN ERİŞİM İSTEĞİ]
         │
         ├── 1. Kimlik Doğrulama: Parola + FIDO2 / Donanım MFA
         ├── 2. Rol Denetimi (RBAC): Kaynak üzerinde atanmış rol var mı?
         ├── 3. Katman (Tier) Uyumu: Tier-0 üst yönetici alt makinede oturum açamaz!
         ├── 4. Cihaz Uyumluluğu (ABAC): MDM kayıtlı mı? EDR aktif mi? BitLocker var mı?
         ├── 5. Ağ & Konum Doğrulaması: Güvenilir IP mi? İmkansız seyahat var mı?
         ├── 6. Davranışsal Risk Puanı: Machine Learning risk skoru < 0.70 mi?
         └── 7. SoD Denetimi: Zehirli rol çatışması taşıyor mu?
         │
         ▼
[DİNAMİK KARAR: PERMIT / DENY]
         │
         ▼ (Oturum Açıldıktan Sonra)
[Sürekli Değerlendirme (CAE)]: Oturum sırasında risk fırlarsa jetonu anında İPTAL ET!
```

1. **Öznitelik Tabanlı Erişim Kontrolü (ABAC / PBAC):**
   - Karar motoru, istek anındaki bağlam nesnesini (`SubjectContext`) analiz eder.
   - Örnek Politika Kuralı: `IF (Role == 'ROLE_DBA_ADMIN' AND Device.IsCompliant == True AND MFA == True AND Session.RiskScore < 0.70 AND Time >= 08:00 AND Time <= 19:00) THEN PERMIT ELSE DENY`.
2. **Sürekli Erişim Değerlendirmesi (CAE / Continuous Access Evaluation):**
   - OpenID Connect / OAuth 2.0 standartlarında token ömürleri beklenmez.
   - Kullanıcı parolasını değiştirdiğinde, işten çıkarıldığında veya IP adresi aniden riskli bir ülkeye sıçradığında IdP sisteme "Revoke Token" sinyali gönderir ve aktif bağlantı milisaniyeler içinde koparılır.
3. **Görevler Ayrılığı (SoD) Entegrasyonu:**
   - ABAC motoru yalnızca kaynağa erişimi değil, kullanıcının o an taşıdığı diğer rolleri de doğrular. Fatura girişi yapan bir kullanıcı, aynı anda ödeme onaylama yetkisine sahipse oturumu reddedilir.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Asla güvenme, her zaman doğrula! Kimlik doğrulama bir defa kapıdan geçerken bilet göstermek değildir; içeride attığın her adımda kimliğini ve niyetini ispatlamaktır."
- *Altın Kural:* Yüksek ayrıcalıklı kaynaklar (Tier 0 ve Tier 1) için cihaz sağlığı ve MFA denetimi koşullu erişim politikalarında "AND" mantığıyla birleştirilmeli; bir tek koşul dahi sağlanamazsa erişim derhal reddedilmelidir.
