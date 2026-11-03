# Hafta 17 / Gün 118: En Az Ayrıcalık ve Sıfır Güven — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: Kalıcı Ayrıcalıkların (Standing Privileges — CWE-250) Riskleri, Zero Standing Privileges (ZSP) ve Just-In-Time (JIT) Yetkilendirme Mimarisi

### 1. Soru Başlığı ve Tanımı
Geleneksel kurumsal kimlik yönetiminde sistem yöneticilerine ve servislere tanımlanan **Kalıcı Ayrıcalıklar (Standing Privileges / 7x24 Admin — CWE-250)** neden en büyük saldırı vektörüdür? Modern Sıfır Güven yaklaşımında benimsenen **Zero Standing Privileges (ZSP)** felsefesi ve **Just-In-Time (JIT) Geçici Yetkilendirme** bu zafiyeti nasıl ortadan kaldırır?

### 2. Derinlemesine Teknik Analiz
Geleneksel IT yapılarında yöneticilere sürekli açık duran `Domain Admin`, `Root` veya `Cloud Global Admin` hesapları verilir. Bu yaklaşımın taşıdığı kritik zafiyetler şunlardır:
1. **Saldırı Yüzeyinin Sürekli Açık Kalması (CWE-250):** Bir yönetici günün yalnızca 30 dakikasında yetkili işlem yaparken, hesabın taşıdığı sınırsız yetki 7 gün 24 saat boyunca bellekte, kimlik sağlayıcıda (IdP) ve istemci uç noktasında durur.
2. **Kimlik Avı ve Oturum Hırsızlığı:** Yöneticinin web'de gezinirken veya e-postalarını okurken tıkladığı kötü amaçlı bir bağlantı, saldırgana doğrudan kalıcı admin oturumunu teslim eder.
3. **İç Tehditler ve Hesap Kötüye Kullanımı:** Eski çalışanların veya yetki aşımı yapan personelin sistemde açtığı arka kapılar denetlenemez hale gelir.

**Zero Standing Privileges (ZSP) ve JIT Mimarisi:**
- **Prensip:** Kimsenin varsayılan olarak yönetici yetkisi yoktur ($\text{Standing Privileges} = \emptyset$).
- **İhtiyaç Anında Talep (On-Demand Request):** Kullanıcı bir müdahale gerektiğinde (örn: acil veritabanı yedeği) yetki talep eder.
- **Kapsam Daraltma (Granular Scoping - CWE-272):** Kullanıcıya "Full Admin" değil, yalnızca o görevi yapmaya yetecek en dar kapsam verilir (örn: `db:maintenance_backup`).
- **Sıkı Yaşam Süresi (Ephemeral TTL - CWE-613):** Belirteç veya hibe en fazla 15 ila 60 dakika geçerli olacak şekilde üretilir. Süre dolduğunda ayrıcalık sistem tarafından otomatik olarak geri alınır. Saldırgan belirteci çalsa dahi dakikalar içinde işe yaramaz hale gelir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Küresel bir finans kurumunda kıdemli bulut mühendisinin dizüstü bilgisayarına "infostealer" zararlısı bulaşmıştır. Mühendisin AWS hesabında kalıcı `AdministratorAccess` rolü bulunmaktadır. Saldırgan tarayıcıdaki oturum çerezlerini ve AWS CLI profilindeki sabit erişim anahtarlarını çalarak gecenin bir yarısı şirketin tüm S3 yedeklerini şifrelemiş ve fidye talep etmiştir (CWE-250).

**Pratik Çözüm (JIT Token Tahsis Mekanizması):**
```python
def issue_jit_temporary_grant(user_id: str, requested_scope: str, approver_id: str, ttl_seconds: int = 1800):
    # 1. Kalıcı ve aşırı yetki talepleri reddedilir (CWE-250)
    if requested_scope in ("*:*", "root", "admin"):
        raise StandingPrivilegeForbiddenError("Sıfır Güven Kuralı: Kalıcı veya sınırsız yetki verilemez!")
        
    # 2. Yetki onaylı katalogda olmalıdır (CWE-272)
    if requested_scope not in APPROVED_JIT_CATALOG:
        raise ExcessiveScopeRequestedError("Talep edilen kapsam katalog dışındadır.")
        
    # 3. Kısıtlı TTL ile geçici nesne üretilir (CWE-613)
    grant_id = f"JIT-{secrets.token_hex(6).upper()}"
    expires_at = datetime.datetime.now() + datetime.timedelta(seconds=ttl_seconds)
    return JITElevationGrant(grant_id, user_id, requested_scope, approver_id, expires_at)
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, bir yöneticiye 7/24 kalıcı admin yetkisi vermek, kapı kilidini söküp anahtarı da paspasın altına koymaya benzer. Kimseye daimi güç verme. Yetkiyi cerrah neşteri gibi kullan: Yalnızca ameliyat anında ver, operasyon biter bitmez sterilize edip geri al."

---

## Soru 2: NIST SP 800-207 Sıfır Güven Mimarisi: Cihaz Sağlığı (Device Posture) ve Dinamik Güven Puanlaması (Continuous Trust Scoring)

### 1. Soru Başlığı ve Tanımı
NIST SP 800-207 Sıfır Güven Mimarisinde yer alan **"Asla Güvenme, Daima Doğrula" (Never Trust, Always Verify)** ilkesi pratikte nasıl işletilir? Kullanıcının kimlik doğrulaması başarılı olsa dahi, **Uç Nokta Cihaz Sağlığı (Device Posture)** ve **Dinamik Güven Skoru (Dynamic Trust Score)** yetkilendirme kararını nasıl doğrudan etkiler?

### 2. Derinlemesine Teknik Analiz
Geleneksel kimlik doğrulama sistemleri "Statik ve Tek Seferlik" (Single Point in Time) çalışır: Kullanıcı oturum açarken doğru parolayı ve SMS kodunu girdiyse, oturum kapatılana kadar sisteme "güvenilir" kabul edilir.
Oysa Sıfır Güven modelinde güven anlık ve geçicidir; sürekli ölçülmelidir (Continuous Adaptive Risk and Trust Assessment - CARTA).

**1. Uç Nokta Sağlığı (Device Posture Assessment - CWE-284):**
Bir kimlik doğrulansa bile, istek zararlı yazılım bulaşmış veya yaması yapılmamış bir cihazdan geliyorsa güven sınırı ihlal edilmiştir:
- Cihaz MDM (Mobile Device Management) tarafından yönetiliyor mu?
- EDR / Antivirüs ajanı aktif ve son tanımları yüklü mü?
- Sabit disk BitLocker veya FileVault ile şifrelenmiş mi?
- İşletim sistemi güvenlik yaması gecikmesi kritik eşiği (örn: 14 gün) aşmış mı?
Bu metrikler üzerinden bir **Cihaz Sağlık Skoru (Posture Score: 0 - 100)** hesaplanır. 60 puanın altındaki cihazlar PEP (Policy Enforcement Point) kapısından içeri sokulmaz.

**2. Dinamik Güven Skoru ve Anomali Azaltımı:**
Oturum boyunca kullanıcının davranışları izlenir:
$$\text{Güven Skoru} = w_1 \times \text{Posture} + w_2 \times \text{Auth} - \sum \text{Anomali Cezaları}$$
- Kullanıcı aniden yetkisi olmayan dosyalara erişmeye çalışırsa,
- İstemci IP adresi veya kullanıcı ajanı (User-Agent) oturum ortasında değişirse,
- İstek sıklığı olağan dışı fırlarsa,  
sistem anomali sayacını artırarak güven skorunu düşürür. Skor kaynağın asgari eşiğinin altına indiğinde oturum anında feshedilir veya kullanıcıdan **Step-Up MFA (CWE-308)** talep edilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir uzaktan çalışan personel, şirket VPN'ine bağlanmış ve meşru kimlik bilgilerini girmiştir. Ancak çalışanın 16 yaşındaki çocuğu, aynı bilgisayara torrent üzerinden korsan oyun indirmiş ve oyunla birlikte gelen arka kapı (RAT) antivirüsü devre dışı bırakmıştır. Saldırgan arka planda aktif VPN oturumunu kullanarak şirket içi finans sunucularına sızmaya çalışmaktadır.

**Pratik Çözüm (Sıfır Güven Doğrulama Kapısı):**
```python
def evaluate_zero_trust_access(session: ZeroTrustSession, resource: ProtectedResource):
    # 1. Cihaz Posture Denetimi: Antivirüs kapalıysa derhal engelle (CWE-284)
    posture = session.device.calculate_posture_score()
    if posture < 60.0 or not session.device.antivirus_active:
        raise DevicePostureUntrustedError(f"Cihaz güvensiz (Puan: {posture:.1f})! Erişim engellendi.")
        
    # 2. Dinamik Güven Skoru Denetimi
    trust = session.evaluate_trust()
    if trust < resource.min_trust_score:
        raise DynamicTrustScoreDegradedError("Güven skoru yetersiz! Oturum askıya alındı.")
        
    # 3. Kritik İşlem Step-Up MFA
    if resource.requires_step_up_mfa and not session.mfa_verified:
        raise StepUpAuthenticationRequiredError("Kritik işlem için anlık Step-Up MFA zorunludur.")
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, güven bir kere verilip sonsuza dek saklanan bir altın madalyon değildir; her saniye eriyen bir buz kalıbıdır. Kullanıcının kimliğine değil, elindeki cihazın temizliğine ve anlık hareketlerine bakacaksın. Yama yapmamış, antivirüsünü kapatmış bir laptop ile gelen çalışan, kapıda bekleyen truva atıdır."

---

## Soru 3: Mikro-Segmentasyon (Micro-Segmentation) ve Yanal Hareketin (Lateral Movement — CWE-284) Ağ Seviyesinde Engellenmesi

### 1. Soru Başlığı ve Tanımı
Geleneksel çevre güvenliğinde (Perimeter Security) bir saldırganın iç ağa sızdıktan sonra serbestçe dolaşmasını ifade eden **Yanal Hareket (Lateral Movement — CWE-284)** neden engellenemez? **Yazılım Tanımlı Mikro-Segmentasyon (Micro-Segmentation)** ve Sıfır Güven Ağ Mimarisi (ZTA) bu tehdidi nasıl etkisiz hale getirir?

### 2. Derinlemesine Teknik Analiz
Klasik kurumsal ağ mimarilerinde tüm iç kaynaklar genellikle birkaç geniş VLAN (örn: İstemciler VLAN'i, Sunucular VLAN'i) içerisinde toplanır. Bir VLAN içindeki makineler arasında hiçbir güvenlik duvarı veya denetim noktası bulunmaz (Flat Network).

**Saldırganın İlerleme Yolu (Flat Network):**
1. Saldırgan muhasebe departmanındaki bir istemciyi (Workstation) oltalamayla ele geçirir.
2. Ağ 'düz' olduğu için saldırgan `nmap` ve `mimikatz` çalıştırarak aynı alt ağdaki diğer 200 istemciyi tarar.
3. Pass-the-Hash veya SMB Relay saldırılarıyla domaindeki diğer sunuculara zıplar (Yanal Hareket - Lateral Movement).
4. Nihayetinde DMZ'deki web sunucusundan veritabanı sunucusuna doğrudan TCP 1433/3306 bağlantısı açarak tüm verileri çeker.

**Mikro-Segmentasyon ile Sıfır Güven Çözümü:**
Mikro-segmentasyon, ağı fiziksel anahtarlara (switch) bağımlı olmaksızın iş yükü (workload) veya servis düzeyinde mikro hücrelere böler:
- Her sunucu veya mikroservis kendi etrafında görünmez bir güvenlik duvarına (Software-Defined Perimeter) sahiptir.
- **Varsayılan Kural: Default Deny.** Farklı segmentler arasında doğrudan paket iletimi imkansızdır.
- Örneğin `Guest_WiFi` segmentindeki bir makine, `Core_Banking` veya `DB_Tier` segmentine IP seviyesinde dahi erişemez.
- İstemciden veritabanına erişim ancak yetkili bir `Management_Jumpbox` üzerinden, kimlik, cihaz sağlığı ve anlık JIT yetkisi doğrulandıktan sonra PEP gözetiminde tünellenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekom operatörünün çağrı merkezi personeline açık olan Wi-Fi ağına bir saldırgan sızmıştır. Ağ mikro-segmente edilmediği için saldırgan Wi-Fi ağından doğrudan abone veri tabanının bulunduğu sunucu kümesine erişmiş ve 10 milyon abonenin kimlik ve iletişim kayıtlarını dump etmiştir (CWE-284).

**Pratik Çözüm (Mikro-Segmentasyon Denetim Kuralı):**
```python
def enforce_micro_segmentation(source_segment: str, target_segment: str, allowed_matrix: dict):
    # Aynı segment içi veya açıkça izinli hedef kontrolü
    if source_segment == target_segment:
        return True
        
    allowed_destinations = allowed_matrix.get(source_segment, set())
    if target_segment not in allowed_destinations:
        raise NetworkMicroSegmentationViolationError(
            f"YANAL HAREKET ENGELLENDİ (CWE-284): '{source_segment}' ağından "
            f"'{target_segment}' ağına doğrudan geçiş kesinlikle yasaktır!"
        )
    return True
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, denizaltılar neden su geçirmez bölmelere (kompartımanlara) ayrılır bilir misin? Bir bölme delinip su alsa bile, denizaltı batmasın diye! Ağını da tıpkı bir denizaltı gibi tasarlayacaksın. Bir uç nokta ele geçirilirse saldırgan sadece o küçük kompartımanda hapsolmalı; komşu sunucunun varlığından dahi haberdar olamamalıdır. Mikro-segmentasyon, siber fırtınalarda gemiyi yüzdüren çelik perdedir."
