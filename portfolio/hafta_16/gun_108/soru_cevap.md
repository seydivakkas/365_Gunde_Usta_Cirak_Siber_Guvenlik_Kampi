# Gün 108: X.509 ve Sertifika Zinciri — Soru ve Cevaplar
## Usta-Çırak Derin Teknik Mülakat ve Güvenlik Analizi

---

### Soru 1: X.509 Temel Kısıtlamalar (Basic Constraints) Uzantısı Nedir ve "Uç Sertifikanın Yetkisiz CA Olarak Davranması" Zafiyeti (CWE-295) Nasıl Önlenir?

#### 1. Soru Başlığı ve Tanımı
Bir X.509 sertifikasında `Basic Constraints` uzantısının bulunmaması veya istemci yazılımı tarafından denetlenmemesi neden tüm internet PKI güvenliğini yerle bir eden bir güvenlik zafiyetidir (CWE-295)? Normal bir web sitesi sertifikasına sahip bir saldırgan bu eksikliği istismar ederek nasıl sahte bir ara otoriteye (Rogue CA) dönüşebilir?

#### 2. Derinlemesine Teknik Analiz
RFC 5280 Section 4.2.1.9 standardına göre `Basic Constraints` uzantısı iki kritik parametre tanımlar:
1. `cA: BOOLEAN`: Sertifikanın bir Sertifika Otoritesi (CA) olup olmadığını belirler.
2. `pathLenConstraint: INTEGER (İsteğe bağlı)`: Bu CA'nın altında kurulabilecek maksimum ara CA zinciri derinliğini sınırlar.

Eğer bir TLS doğrulayıcı kütüphane sertifika zincirini incelerken yalnızca imza matematiksel doğrulamasına bakar ve `cA: TRUE` kontrolünü ihmal ederse:
- Saldırgan, meşru bir genel CA'den (örneğin Let's Encrypt veya DigiCert) kendi alan adı için yasal bir uç sertifika alır (`attacker.com`).
- Bu sertifikanın `is_ca` değeri `FALSE` olarak üretilmiştir ve sadece web trafiğini şifrelemek içindir.
- Ancak saldırgan kendi sunucusunda `attacker.com`'un gizli özel anahtarını kullanarak `login.microsoft.com` veya `banka.com` adına yeni bir sertifika üretir ve imzalar.
- İstemciye şu zinciri sunar:
  $$\text{Kök CA} \xrightarrow{\text{İmzalar}} \text{attacker.com (Uç)} \xrightarrow{\text{İmzalar}} \text{login.microsoft.com}$$
- İstemci sadece "İmzalar geçerli mi?" diye baktığında; Kök CA'nın genel anahtarı `attacker.com` imzasını doğrular, `attacker.com`'un genel anahtarı da `login.microsoft.com` imzasını doğrular!
- İstemci `Basic Constraints` denetimi yapmıyorsa, `attacker.com`'u geçerli bir Sertifika Otoritesi sanarak sahte Microsoft/Banka sertifikasını onaylar ve kullanıcı tüm şifrelerini saldırgana kaptırır.

**Savunma Mekanizması:**
RFC 5280 gereğince, zincirde uç sertifika (Leaf) dışındaki TÜM sertifikaların:
1. `basic_constraints.is_ca == True` olduğu,
2. `key_usage` içinde `keyCertSign` bayrağının bulunduğu,
3. Varsa `pathLenConstraint` sınırının aşılmadığı
kesinlikle doğrulanmalıdır. En ufak ihlalde `NonCACertificateUsedAsCAError` fırlatılmalıdır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo (2002 Moxie Marlinspike & Internet Explorer Açığı):** 2002 yılında Moxie Marlinspike, Microsoft Internet Explorer ve CryptoAPI kütüphanesinde `BasicConstraints` denetiminin yapılmadığını keşfetti. 10 dolara herhangi bir alan adına SSL sertifikası alan bir saldırgan, yerel ağdaki herkese istediği herhangi bir sitenin (VeriSign köküne bağlı gibi görünen) sahte sertifikasını sunabiliyor ve IE hiçbir uyarı vermeden yeşil kilit gösteriyordu.

**Pratik Çözüm:**
Zincir doğrulayıcı kod tabanında veren makamın CA yetkisi katı biçimde denetlenir:
```python
if not issuer_cert.basic_constraints.is_ca:
    raise NonCACertificateUsedAsCAError(
        f"CWE-295: '{issuer_cert.subject.common_name}' is_ca=False olmasına rağmen sertifika imzalamıştır!"
    )
if "keyCertSign" not in issuer_cert.key_usage:
    raise X509SecurityError("İmzayı atan sertifikada keyCertSign yetkisi bulunmuyor!")
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, bir sertifikanın üzerinde geçerli bir imza olması, onun başkalarına kimlik kartı dağıtabileceği anlamına gelmez. Bir vatandaşın pasaportundaki devlet mührü gerçektir diye o vatandaşın başkalarına pasaport basmasına izin veremezsin! İmzayı atanın 'Mühür Basma Yetkisi' (is_ca=True) olup olmadığını denetlemeden hiçbir zincire güvenme!"

---

### Soru 2: RFC 5280 Sertifika Yol Doğrulama (Path Validation) Algoritması Nasıl Çalışır ve "Güven Dayanağı" (Trust Anchor) Neden Zorunludur?

#### 1. Soru Başlığı ve Tanımı
Bir TLS istemcisi sunucudan aldığı sertifika zincirini Kök Otoriteye kadar doğrularken hangi adımları izler? "Güven Dayanağı" (Trust Anchor / Root Store) nedir ve istemcide yerel olarak bulunmayan bir kök sertifika neden asla doğrudan internetten indirilip güvenilmemelidir (CWE-295)?

#### 2. Derinlemesine Teknik Analiz
RFC 5280 standardında tanımlanan Sertifika Yol Doğrulama (Certification Path Validation) algoritması, bir uç sertifikadan başlayarak önceden güvenilen bir köke kadar giden yönlü bir güven grafiği (DAG) kurar.
Doğrulama adımları şu katı sırayı takip eder:

1. **Başlangıç:** İstemci sunucudan gelen uç sertifikayı ($C_0$) ve ara sertifikaları ($C_1, \dots, C_n$) alır.
2. **Süre Denetimi (Validity Period - CWE-298):** Zincirdeki her $C_i$ sertifikası için:
   $$\text{NotBefore} \le T_{\text{current}} \le \text{NotAfter}$$
   şartı kontrol edilir. Süresi geçmiş veya tarihi henüz gelmemiş sertifikalar zinciri derhal kırar.
3. **İsim ve İmza Zincirleme (Name & Signature Chaining):**
   Her $C_i$ sertifikasının `Issuer DN` alanı, bir üstteki $C_{i+1}$ sertifikasının `Subject DN` alanı ile eşleşmelidir. Ardından $C_i$'nin imzası, $C_{i+1}$'in genel anahtarıyla (`SPKI`) doğrulanır.
4. **Kısıtlama ve Politika Kontrolleri:**
   $C_{i+1}$ sertifikasının `is_ca == True`, `keyUsage` içinde `keyCertSign` bulunduğu ve zincir derinliğinin `pathLenConstraint` sınırını aşmadığı teyit edilir.
5. **İptal Listesi Denetimi (Revocation - CRL / OCSP):**
   Zincirdeki hiçbir sertifikanın seri numarası güncel iptal listesinde yer almamalıdır.
6. **Güven Dayanağı (Trust Anchor / Root Store):**
   Zincirin en tepesindeki kendinden imzalı Kök CA ($C_n$), istemcinin işletim sistemi veya tarayıcı deposunda (Windows Certificate Store, Mozilla NSS, macOS Keychain) **önceden tanımlı ve güvenilir** olarak yer almalıdır.

**Neden Kök CA İnternetten İndirilemez?**
Eğer istemci, sunucunun gönderdiği veya internetten dinamik indirdiği bir kök sertifikayı "imzası geçerli ve kendinden imzalı" diye doğrudan güvenilir kabul ederse, herhangi bir saldırgan `Attacker Root CA` üretip kendi kökünü sisteme dayatabilir. Bu durum PKI'ın tüm varlık amacını ortadan kaldırır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir mobil bankacılık uygulamasında TLS kütüphanesi yazılırken geliştirici `TrustAllCertificatesCallback` veya `verify_mode = CERT_NONE` yazmış ya da sunucudan gelen kök sertifikayı anlık olarak güven deposuna eklemiştir. Havalimanı Wi-Fi ağındaki saldırgan araya girerek (MITM) kendi ürettiği sahte kök sertifikayı sunar. Uygulama sahte kökü onaylar ve müşterinin tüm hesap hareketleri ve parolaları saldırganın eline geçer.

**Pratik Çözüm:**
Uygulama yalnızca işletim sisteminin güvenilen sertifika deposunu (`trust_store`) kullanmalı ve kritik uygulamalarda **Sertifika Sabitleme (Certificate Pinning / HPKP mantığı)** uygulanmalıdır:
```python
# Yalnızca trust_store içinde var olan kökler zinciri tamamlayabilir
is_trusted = any(root.matches(current_cert) for root in trust_store)
if not is_trusted:
    raise UntrustedRootCAError("Kök sertifika yerel trust store'da bulunamadı!")
```

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, zincir ne kadar sağlam olursa olsun, onu bağladığın kanca çürükse tüm köprü nehre dökülür. Trust Anchor senin sağlam kancandır. İstemcinin yerel hafızasında olmayan hiçbir yabancı köke güvenme; internetten gelen kök sertifika, kapına gelen yabancının sana kendi kimliğini teyit etmesi gibidir!"

---

### Soru 3: Alan Adı Doğrulama (RFC 6125 - Hostname Verification) Neden Hayatidir ve CN yerine SAN Kullanımı Neden Zorunlu Hale Gelmiştir?

#### 1. Soru Başlığı ve Tanımı
Bir TLS sertifikasının güvenilir bir CA tarafından imzalanmış olması neden tek başına yeterli değildir? Alan adı uyuşmazlığı (Hostname Mismatch - CWE-297) nasıl bir Ortadaki Adam (MITM) saldırısı doğurur ve modern standartlar neden `Common Name (CN)` yerine `Subject Alternative Name (SAN)` kullanımını şart koşmaktadır?

#### 2. Derinlemesine Teknik Analiz
Bir saldırgan meşru bir Sertifika Otoritesine başvurarak sahibi olduğu `zararli-site.com` için tamamen yasal, geçerli bir SSL/TLS sertifikası alabilir. Kök CA imzası kusursuzdur, süre geçerlidir, iptal edilmemiştir.
Eğer bir istemci kullanıcıyı `https://banka.com.tr` adresine bağlarken sunucunun sunduğu sertifikada sadece "CA imzası geçerli mi?" diye bakar ve alan adını denetlemezse:
1. Saldırgan DNS zehirlemesi (DNS Spoofing) veya sahte Wi-Fi ile kurbanın `banka.com.tr` trafiğini kendi IP adresine yönlendirir.
2. Saldırgan kurbana kendi yasal `zararli-site.com` sertifikasını sunar.
3. İstemci CA imzasını geçerli bulup bağlantıyı kurarsa, kurban bankaya bağlandığını sanırken tüm verilerini saldırgana aktarır (CWE-297).

**RFC 6125 Alan Adı Doğrulama Kuralları:**
İstemci URL'de yazan alan adı ile sertifikadaki kimliği eşleştirmek ZORUNDADIR:
- **Tarihsel CN Zafiyeti:** Eski X.509 v1/v2 sertifikalarında alan adı `Subject: CN=domain.com` içine yazılırdı. Ancak CN alanı tek bir string'dir, birden fazla alan adını desteklemez ve e-posta, şirket adı gibi serbest metinlerle karışmaya müsaittir.
- **Modern SAN (Subject Alternative Name) Zorunluluğu:** RFC 5280 ve CA/Browser Forum kuralları gereğince, tüm alan adları `extensions.subject_alt_names` (dNSName) içinde yer almalıdır. Tarayıcılar (Chrome, Firefox, Safari) CN alanını artık tamamen göz ardı etmekte, yalnızca SAN listesine bakmaktadır.

**Joker (Wildcard) Eşleme Mantığı:**
`*.bank.com.tr` jokeri, yalnızca **tek seviyeli** alt alan adlarıyla eşleşir (`login.bank.com.tr`, `api.bank.com.tr`).
Asla şu durumlarda geçerli kabul edilemez:
- Çok seviyeli alt alan adları: `sub.login.bank.com.tr` (Reddedilir).
- Ana alan adı: `bank.com.tr` (SAN'da ayrıca listelenmemişse reddedilir).
- En üst düzey alan adları (TLD): `*.com` veya `*.com.tr` (Tüm interneti ele geçirmeyi önlemek için kesinlikle yasaktır).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir mikroservis mimarisinde arka uç servisleri birbirleriyle HTTPS üzerinden haberleşmektedir. Python `urllib` veya ilkel bir soket istemcisi kullanan yazılımcı `check_hostname = False` parametresi bırakmıştır. Ağdaki saldırgan ARP zehirlemesi yaparak ödeme servisi trafiğini kendi sunucusuna çeker ve kendi geçerli şirket sertifikasını sunarak tüm kredi kartı transferlerini kaydeder.

**Pratik Çözüm:**
Motor düzeyinde RFC 6125 uyumlu tam SAN eşleşmesi ve joker denetimi uygulanır:
```python
if not leaf.matches_hostname(target_domain):
    raise HostnameMismatchError(
        f"CWE-297: Sertifika hedef alan adı ('{target_domain}') ile uyuşmuyor!"
    )
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, elindeki kimlik kartı devletin en hakiki mührünü taşısa bile, üzerinde senin fotoğrafın ve adın yazmıyorsa o kartla bankadan para çekemezsin. Sertifikanın kime verildiği (SAN), en az onu kimin imzaladığı kadar hayatidir. Alan adını kontrol etmeyen şifreleme, kapıyı kilitleyip anahtarı paspasın altına bırakmaktan farksızdır!"
