# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 109: PKI ve Sertifika Yaşam Döngüsü — Soru ve Cevaplar

---

## Soru 1: CSR Mimarisi ve Proof-of-Possession (Mülkiyet İspatı) Güvenliği

### 1. Soru Başlığı ve Tanımı
PKCS#10 (RFC 2986) standardında Sertifika İmza Talebi (CSR) nedir ve içerisindeki "Proof-of-Possession (PoP / Mülkiyet İspatı)" mekanizması nasıl çalışır? Bir Sertifika Otoritesi (CA), gelen CSR'deki mülkiyet ispatı imzasını doğrulamayı atlarsa (CWE-347) ne tür kimlik sahteciliği ve yetkisiz sertifika edinme saldırıları meydana gelir?

### 2. Derinlemesine Teknik Analiz
PKCS#10 (RFC 2986), bir istemcinin Sertifika Otoritesi'nden (CA) dijital sertifika talep etmek için hazırladığı standart veri yapısıdır. Bir CSR üç ana bileşenden oluşur:
1. **CertificationRequestInfo (Kanonik Gövde):** Başvuru sahibinin kimlik bilgileri (Subject DN: CN, O, C vb.), genel anahtarı (`SubjectPublicKeyInfo`) ve opsiyonel öznitelikler (talep edilen SAN uzantıları).
2. **SignatureAlgorithmIdentifier:** Kullanılan özet ve imza algoritması (örn. `sha256WithRSAEncryption`).
3. **Signature (Dijital İmza):** CertificationRequestInfo bloğunun SHA-256 özetinin, **başvuru sahibinin özel anahtarı** ile imzalanmış hali.

Buradaki imza, kriptografide **Proof-of-Possession (PoP)** olarak adlandırılır. Amacı şudur: Başvuru sahibi CA'e der ki: *"Ben bu genel anahtarın (`public key`) bana verilmesini istiyorum ve sana ispat ediyorum ki bu genel anahtarın eşi olan gizli özel anahtara (`private key`) bizzat sahibim."*

CA, CSR'yi aldığında şu adımları izlemekle yükümlüdür:
$$\text{Verify}(\text{PublicKey}_{\text{CSR}}, \text{Hash}(\text{CSR}_{\text{body}}), \text{Signature}_{\text{CSR}}) \stackrel{?}{=} \text{TRUE}$$

**CWE-347 Zafiyeti (PoP Atlanması Durumu):**
Eğer CA yazılımında bir mantık hatası varsa ve CSR imzasını doğrulamadan sadece içindeki genel anahtarı alıp doğrudan sertifika basarsa felaket başlar:
- **Genel Anahtar Gaspı (Public Key Theft):** Saldırgan, meşru bir bankanın veya devlet kurumunun kamuya açık TLS genel anahtarını alır. Kendi kimlik bilgileriyle (`Subject: CN=saldirgan-site.com`) bir CSR hazırlar. Ancak özel anahtara sahip olmadığı için rastgele çöp baytlarla sahte bir imza atar.
- **İtibar Çalma ve İtiraz Edilemezliğin Çöküşü:** CA bu sahte CSR'ı onaylarsa, bankanın genel anahtarına bağlı saldırgan adına basılmış yasal bir sertifika oluşur. Saldırgan, bankanın işlemlerine kendi adına atıfta bulunabilir ya da bankayı kendi yasadışı eylemlerinin kaynağı gibi gösterebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir PKI portalı geliştiren yazılım ekibi, ACME API entegrasyonu sırasında performans optimizasyonu gerekçesiyle CSR ayrıştırıcısındaki imza kontrolünü devre dışı bırakmıştır. İç ağdaki sızma testinde kırmızı takım uzmanı, şirket CEO'sunun e-imza genel anahtarını alıp kendi kullanıcı adı adına bir kod imzalama sertifikası talep etmiş ve CA bu sertifikayı sorgusuz basmıştır.

**Pratik Çözüm:**
CA çekirdeğinde CSR işleme fonksiyonuna tavizsiz bir PoP kontrolü entegre edilmelidir:
```python
def validate_and_process_csr(csr_bytes: bytes, ca_engine) -> X509Certificate:
    csr = CertificateSigningRequest.parse(csr_bytes)
    # 1. Adım: CWE-347 Koruması - Proof-of-Possession doğrulaması
    digest = hashlib.sha256(csr.to_canonical_bytes()).digest()
    if not RSAKeyPair.verify_signature(csr.public_key, digest, csr.signature):
        raise CSRSignatureVerificationError("CWE-347: CSR mülkiyet ispatı (PoP) geçersiz!")
    # 2. Adım: Sertifika üretimine devam et
    return ca_engine.issue_certificate(csr)
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir kapı çaldığında sana başkasının nüfus cüzdanını gösteren adama anahtar teslim edemezsin; elindeki mührü basarak o cüzdanın gerçek sahibi olduğunu kendi huzurunda kanıtlamasını isteyeceksin. CSR'deki Proof-of-Possession işte bu mühürdür. CA kodlarken veya PKI mimarisi çizerken "nasılsa genel anahtarı veriyor, imzasına ne gerek var" diyen her geliştiriciyi uyar; PoP doğrulaması olmayan bir CA, sahtekarlara açık çek dağıtan batık bir banka gibidir.

---

## Soru 2: Sertifika İptal Mekanizmaları: CRL vs OCSP vs OCSP Stapling

### 1. Soru Başlığı ve Tanımı
X.509 sertifika ekosisteminde sertifika iptali (Revocation) için kullanılan CRL (RFC 5280) ve OCSP (RFC 6960) mekanizmalarının mimari farkları ve zafiyetleri nelerdir? OCSP Replay (CWE-294), istemci gizliliği sızıntısı ve bağlantı gecikmesi problemleri **OCSP Stapling (RFC 6066)** ile nasıl bertaraf edilir?

### 2. Derinlemesine Teknik Analiz
Bir sertifikanın özel anahtarı çalındığında, süresi dolmamış olsa bile acilen geçersiz kılınması gerekir. Tarihsel olarak iki temel yöntem gelişmiştir:

1. **Sertifika İptal Listesi (CRL - RFC 5280):**
   - CA, iptal edilen tüm sertifikaların seri numaralarını, iptal tarihlerini ve nedenlerini bir liste halinde toplar, listeyi kendi özel anahtarıyla imzalar ve HTTP/LDAP üzerinden yayınlar.
   - **Sorun:** CRL dosyaları yüzlerce megabayta ulaşabilir. İstemciler her bağlantıda tüm listeyi indiremez, bu yüzden saatler veya günler süren önbellekler kullanılır. Bu gecikme süresinde çalınan anahtarlar özgürce kullanılabilir.

2. **Çevrimiçi Sertifika Durum Protokolü (OCSP - RFC 6960):**
   - İstemci, bağlanmak istediği sertifikanın seri numarasını CA'in OCSP Responder servisine gerçek zamanlı sorar.
   - Yanıt: `GOOD`, `REVOKED` veya `UNKNOWN`.
   - **Zafiyet 1 (CWE-294 - Replay Saldırısı):** OCSP yanıtları imzalıdır ancak geçerlilik süresi (örn. 24 saat) içerir. Bir saldırgan, sertifika iptal edilmeden önce CA'den aldığı "GOOD" yanıtını saklar. Sertifika iptal edildikten sonra istemcinin OCSP sorgusunu MitM ile engelleyip eski "GOOD" yanıtını döndürür. Savunma: İstemcinin sorguya eklediği rastgele `Nonce` değerinin yanıtta birebir eşleşmesini zorunlu kılmaktır.
   - **Zafiyet 2 (Gizlilik Sızıntısı):** İstemci her web sitesine girdiğinde, o sitenin sertifikasını CA'in OCSP sunucusuna sorar. Bu durum CA operatörünün hangi IP adresinin hangi web sitesini ne zaman ziyaret ettiğini (gezinme geçmişini) görmesine yol açar!
   - **Zafiyet 3 (Gecikme ve Çökme Riski):** Her TLS bağlantısından önce harici bir OCSP sunucusuna HTTP isteği atmak TLS el sıkışmasını 200-500 ms yavaşlatır. CA'in OCSP sunucusu çökerse dünya genelinde sitelere erişim durur (veya tehlikeli fail-open moduna geçilir).

3. **Modern Çözüm: OCSP Stapling (RFC 6066 / RFC 6961):**
   - Yük istemcinin sırtından alınır, web sunucusuna verilir.
   - Web sunucusu, arka planda periyodik olarak (örn. saatte bir) CA'in OCSP sunucusuna gider, kendi sertifikasının güncel ve imzalı OCSP yanıtını alır ve önbelleğinde saklar.
   - İstemci web sitesine bağlandığında, web sunucusu TLS Handshake paketinin (`CertificateStatus`) içine bu imzalı OCSP yanıtını "zımbalar" (staple).
   - **Kazanımlar:** İstemci harici hiçbir sunucuya bağlanmaz (sıfır gecikme), istemcinin ziyaret ettiği site CA'e sızmaz (tam gizlilik), CA çökse bile sunucudaki önbellekli yanıt el sıkışmasını ayakta tutar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret platformunda Black Friday indirimlerinde kullanıcıların ödeme sayfasına girişi aniden kilitlenmiştir. Yapılan ağ analizinde, web sunucularının OCSP Stapling yapılandırmasının kapalı olduğu, milyonlarca kullanıcının tarayıcısının aynı anda CA'in OCSP sunucusuna yüklendiği ve CA yanıt veremeyince tarayıcıların "Zaman Aşımı" hatasıyla bağlantıyı kestiği görülmüştür.

**Pratik Çözüm (Nginx / Apache OCSP Stapling Yapılandırması):**
```nginx
# Nginx sunucusunda OCSP Stapling'i zorunlu ve güvenli hale getirme
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/chain_with_root.pem;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
```
Python tarafında istemci denetleyicisi:
```python
# Sunucudan gelen zımbalanmış OCSP yanıtını doğrula
is_valid = OCSPVerifier.verify_response(
    cert=server_cert,
    ocsp_response=stapled_ocsp_response,
    expected_nonce=None, # Stapled yanıtta nonce aranmaz, zaman damgası kontrol edilir
    policy="FAIL_CLOSED"
)
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, bir müşteriye hizmet verirken onu üçüncü bir tarafın kapısında bekletmek hem saygısızlıktır hem de operasyonel zaaftır. Bir TLS sunucusu ayağa kaldırıyorsan OCSP Stapling senin varsayılan refleksin olmalıdır. CA sunucusu internetin diğer ucunda uyuyakalabilir ama senin sunucun taze ve imzalı durum belgesini cebinde taşırsa hiçbir fırtına gemini batıramaz!

---

## Soru 3: ACME Protokolü ile Otomatik Yaşam Döngüsü ve Crypto-Shredding

### 1. Soru Başlığı ve Tanımı
RFC 8555 standardındaki ACME (Automated Certificate Management Environment) protokolü sertifika yaşam döngüsünü nasıl sıfır dokunuşla (Zero-Touch) otomatikleştirir? Sertifika rotasyonu tamamlandıktan sonra eski özel anahtarın "Crypto-Shredding" yöntemiyle imha edilmesinin ileriye dönük gizlilik (Forward Secrecy) ve adli bilişim açısından önemi nedir?

### 2. Derinlemesine Teknik Analiz
Geçmişte sertifika yönetimi elle yürütülürdü: Sistem yöneticisi takvimine not alır, yılda bir CSR üretir, CA portalına yükler, ödeme yapar, indirir ve sunucuya kopyalardı. Bu insan odaklı süreç, unutulan tek bir sertifika yüzünden Microsoft Teams'in 2020'de saatlerce çökmesine sebep oldu.

**ACME (RFC 8555) Otomasyon Mimarisi:**
1. **Hesap Oluşturma:** İstemci (örn. Certbot), ACME sunucusunda asimetrik bir hesap anahtarıyla hesap açar.
2. **Sipariş Verme (Order Creation):** İstemci, `example.com` için bir sertifika siparişi oluşturur.
3. **Challenge (Sınama) Türleri:**
   - **HTTP-01:** ACME sunucusu istemciye `http://example.com/.well-known/acme-challenge/<token>` adresinde belirli bir kriptografik yetkilendirme dizgisi yayınlamasını söyler. CA HTTP ile kontrol eder.
   - **DNS-01:** İstemci, DNS sağlayıcısının API'sini kullanarak `_acme-challenge.example.com` adresine TXT kaydı girer. Wildcard (`*.example.com`) sertifikalar için şarttır.
   - **TLS-ALPN-01:** 443 portu üzerinden özel bir TLS uzantısıyla doğrudan el sıkışma seviyesinde doğrulama yapılır.
4. **Finalize & Certificate Issuance:** Challenge onaylandığında istemci yerel olarak ürettiği yeni CSR'ı gönderir ve CA saniyeler içinde imzalı sertifikayı döner.
5. **Otomatik Yenileme Döngüsü:** Sertifikalar 90 günlük basılır ve her 60 günde bir (bitime 30 gün kala) arka plan servisi (cron/systemd timer) hiçbir insan müdahalesi olmadan bu döngüyü işletir.

**Kriptografik İmha (Crypto-Shredding / CWE-311 Savunması):**
Yeni sertifika devreye alındığında (Graceful Cutover), eski sertifika CA'e `superseded` (yenisiyle değiştirildi) gerekçesiyle bildirilir. Ancak en büyük tehdit eski özel anahtardır:
- **Harvest Now, Decrypt Later Riski:** Saldırganlar ağdaki şifreli trafiği terabaytlarca depolar. Yıllar sonra eski bir sunucu hurdaya çıktığında veya yedek diski ele geçirildiğinde, o eski özel anahtar ele geçerse (özellikle statik RSA anahtar değişimi kullanılan eski oturumlar) geçmişe dönük tüm sırlar çözülür.
- **Crypto-Shredding Uygulaması:** Özel anahtarın tutulduğu bellek adresleri ve disk blokları, işletim sisteminin `unlink` çağrısıyla silinmeden önce en az üç geçişli rastgele desenlerle (`0x00`, `0xFF`, CSPRNG rastgele bitleri) ezilmelidir:
  $$\text{DiskSector} \leftarrow \text{RandomBits}(512)$$
  Ardından dosya silinir ve bellek işaretçisi `None` yapılarak çöp toplayıcıya teslim edilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Büyük bir finans kuruluşu, 3 yıl önce yenilenen bir API sunucusunun eski özel anahtarını arşiv sunucusundaki sıkıştırılmış bir tar.gz dosyasında unutmuştur. Arşiv sunucusuna sızan bir APT grubu bu anahtarı ele geçirmiş ve son 3 yılda forward secrecy desteklemeyen eski kurumsal entegrasyonların geçmişe dönük kaydedilmiş tüm verilerini deşifre etmiştir.

**Pratik Çözüm:**
Otomatik rotasyon döngüsüne kriptografik imha (shredding) fonksiyonu zorunlu bir adım olarak eklenmelidir:
```python
def secure_crypto_shred_file(file_path: str) -> None:
    """Özel anahtar dosyasını diskte rastgele bitlerle ezerek yok eder."""
    if os.path.exists(file_path):
        length = os.path.getsize(file_path)
        with open(file_path, "wb") as f:
            # 1. Geçiş: Sıfırlar
            f.write(b"\x00" * length)
            f.flush()
            # 2. Geçiş: Birler
            f.seek(0)
            f.write(b"\xFF" * length)
            f.flush()
            # 3. Geçiş: CSPRNG Rastgele Baytları
            f.seek(0)
            f.write(secrets.token_bytes(length))
            f.flush()
        # Diski senkronize et ve dosyayı sil
        os.remove(file_path)
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! İyi bir hekim hastayı iyileştirdiği gibi, kullandığı tıbbi atığı da güvenle imha eder. Siber güvenlikte de yeni anahtarı devreye almak işin sadece yarısıdır; eski anahtarı geride çöp gibi bırakırsan o çöp gün gelir ayağına pranga olur. ACME gibi modern otomasyonları kullanırken asla anahtar biriktirme hastalığına kapılma; vadesi dolan anahtara merhamet etme, onu diskinde ve belleğinde atomlarına kadar parçala!
