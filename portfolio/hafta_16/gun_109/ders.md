# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 109: PKI ve Sertifika Yaşam Döngüsü (Certificate Lifecycle Management)

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, dün seninle X.509 sertifika zincirini, Root CA’dan Leaf sertifikaya kadar olan hiyerarşik güven patikasını ilmek ilmek dokuduk. Fakat sahadaki acemi mühendislerin en büyük yanılgısı şudur: Bir sertifikayı CA'den satın alıp sunucuya bağladıklarında işin bittiğini zannederler. Oysa sertifika statik bir dosya değil; doğan, yaşayan, yaşlanan, hastalanan (çalınan/sızan), emekliye ayrılan ve sonunda güvenle yok edilmesi gereken dinamik bir organizmadır! 

**Çırak:** Hocam, "hastalanan sertifika" derken neyi kastediyorsunuz? Sertifika dediğimiz şey matematiksel bir veri yapısı değil mi? Nasıl hastalanır ya da ölür?

**Usta:** Özel anahtarı (private key) yetkisiz bir göz gördüğü veya diski yedekleyen sistem yöneticisi o anahtarı açık bir S3 bucket'ına unuttuğu an, o sertifika ölümcül bir virüs kapmıştır! O anahtara sahip olan bir saldırgan, senin tüm kullanıcı trafiğini Man-in-the-Middle (MitM) ile dinleyebilir ve sahte portallarla oturum çalabilir. İşte bu yüzden bir güvenlik mühendisi için **Sertifika Yaşam Döngüsü Yönetimi (Certificate Lifecycle Management - CLM)**, kriptografik formüller kadar hayati bir operasyonel disiplindir. Bugün bir anahtarın doğumundan (KeyGen/CSR) ölümüne (Revocation/Crypto-Shredding) kadar her aşamasını ameliyat masasına yatıracağız.

---

## 1. Faz: Doğum — Asimetrik Anahtar Üretimi ve CSR (PKCS#10 / RFC 2986)

### 1.1 Kriptografik Olarak Güvenli Anahtar Üretimi
Yaşam döngüsü, sunucunun yerel ortamında (asla üçüncü bir tarafın sunucusunda değil!) asimetrik bir anahtar çifti (RSA veya ECC) üretmesiyle başlar.
- **Rastgelelik İlkesi:** Anahtar üretilirken kullanılan entropi kaynağı işletim sisteminin kriptografik rastgele sayı üreticisi (CSPRNG - Linux'ta `getrandom(2)` / `/dev/urandom`, Windows'ta `BCryptGenRandom`) olmalıdır. Yetersiz entropi, RSA asal sayılarının tahmin edilmesine (CWE-330) yol açar.
- **Özel Anahtar Yalıtımı:** Üretilen özel anahtar asla sunucu dışına çıkmaz. Dosya izinleri en kısıtlı seviyede (`chmod 0600` veya Windows ACL SYSTEM/Administrators Only) tutulmalıdır (CWE-311).

### 1.2 CSR (Certificate Signing Request) Mimarisi ve Mülkiyet İspatı (Proof-of-Possession)
İstemci, Sertifika Otoritesi'ne (CA) özel anahtarını göndermez. Sadece genel anahtarını, kimlik bilgilerini (Subject DN: CN, O, C) ve alan adlarını (SAN) içeren bir **PKCS#10 (RFC 2986)** Sertifika İmza Talebi (CSR) hazırlar.

$$\text{CSR} = \{\text{Subject DN}, \text{SAN}, \text{Public Key}, \text{Attributes}\}$$

Burada en kritik güvenlik adımı **Proof-of-Possession (PoP / Mülkiyet İspatı)** mekanizmasıdır:
1. Başvuru sahibi, CSR gövdesinin özetini (SHA-256) alır.
2. Bu özeti **kendi özel anahtarıyla** imzalar:
   $$\text{Signature}_{\text{CSR}} = \text{Sign}_{K_{\text{private}}}(\text{Hash}(\text{CSR}_{\text{body}}))$$
3. CA, CSR'yi aldığında içindeki `Public Key` ile bu imzayı doğrular (CWE-347 Koruması).
4. Eğer imza doğrulanamazsa, başvuran varlığın beyan ettiği genel anahtarın özel bileşenine sahip olmadığı anlaşılır ve talep derhal çöpe atılır! Aksi takdirde bir saldırgan, başkasının genel anahtarını kendi adına tescil ettirmeye çalışabilirdi.

---

## 2. Faz: İhraç ve Şeffaflık — CA Doğrulaması ve Certificate Transparency (RFC 6962)

### 2.1 Kayıt Otoritesi (RA) ve Alan Adı Sahiplik Doğrulaması
CA'in arkasındaki Kayıt Otoritesi (Registration Authority - RA), talebin meşruiyetini teyit etmek zorundadır:
- **DV (Domain Validation):** Başvuru sahibinin alan adına hükmettiği teyit edilir (DNS TXT kaydı veya HTTP doğrulama dosyası).
- **OV (Organization Validation):** Kurumun resmi ticaret sicil kayıtları, fiziksel varlığı ve telefon teyidi incelenir.
- **EV (Extended Validation):** En katı yasal ve idari denetim protokolleri uygulanır.

### 2.2 Certificate Transparency (CT Log / RFC 6962) ve SCT
Eskiden güvenilir bir CA ele geçirildiğinde (2011 DigiNotar vakasında olduğu gibi), saldırganlar gizlice Google, Yahoo gibi alan adları adına sahte sertifikalar basıp aylarca tespit edilmeden trafiği dinleyebiliyordu.

Google ve IETF bu karanlık noktayı ortadan kaldırmak için **Certificate Transparency (CT Log - RFC 6962)** standardını getirdi:
1. Bir CA, internete açık bir TLS sertifikası ihraç etmeden önce bunu halka açık, ekleme-yapılabilir (append-only) kriptografik **Merkle Ağacı (Merkle Tree)** denetim günlüklerine (CT Log) kaydettirmek zorundadır.
2. CT günlüğü sertifikayı sıraya aldığında bir **Signed Certificate Timestamp (SCT)** üretir ve CA'e döner.
3. CA, bu SCT zaman damgasını sertifikanın X.509 uzantıları arasına gömer.
4. Modern tarayıcılar (Chrome, Safari, Firefox), sunulan sertifikada geçerli en az iki bağımsız SCT kanıtı görmezse bağlantıyı **"Certificate Transparency Required"** hatasıyla engeller!
5. Bu sayede bir kurum, alan adı adına dünyanın herhangi bir yerinde izinsiz sertifika basıldığını saniyeler içinde CT Log izleyicileri üzerinden tespit edebilir.

---

## 3. Faz: İşletim ve İptal Yönetimi — CRL, OCSP ve OCSP Stapling

Bir sertifika ihraç edildikten sonra en kritik operasyonel süreç, o sertifikanın yetkisinin iptal edilmesidir (Revocation). İptal nedenleri (RFC 5280):
- `keyCompromise` (Özel anahtar sızdı/çalındı)
- `superseded` (Sertifika yenilendi, eskisi geçersiz)
- `affiliationChanged` (Kurum adı veya alan adı devredildi)
- `cessationOfOperation` (Sunucu kalıcı olarak kapatıldı)

| Mekanizma | Standart | Çalışma Prensibi | Avantajları | Zafiyetler ve Riskler |
| :--- | :--- | :--- | :--- | :--- |
| **CRL** | RFC 5280 | CA periyodik olarak iptal edilen seri numaralarını imzalı bir dosya olarak yayınlar. | Basit, çevrimdışı doğrulanabilir. | Dosya boyutu megabaytları bulabilir; güncelleme aralıkları uzundur (24-48 saat gecikme). |
| **OCSP** | RFC 6960 | İstemci her TLS bağlantısında CA'in OCSP sunucusuna sertifika seri numarasını sorar. | Gerçek zamanlı iptal bilgisi; hafif veri paketi. | Her bağlantıda CA'e DNS/HTTP sorgusu gider (Gizlilik sızıntısı & El sıkışma gecikmesi). Replay saldırısı riski (CWE-294). |
| **OCSP Stapling** | RFC 6066 | Sunucu kendi sertifikasının OCSP yanıtını CA'den periyodik alır, el sıkışmada istemciye sunar. | Sıfır ilave gecikme; istemci gizliliği tam korunur; CA çökse bile sunucu çalışır. | Sunucu tarafında stapling önbellekleme desteği ve yapılandırma gerektirir. |

### 3.1 CWE-294: OCSP Replay Saldırısı ve Nonce Koruması
Kötü niyetli bir saldırgan, daha önce yakaladığı "GOOD" (geçerli) durumundaki eski bir OCSP yanıtını saklayabilir. Sertifika sonradan çalınıp iptal edildiğinde (`REVOKED`), istemcinin OCSP sorgusunu araya girerek (MitM) engelleyip eski "GOOD" yanıtını geri döndürebilir!
- **Savunma:** İstemci, OCSP isteğine kriptografik olarak rastgele bir **Nonce** (kullan-at değer) eklemelidir. Yanıtlayıcı CA, bu nonce değerini imzalı yanıt gövdesine aynen ekler. İstemci, yanıttaki nonce ile istekteki nonce birebir eşleşmiyorsa yanıtı **CWE-294** ihlali gerekçesiyle reddeder.

### 3.2 CWE-299 / CWE-295: Fail-Open vs Fail-Closed İkilemi
Bir istemci OCSP sunucusuna veya CRL dağıtım noktasına ağ kesintisi/DDoS nedeniyle erişemezse ne yapmalıdır?
- **Fail-Open (Kullanıcı Odaklı):** "Hata aldım ama sertifika muhtemelen geçerlidir" diyerek bağlantıya izin verir. Zafiyet: Saldırgan OCSP sunucusuna giden trafiği düşürerek iptal denetimini tamamen baypas eder (Soft-Fail felaketi).
- **Fail-Closed (Güvenlik Odaklı):** "İptal durumunu kesin olarak teyit edemiyorsam bağlantıyı derhal sonlandırırım" der. Yüksek güvenlikli bankacılık ve savunma sistemlerinde zorunludur.

---

## 4. Faz: Yenileme, Otomatik Rotasyon ve Kriptografik İmha (ACME & Crypto-Shredding)

### 4.1 ACME Protokolü (RFC 8555 / Let's Encrypt Mimarisi)
Manuel sertifika yönetimi, unutulan süre bitimleri nedeniyle tarihteki en büyük hizmet kesintilerine (Teams, Spotify, Ericsson baz istasyonları) yol açmıştır.
ACME (Automated Certificate Management Environment), sertifika talebi, challenge doğrulaması ve yenileme süreçlerini tamamen otomatikleştirir:
1. **HTTP-01 Challenge:** CA istemciye bir token verir. İstemci bu tokenı web sunucusunun `/.well-known/acme-challenge/<token>` adresine koyar. CA gelip HTTP ile doğrular.
2. **DNS-01 Challenge:** İstemci DNS sunucusuna `_acme-challenge.domain.com` TXT kaydı ekler. Wildcard sertifikalar için zorunludur.
3. Otomasyon ajanı, sertifikanın bitimine 30 gün kala yeni CSR üretir, doğrulamayı tamamlar ve web sunucusunu kesintisiz (graceful reload) olarak yeni sertifikaya geçirir.

### 4.2 Kriptografik İmha (Crypto-Shredding / CWE-311 Savunması)
Bir sertifika yenilendiğinde veya iptal edildiğinde, eski özel anahtar öylece diskte veya yedeklerde bırakılamaz! Gelecekte eski anahtar ele geçirilirse, Perfect Forward Secrecy (PFS) kullanılmayan eski şifreli oturumlar çözülebilir (Harvest Now, Decrypt Later).
- **Crypto-Shredding Kuralı:** Emekliye ayrılan özel anahtarın bulunduğu bellek blokları ve disk sektörleri, üzerine kriptografik olarak rastgele baytlar yazılarak (`0x00`, `0xFF` ve `CSPRNG bytes`) fiziksel olarak imha edilmeli, ardından dosya silinmelidir.

---

## Ustanın Çırağa Öğüdü
Evlat, sertifika yönetimi bir yazılım geliştirmekten çok, bir bahçeye bakmaya benzer. Bir gün ilgilenmezsen yabani otlar sarmaz ama süresi dolan tek bir sertifika tüm holdingin sistemlerini felç eder. 
1. Asla süresi dolana kadar bekleme; otomasyonu 30 gün öncesine ayarla.
2. Özel anahtarını asla e-posta, Slack veya Git reposuna sokma.
3. İptal denetiminde OCSP Stapling'i zorunlu kıl ve fail-closed politikasıyla sistemini sahte sertifikalara karşı çelik bir kalkanla donat!
