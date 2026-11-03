# Gün 108: X.509 ve Sertifika Zinciri (Certificate Chain & PKI)
## Usta-Çırak / Hoca Dersi: X.509 v3 Anatomisi, RFC 5280 Yol Doğrulama ve BasicConstraints Güvenliği

---

### 1. Ustanın Giriş Dersi: "İnternette Kimin Kim Olduğunu Nereden Biliyoruz?"

Evlat, dünkü dersimizde dijital imzanın inkar edilemezlik sağladığını ve bir belgenin değiştirilmediğini kanıtladığını öğrendin. Ancak asimetrik kriptografinin en can alıcı sorusu hala masada duruyor:
> *"Bir genel anahtarın (`e, n`) gerçekten 'google.com' veya 'ziraatbank.com.tr'ye ait olduğunu nereden bileceğiz? Ya aradaki saldırgan kendi ürettiği genel anahtarı bize sunup 'Ben senin bankanım' diyorsa?"*

İşte bu kimlik doğrulama problemini çözen mimariye **Kamu Anahtarı Altyapısı (Public Key Infrastructure - PKI)** ve bu altyapının resmi kimlik kartına **X.509 Sayısal Sertifikası** denir.

Sertifika, bir kuruluşun kimlik bilgilerini (Alan adı, Şirket adı, Ülke) o kuruluşun **Genel Anahtarı** ile birbirine mühürleyen ve güvenilir bir **Sertifika Otoritesi (Certificate Authority - CA)** tarafından dijital olarak imzalanmış resmi bir belgedir.

---

### 2. Neden 3 Kademeli PKI Hiyerarşisi? (Kök CA Neden İnternete Bağlanmaz?)

Bir çırak şöyle düşünebilir:
> *"Usta, tek bir Kök CA olsa ve tüm web sitelerini doğrudan o imzalasaydı daha basit olmaz mıydı?"*

Bu ölümcül bir operasyonel hatadır!
Eğer dünyadaki milyarlarca web sitesini doğrudan Kök CA (Root CA) imzalarsa:
1. Kök CA'nın özel anahtarı (`d_root`) sürekli internete bağlı sunucularda aktif kalmak zorundadır.
2. Bu sunucuya yapılacak tek bir siber saldırı veya içeriden bir sızıntı durumunda Kök Anahtar çalınırsa, **tüm küresel internet çöker!**
3. Milyarlarca cihazın (Windows, iOS, Android, Linux) işletim sistemi depolarında yüklü olan kök sertifikayı değiştirmek aylar sürer.

Bu yüzden endüstride her zaman **3 Kademeli Hiyerarşi (Tiered Hierarchy)** uygulanır:

```
    [ KÖK SERTİFİKA OTORİTESİ (ROOT CA) ]
    * Çevrimdışı (Air-Gapped), yeraltı sığınaklarında HSM'de kilitlidir.
    * 10-25 yıllık geçerlilik süresi vardır.
    * Yılda sadece 1-2 kez özel protokollerle açılır ve yalnızca Ara CA imzalar.
                    │
                    ▼
    [ ARA SERTİFİKA OTORİTESİ (INTERMEDIATE CA) ]
    * İnternete bağlı, bulutta veya HSM'de çalışan operasyonel CA'dir.
    * 1-5 yıllık geçerliliği vardır.
    * Çalınırsa sadece bu ara sertifika iptal edilir (CRL/OCSP); Kök CA zarar görmez!
                    │
                    ▼
    [ UÇ SUNUCU SERTİFİKASI (LEAF / END-ENTITY) ]
    * Web sunucularında (Nginx, Apache, Envoy) çalışan sertifikadır.
    * 90 gün ile 1 yıl geçerlidir (Let's Encrypt / DigiCert).
    * Kesinlikle başka bir sertifika imzalama yetkisi YOKTUR (is_ca=False).
```

---

### 3. X.509 v3 Sertifika Anatomisi ve Kritik Alanlar

Bir X.509 v3 sertifikası temel olarak şu parçalardan oluşur:
1. **TBSCertificate (To-Be-Signed):** Sertifikanın imzalanacak tüm veri alanları.
   - `Serial Number`: CA tarafından verilen benzersiz tamsayı.
   - `Issuer DN`: Sertifikayı veren makam (`CN=DigiCert Global Root CA, O=DigiCert, C=US`).
   - `Validity`: `NotBefore` ve `NotAfter` tarihleri (Süresi dolan sertifika geçersizdir).
   - `Subject DN`: Sertifikanın sahibi (`CN=secure.bank.com.tr`).
   - `SubjectPublicKeyInfo`: Sahibin RSA/ECC genel anahtarı.
2. **Extensions (Uzantılar):** Güvenliğin kalbi buradadır!
   - **`BasicConstraints` (CWE-295):** `is_ca: BOOLEAN` ve `pathLenConstraint: INTEGER`. Bu alan bir sertifikanın başkalarını imzalama yetkisi olup olmadığını belirler.
   - **`KeyUsage`:** Anahtarın ne için kullanılabileceği (`digitalSignature`, `keyCertSign`, `cRLSign`).
   - **`SubjectAlternativeName` (SAN - RFC 6125):** Sertifikanın geçerli olduğu alan adları listesi (`["bank.com.tr", "api.bank.com.tr", "*.bank.com.tr"]`).
3. **SignatureValue:** TBS bloğunun veren CA'nın özel anahtarıyla imzalanmış PKCS#1 v1.5 / PSS özeti.

---

### 4. Ölümcül Hata: "BasicConstraints is_ca=False" İhmali (CWE-295)

Eski veya acemice yazılmış TLS istemcilerinin yaptığı en büyük hata, sadece imzanın doğruluğunu kontrol edip `BasicConstraints` uzantısını incelememektir.

**Saldırı Senaryosu:**
1. Saldırgan meşru bir CA'den kendi web sitesi için bir SSL sertifikası satın alır (`attacker.com`).
2. Saldırgan kendi sunucusundaki `attacker.com` sertifikasının özel anahtarını kullanarak `google.com` adına yeni bir sertifika üretir ve imzalar!
3. Kurbana bu sahte `google.com` sertifikasını ve aradaki `attacker.com` sertifikasını zincir olarak sunar.
4. İstemci sadece "İmzalar zincirleme tutuyor mu?" diye bakarsa; Kök CA `attacker.com`'u imzalamış, `attacker.com` da `google.com`'u imzalamış görünür!
5. **Savunma:** İstemci, bir sertifika başka bir sertifikayı imzalamışsa, imzalayanın `basic_constraints.is_ca == True` olduğunu ve `keyUsage` içinde `keyCertSign` bulunduğunu kontrol etmek ZORUNDADIR! Uç sertifikanın (`is_ca=False`) imzaladığı tüm zincirler anında çöpe atılmalıdır (`NonCACertificateUsedAsCAError`).

---

### 5. Alan Adı Eşleme Kuralları (RFC 6125 - CWE-297)

Geçerli bir CA tarafından imzalanmış bir sertifika elinde olsa dahi, eğer alan adı tutmuyorsa bağlantı MITM (Ortadaki Adam) saldırısı altındadır!
- **CN vs SAN:** Tarihsel olarak `Subject CN` kullanılırdı. Günümüzde `CN` kullanımdan kaldırılmıştır; tarayıcılar yalnızca **Subject Alternative Name (SAN)** listesine bakar.
- **Joker (Wildcard) Kuralları:** `*.bank.com.tr`, `odeme.bank.com.tr` ile eşleşir. Ancak `sub.odeme.bank.com.tr` gibi çok seviyeli alan adlarıyla eşleşmez!

---

### 6. Sertifika İptal Mekanizmaları: CRL vs OCSP

Bir sertifikanın özel anahtarı çalınırsa veya bir şirket çalışanının erişimi kesilirse, sertifikanın süresinin bitmesi beklenemez.
1. **CRL (Certificate Revocation List):** CA tarafından periyodik olarak yayınlanan ve iptal edilen sertifika seri numaralarını içeren devasa liste. Dezavantajı: Boyutu yüzlerce megabayta ulaşabilir ve statiktir (güncelleme gecikmesi).
2. **OCSP (Online Certificate Status Protocol):** İstemcinin CA'nın OCSP sunucusuna "Şu seri numaralı sertifika şu an geçerli mi?" diye anlık HTTP sorgusu atması.
3. **OCSP Stapling:** İstemcinin CA'ya gitmesi yerine, sunucunun CA'dan aldığı güncel OCSP yanıtını TLS el sıkışması sırasında kendisinin sunması (performans ve gizlilik kazancı).

---

### 7. Ustanın Çırağa Altın Kuralları

1. **Güven Kökten Başlar:** Zincirin tepesindeki Kök CA senin yerel işletim sistemi güven depoda (`Trust Store`) yoksa, zincir ne kadar kusursuz görünürse görünsün bağlantıyı derhal reddet (CWE-295).
2. **BasicConstraints Hayattır:** `is_ca=False` olan hiçbir sertifikanın başkasını imzalamasına izin verme.
3. **Tarihe ve İptale Asla Güvenme:** Sistem saatini kontrol et; süresi dolmuş veya iptal edilmiş tek bir sertifikayı dahi sistemine sokma.
