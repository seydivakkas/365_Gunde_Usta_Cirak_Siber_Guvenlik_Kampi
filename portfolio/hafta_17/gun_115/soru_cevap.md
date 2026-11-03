# Hafta 17 / Gün 115: OAuth 2.0 ve OpenID Connect — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: OAuth 2.0 ile OpenID Connect (OIDC) Arasındaki Mimari Ayrım ve Access Token ile ID Token'ın Güvenlik Rolleri

### 1. Soru Başlığı ve Tanımı
Geliştiricilerin sıklıkla birbiri yerine kullandığı **OAuth 2.0** ile **OpenID Connect (OIDC)** protokolleri arasındaki temel mimari ve güvenlik farkı nedir? Bir istemci uygulamanın kimlik doğrulamak amacıyla `access_token` kullanması neden büyük bir güvenlik zaafıdır ve `id_token` (JWT) bu sorunu nasıl çözer?

### 2. Derinlemesine Teknik Analiz
OAuth 2.0 (RFC 6749) tasarlanırken bir **yetki devri (delegated authorization)** çerçevesi olarak kurgulanmıştır.
- `access_token`: Yalnızca Kaynak Sunucusuna (Resource Server) hitap eden opak (opaque) veya yapılandırılmış bir yetki belgesidir. İstemci uygulamanın hedef API üzerinde hangi işlemleri (scope) yapabileceğini söyler. Ancak `access_token` şu sorulara yanıt veremez:
  - Bu kullanıcı kimliğini ne zaman ve nasıl doğruladı (`auth_time`, `amr`)?
  - Bu belirteç gerçekten benim istemcim için mi üretildi yoksa başka bir istemciye mi ait (`aud`)?
  - Bu belirteç şu an giriş yapan kullanıcıya mı ait?

Eğer bir istemci, kullanıcının sisteme giriş yaptığını kabul etmek için sadece bir `access_token`'ın varlığına güvenirse (**Pseudorandom Access Token Authentication Anti-Pattern**):
Saldırgan kötü amaçlı başka bir uygulama (Malicious Client B) üzerinden geçerli bir access token alır ve bu token'ı hedef uygulamaya (Victim Client A) sunar. Client A token'ın geçerli olduğunu teyit eder ancak kime ait olduğunu bilmediği için saldırganı kurbanın hesabına oturtabilir (Confused Deputy / Token Substitution Saldırısı).

**OpenID Connect (OIDC Core 1.0) Çözümü:**
OIDC, OAuth 2.0'ın üzerine bir kimlik doğrulama katmanı ekler ve `id_token` üretir.
`id_token` bir JSON Web Token'dır (JWT):
1. **İmza (Cryptographic Signature):** Kimlik Sağlayıcı (IdP) tarafından imzalanmıştır (HS256 veya RS256/ES256); istemci imzanın doğruluğunu matematiksel olarak teyit eder.
2. **Audience (`aud`):** Belirtecin **sadece ve sadece bu istemci** için üretildiğini kanıtlar (`aud == client_id`). Başka uygulamanın token'ı burada çalışmaz.
3. **Subject (`sub`):** Kullanıcının sistemdeki kalıcı tekil kimliğidir.
4. **Zaman Damgaları (`iat`, `exp`, `auth_time`):** Kimlik doğrulamanın ne zaman gerçekleştiğini ve geçerlilik süresini belirtir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret sitesi, kullanıcıları oturum açtırmak için "X ile Giriş Yap" düğmesi koymuştur. Ancak arka planda dönen `access_token`'ı doğrudan `SELECT * FROM users WHERE access_token = :token` şeklinde doğrulamaktadır. Saldırgan kendi telefonundaki mobil uygulama üzerinden geçerli bir access_token alır ve bunu web sitesinin API'sine enjekte eder. Web sitesi token'ın meşru olduğunu doğrular ve saldırgana en son giriş yapan şirket CEO'sunun hesabını teslim eder!

**Pratik Çözüm:**
İstemci tarafında OIDC ID Token katı kurallarla doğrulanmalıdır:
```python
def verify_oidc_identity(id_token_jwt, client_id, expected_issuer, idp_public_key, expected_nonce):
    # 1. JWT İmzası Doğrulanır (CWE-347)
    claims = jwt.decode(id_token_jwt, idp_public_key, algorithms=["RS256"], audience=client_id)
    
    # 2. Issuer Denetimi
    if claims["iss"] != expected_issuer:
        raise SecurityException("Geçersiz Kimlik Sağlayıcı!")
        
    # 3. Nonce Replay Denetimi (CWE-294)
    if claims.get("nonce") != expected_nonce:
        raise SecurityException("Nonce uyuşmazlığı! OIDC replay saldırısı engellendi.")
        
    # Kullanıcı kimliği güvenle tespit edildi
    return claims["sub"]
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, Access Token kapıyı açan anahtardır; ID Token ise üzerindeki fotoğraflı kimlik kartıdır. Kapıcı anahtara bakar ve kapıyı açar. Ama sen misafiri ağırlarken anahtara değil kimlik kartına bakmak zorundasın. Kimlik doğrulamada asla access token kullanma; daima OIDC ID Token'ın imzasını ve audience alanını denetle."

---

## Soru 2: RFC 7636 PKCE (Proof Key for Code Exchange) ve Yetkilendirme Kodu Araya Girme Saldırılarının (Authorization Code Interception — CWE-287) Kriptografik Engellenmesi

### 1. Soru Başlığı ve Tanımı
Mobil uygulamalarda ve Tek Sayfalı Web Uygulamalarında (SPA) klasik OAuth 2.0 Authorization Code akışı neden yetersiz kalmıştır? **Yetkilendirme Kodu Yakalama Saldırısı (Authorization Code Interception Attack — CWE-287)** nasıl gerçekleşir ve **RFC 7636 PKCE** bu açığı kriptografik olarak nasıl tamamen kapatır?

### 2. Derinlemesine Teknik Analiz
Mobil işletim sistemlerinde (Android / iOS) uygulamalar, özel URL şemaları (Custom URI Schemes, örn. `myapp://oauth-callback`) aracılığıyla tarayıcıdan gelen yönlendirmeleri yakalar.
Ancak işletim sisteminde birden fazla uygulama aynı URI şemasını dinleyebilir.

**Saldırı Senaryosu (PKCE Olmadan):**
1. Meşru uygulama kullanıcıyı tarayıcıda IdP'ye yönlendirir.
2. Kullanıcı giriş yapar, IdP `myapp://oauth-callback?code=SPLIT_CODE_123` döner.
3. Cihazdaki kötü niyetli bir casus uygulama (Malicious App) bu URI yönlendirmesini meşru uygulamadan önce yakalar.
4. Mobil veya SPA uygulamaları genel istemci (Public Client) olduğu için `client_secret` barındıramaz.
5. Casus uygulama yakaladığı `SPLIT_CODE_123` kodunu alarak doğrudan IdP'nin `/token` uç noktasına gider ve kurbanın adına `access_token` alır (CWE-287).

**PKCE (RFC 7636) ile Kriptografik Kilit:**
PKCE bu açığı dinamik, geçici bir asimetrik meydan okuma ile çözer:
1. **Üretim:** Meşru istemci cihazın belleğinde yüksek entropili rastgele bir dizge üretir:
   $$\text{code\_verifier} \in [A\text{-}Z, a\text{-}z, 0\text{-}9, \dots]^{64}$$
2. **Özetleme:** Bu verifier'ın SHA-256 özetini alıp Base64URL kodlar:
   $$\text{code\_challenge} = \text{BASE64URL}(\text{SHA-256}(\text{code\_verifier}))$$
3. **Yetkilendirme:** `/authorize` isteğine `code_challenge` ve `code_challenge_method=S256` eklenir. IdP bu challenge'ı hafızaya yazar.
4. **Kod Çalınsa Bile:** Casus uygulama `AUTH_CODE` değerini yakalasa dahi, `/token` uç noktasına gittiğinde sunucu ondan orijinal `code_verifier`'ı talep eder.
5. **Matematiksel Engel:** Kriptografik özet fonksiyonları tek yönlüdür ($\text{SHA-256}^{-1}$ hesaplanamaz). Casus uygulama `code_challenge`'dan `code_verifier`'ı türetemez.
6. Meşru uygulama ise belleğinde sakladığı `code_verifier`'ı sunucuya iletir. Sunucu $\text{SHA-256}(\text{code\_verifier}) == \text{code\_challenge}$ olduğunu teyit eder ve belirteci sadece meşru istemciye teslim eder!

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kripto para alım-satım mobil uygulamasında kullanıcılar OAuth 2.0 ile giriş yapmaktadır. Cihaza indirilen sahte bir fener uygulaması, kripto uygulamasının deep-link callback şemasını dinleyerek yetkilendirme kodlarını yakalamakta ve kullanıcıların cüzdan API token'larını çalmaktadır.

**Pratik Çözüm:**
Yetkilendirme Sunucusu (IdP), PKCE kullanılmayan tüm istekleri reddetmelidir (OAuth 2.1 Standardı):
```python
# Authorization Server Uç Noktası Kontrolü:
if not request.code_challenge or request.code_challenge_method != "S256":
    raise PKCEVerificationFailedError("OAuth 2.1 Güvenlik Kuralı: PKCE S256 zorunludur!")
```

### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, 'Client Secret' genel istemcilerde bir hayaldir. Bir mobil uygulamanın içine veya JavaScript koduna gömdüğün parola, saniyeler içinde ayıklanır. Cihaza güvenme, belleğe güven; dinamik PKCE anahtarını her oturumda anlık üret ve takasta doğrulat. OAuth 2.1'de PKCE artık bir seçenek değil, kanundur."

---

## Soru 3: OAuth Akışlarında Açık Yönlendirici (Open Redirector — CWE-601) ve CSRF (State Parametresi — CWE-352) Tehditlerinin Anatomisi ve Güvenli Beyaz Liste Mimarisi

### 1. Soru Başlığı ve Tanımı
OAuth 2.0 mimarisinde **Açık Yönlendirici (Open Redirector — CWE-601)** ve **Siteler Arası İstek Sahteciliği (CSRF — CWE-352)** saldırıları nasıl kurgulanır? `redirect_uri` denetiminde yapılan yaygın hatalar nelerdir ve `state` parametresinin kriptografik yaşam döngüsü nasıl yönetilmelidir?

### 2. Derinlemesine Teknik Analiz

#### A. Açık Yönlendirici (Open Redirector — CWE-601)
Yetkilendirme sunucusu, yetkilendirme kodunu kullanıcıya `redirect_uri` parametresi üzerinden geri döndürür.
Eğer sunucu bu parametreyi katı bir şekilde denetlemezse:
- Geliştirici hatası 1: Sadece domain başlangıcını kontrol etmek (`redirect_uri.startswith("https://app.com")`) $\rightarrow$ Saldırgan `https://app.com.attacker.com` adresini sunar!
- Geliştirici hatası 2: Regex'te nokta karakterini kaçırmamak (`https://app.com`) $\rightarrow$ Saldırgan `https://appXcom.com` adresini sunar!
- Geliştirici hatası 3: Joker karakter (`*`) kullanmak (`https://*.app.com`) $\rightarrow$ Saldırganın ele geçirdiği bir alt alan adı tüm kodları toplar.

Saldırgan kurbana şu linki gönderir:  
`https://idp.siber.local/authorize?client_id=123&redirect_uri=https://attacker.com/steal`  
Kullanıcı meşru IdP ekranında giriş yaptığında, IdP kullanıcıyı doğrudan saldırganın sitesine yönlendirir:  
`https://attacker.com/steal?code=GIZLI_YETKILENDIRME_KODU`  
Saldırgan kodu ele geçirir.

#### B. OAuth CSRF Saldırısı (CWE-352)
Eğer `state` parametresi kullanılmazsa:
1. Saldırgan kendi hesabıyla IdP'de akış başlatır ve kendine ait bir `AUTH_CODE_SALDIRGAN` alır.
2. Bu callback isteğini tamamlamaz; URL'i kurbana bir resim veya iframe içinde tıklatır:  
   `https://app.siber.local/callback?code=AUTH_CODE_SALDIRGAN`
3. Kurbanın tarayıcısı bu isteği çalıştırır ve kurbanın oturumu **saldırganın hesabına** bağlanır!
4. Kurban kendi kredi kartını veya verilerini girdiğinde aslında saldırganın profiline veri yüklemiş olur.

**Kriptografik Çözüm:**
İstemci istek göndermeden önce 128-bit rastgele bir `state` üretir, bunu kullanıcının güvenli session çerezine (HttpOnly, SameSite=Strict) yazar. Callback geldiğinde gelen state ile oturumdaki state `secrets.compare_digest` ile doğrulanır. Eşleşmiyorsa işlem derhal imha edilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir online bankacılık sisteminde üçüncü parti muhasebe entegrasyonu mevcuttur. IdP, yönlendirme adresini gevşek kontrol ettiği için saldırgan muhasebe uygulamasının açık yönlendiricisini kullanarak bankanın yetkilendirme kodunu kendi sunucusuna aktarmıştır.

**Pratik Çözüm:**
Yetkilendirme Sunucusunda Katı Birebir Beyaz Liste (Exact Matching Whitelist):
```python
def validate_redirect_uri(client: OAuthClient, requested_uri: str):
    # Asla regex veya startswith kullanılmaz! Birebir küme elemanı denetimi:
    if requested_uri not in client.registered_redirect_uris:
        raise InvalidRedirectURIError(f"CWE-601: '{requested_uri}' beyaz listede yok!")
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, redirect_uri doğrulamasında regex yazan mühendis, saldırgana davetiye çıkaran mühendistir. Regex karmaşıktır, gözden kaçar, baypas edilir. Yönlendirme adreslerini sabit bir listede birebir (exact match) tutacaksın. `state` parametresini ise asla opsiyonel bırakmayacaksın; state yoksa yetkilendirme de yoktur!"
