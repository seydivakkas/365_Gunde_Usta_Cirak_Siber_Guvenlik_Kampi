# Hafta 17 / Gün 116: JWT Yapısı ve Doğrulama — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: JWT İmza Bypass Zafiyeti: `alg: none` Açığı (CWE-347) ve Güvenli Kütüphane Tasarımı

### 1. Soru Başlığı ve Tanımı
JSON Web Token (RFC 7519) ve JSON Web Signature (RFC 7515) standartlarında yer alan `"alg": "none"` başlığı ne anlama gelir? Birçok popüler JWT kütüphanesini ve web uygulamasını geçmişte tamamen savunmasız bırakan **None Algorithm Signature Bypass (CWE-347)** saldırısı nasıl gerçekleşir ve bir güvenlik mühendisi bunu kökünden nasıl engeller?

### 2. Derinlemesine Teknik Analiz
RFC 7515 spesifikasyonunda imzasız veya bütünlüğü güvence altına alınmamış veriler için `"alg": "none"` opsiyonu tanımlanmıştır. Tasarım gereği bu durumda imza bileşeni boştur (örn. `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.`).

**Saldırı Mekanizması:**
1. Standart bir JWT token üç parçadan oluşur: `Header.Payload.Signature`.
2. Zayıf veya denetimsiz kütüphaneler imza doğrulama fonksiyonunu çalıştırırken token başlığındaki (`Header`) `alg` değerine körü körüne güvenir:
   ```python
   # GÜVENSİZ KOD ÖRNEĞİ:
   header = json.loads(base64_decode(token_parts[0]))
   alg = header.get("alg")
   if alg == "none":
       return payload # İMZAYI HİÇ DENETLEMEDEN GEÇİRİR!
   ```
3. Saldırgan elindeki meşru token'ın başlığını çözümler, `alg` değerini `"none"` (veya büyük/küçük harf varyasyonları `"None"`, `"NONE"`) yapar.
4. Payload içerisindeki `user_id` veya `role` alanını `"admin"` olarak değiştirir.
5. İmzayı tamamen silerek token'ı `Base64(Header).Base64(Payload).` şeklinde sunucuya gönderir.
6. Sunucu kütüphanesi "alg: none ise imza denetleme" mantığıyla çalıştığı takdirde, saldırgan herhangi bir gizli anahtara sahip olmadan sisteme **Süper Yönetici (Root/Admin)** olarak sızar (CWE-347).

**Kriptografik Çözüm Mimarisi:**
- Sunucu tarafında **Katı Algoritma Beyaz Listesi (Strict Algorithm Whitelisting)** uygulanmalıdır.
- İstemciden gelen `alg` alanına ASLA güvenilmez. Uygulama yalnızca izin verilen güvenli algoritmaları (örn. `{"HS256", "RS256"}`) kabul etmelidir.
- Token başlığında `alg: none` görüldüğü anda, herhangi bir başka kontrole geçilmeksizin derhal `JWTAlgNoneForbiddenError` fırlatılmalı ve güvenlik olayı denetim günlüğüne (audit log) kaydedilmelidir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kamu kurumunun e-hizmet portalında kullanıcı yetkilendirmesi JWT ile yapılmaktadır. Güvenlik açığı bulunan eski bir JWT kütüphanesi kullanılmaktadır. Saldırgan kendi kimlik numarası olan `10000000000` yerine bakanın kimlik numarasını `sub` alanına yazıp `alg: none` ile token oluşturur. Portal saldırganı bakan olarak karşılar ve gizli devlet belgelerini indirmesine izin verir.

**Pratik Çözüm (Üretim Seviyesi Python):**
```python
def verify_jwt_header_securely(raw_header_bytes: bytes, allowed_algorithms: set[str]):
    header_json = json.loads(raw_header_bytes.decode("utf-8"))
    claimed_alg = str(header_json.get("alg", "")).strip().lower()
    
    # 1. alg: none ve varyasyonları tavizsiz engellenir (CWE-347)
    if claimed_alg == "none":
        raise JWTAlgNoneForbiddenError("KRİTİK GÜVENLİK İHLALİ: alg: none kesinlikle yasaktır!")
        
    # 2. Algoritma beyaz liste doğrulaması yapılır
    if header_json.get("alg") not in allowed_algorithms:
        raise JWTAlgorithmMismatchError(f"İzin verilmeyen algoritma: {header_json.get('alg')}")
        
    return header_json
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, kapıyı kilitleyen mekanizmaya, anahtarın neye benzemesi gerektiğini kapıyı açmaya çalışan yabancı söyleyemez! JWT'nin başlığındaki `alg` bilgisi bir beyandır, talimat değil. Senin sunucun hangi algoritmayla imzaladıysa, SADECE o algoritmayı beklemelidir. 'none' kelimesini gördüğün yerde alarm zillerini çalacaksın."

---

## Soru 2: Algoritma Karışıklığı Saldırısı (Algorithm Confusion / Key Confusion CWE-327): RS256 $\rightarrow$ HS256 Manipülasyonu

### 1. Soru Başlığı ve Tanımı
Asimetrik şifreleme (RS256) kullanan bir kimlik doğrulama mimarisinde, saldırganın sistemi simetrik şifrelemeye (HS256) zorlaması (**Algorithm Confusion Attack — CWE-327**) nasıl gerçekleştirilir? Açık anahtar (Public Key) bu saldırıda nasıl kötüye kullanılır?

### 2. Derinlemesine Teknik Analiz
Asimetrik ve simetrik imzalamanın temel farkı anahtar simetrisidir:
- **RS256:** İmzalamak için Özel Anahtar (Private Key $d$), doğrulamak için Açık Anahtar (Public Key $(n, e)$) kullanılır. Açık anahtar dünyadaki herkes tarafından bilinir (örn. `/.well-known/jwks.json`).
- **HS256:** İmzalamak için de doğrulamak için de **aynı Gizli Simetrik Anahtar ($K$)** kullanılır.

**Saldırının Matematiği ve Adımları:**
1. Hedef sunucu meşru token'ları **RS256** ile imzalamakta ve genel erişime açık bir Public Key (`public.pem`) sunmaktadır.
2. Doğrulama kodunda şu zafiyet mevcuttur:
   ```python
   # ZAAFLI KOD:
   alg = jwt_header["alg"] # Saldırgan burayı "HS256" yapabilir!
   jwt.decode(token, key=server_public_key, algorithms=[alg])
   ```
3. Kütüphane `alg` değerini `"HS256"` olarak okur. Kütüphaneye verilen doğrulama anahtarı ise `server_public_key` (PEM veya dize) metnidir.
4. HMAC fonksiyonu ($HMAC(K, M)$) anahtarın türüne bakmaz; ona verilen anahtar dizesini simetrik gizli anahtar olarak kabul eder!
5. Saldırgan sunucunun **herkese açık olan Public Key metnini** simetrik anahtar ($K$) olarak kullanır:
   $$\text{Forged Signature} = \text{HMAC-SHA256}_{K = \text{Public Key}}(\text{Header} \mathbin{\Vert} \text{Payload})$$
6. Sunucu token'ı aldığında başlığa bakar: `"alg": "HS256"`. Kendi elindeki `server_public_key` ile HMAC hesaplar.
7. İki HMAC çıktısı birebir eşleşir! Sunucu, saldırganın sahte token'ını meşru kabul eder (CWE-327).

**Savunma Yöntemi:**
- Asimetrik anahtarla doğrulanması gereken bir serviste asla serbest algoritma seçimi yapılmamalıdır.
- Doğrulama fonksiyonuna `expected_alg="RS256"` parametresi zorunlu kılınmalı; gelen token'ın algoritması bununla birebir örtüşmüyorsa derhal reddedilmelidir.
- Genel anahtar nesnesi asla bir simetrik HMAC fonksiyonuna ham anahtar verisi olarak aktarılmamalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir SaaS platformunda mikroservisler Auth0/Keycloak üzerinden RS256 token tüketmektedir. Bir mikroservis ekibi Node.js kütüphanesini yapılandırırken algoritma parametresini boş bırakmıştır. Kırmızı takım (Red Team), sistemin `jwks.json` dosyasından RSA açık anahtarını indirir. Bu açık anahtarı simetrik secret olarak kullanarak `{"role": "superuser"}` payload'unu HS256 ile imzalar ve API'ye sunar. Mikroservis isteği sorgusuz sualsiz kabul eder.

**Pratik Çözüm:**
```python
def verify_jwt_algorithm_lock(token_alg: str, configured_alg: str):
    # KESİN ALGORİTMA KİLİDİ:
    if token_alg != configured_alg:
        raise JWTAlgorithmMismatchError(
            f"Algorithm Confusion Engellendi (CWE-327)! Beklenen: {configured_alg}, Gelen: {token_alg}"
        )
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, açık anahtar dünyayla paylaştığın kartvizitindir. Bir kütüphanenin, kartvizitini alıp seni kasaya sokan gizli şifre zannetmesi akıl tutulmasıdır. Kodunda algoritmayı dışarıdan gelen token'a değil, kendi sabit güvenlik politikana bağla. RS256 bekliyorsan HS256 geldiği an kapıyı yüzüne kapat."

---

## Soru 3: Stateless JWT Mimarilerinde Token İptali (Revocation), `jti` Kara Listesi ve Süre Aşımı (`exp`, Clock Skew — CWE-298/613)

### 1. Soru Başlığı ve Tanımı
Durumsuz (Stateless) yapıda çalışan JWT'lerin en büyük açmazı olan **"Kullanıcı şifresini değiştirdiğinde veya çıkış yaptığında token geçerliliğini korur mu?"** sorusu nasıl çözülür? `jti` (JWT ID), Kara Liste (Revocation Blacklist) ve Saat Sapması Toleransı (Clock Skew Leeway) bir arada nasıl güvenle yönetilir?

### 2. Derinlemesine Teknik Analiz
Stateless JWT mimarisinin avantajı sunucunun oturum veritabanına bakmadan hızlıca doğrulama yapabilmesidir. Ancak bu durum iki temel güvenlik riskini doğurur:
1. **İptal Edilememe Sorunu (CWE-613):** Kullanıcı oturumu kapattığında veya hesabı askıya alındığında, elindeki JWT `exp` süresi dolana kadar yetkilendirilmeye devam eder. Çalınan bir token geçerlilik süresi boyunca saldırgana sınırsız erişim sağlar.
2. **Yeniden Oynatma (Replay Attack — CWE-294):** Ağ dinleme ile ele geçirilen bir token tekrar tekrar kullanılabilir.

**Kriptografik ve Mimari Çözüm Bileşenleri:**
1. **Tekil Belirteç Kimliği (`jti` - RFC 7519 4.1.7):**
   Her üretilen token'a yüksek entropili rastgele bir UUID verilir (`jti = uuid4().hex`).
2. **Dağıtık TTL Kara Listesi (Blacklist / Revocation Store):**
   Kullanıcı oturumu kapattığında veya token ifşa olduğunda, `jti` değeri merkezi ve çok hızlı bir belleğe (Redis/In-Memory) yazılır. Bu kaydın bellekte kalma süresi (TTL), token'ın kalan `exp` süresine eşittir (`TTL = exp - now`). Token'ın süresi dolduğunda kayıt otomatik olarak silinir; böylece veritabanı şişmesi engellenir.
3. **Zaman Doğrulaması ve Leeway Yönetimi (CWE-298):**
   - Sunucular arasındaki milisaniyelik NTP senkronizasyon farkları için makul bir tolerans (örn. 5 saniye) verilmelidir.
   - Ancak tolerans asla dakikaları bulmamalıdır. `current_time > exp + leeway` olduğu anda token kesinlikle geçersiz sayılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir finans uygulamasında kullanıcının cep telefonu çalınmıştır. Kullanıcı web arayüzünden parolasını sıfırlamış ve "Tüm oturumları kapat" butonuna basmıştır. Ancak JWT stateless olduğu için hırsız çalınan telefondaki token ile 2 saat boyunca banka havaleleri yapmaya devam etmiştir!

**Pratik Çözüm (Hybrid Revocation Pattern):**
```python
def validate_token_lifecycle(claims: dict, revocation_store: set[str], max_leeway_sec: int = 5):
    now = int(time.time())
    
    # 1. exp Zaman Aşımı Denetimi (CWE-613)
    if claims["exp"] + max_leeway_sec < now:
        raise JWTExpiredError("Token süresi dolmuş!")
        
    # 2. nbf (Not Before) Erken Kullanım Denetimi (CWE-298)
    if claims.get("nbf") and (claims["nbf"] - max_leeway_sec > now):
        raise JWTImmatureError("Token henüz geçerli değil!")
        
    # 3. jti Kara Liste Denetimi (Stateful Revocation - CWE-294)
    token_id = claims.get("jti")
    if not token_id or token_id in revocation_store:
        raise JWTRevokedError("Bu token iptal edilmiştir veya jti eksiktir!")
        
    return True
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, safiyane stateless hayaller gerçeğin duvarına çarpar. Bir güvenlik sisteminde gerektiğinde yetkiyi anında geri alamıyorsan, kontrol sende değil saldırgandadır. Access token'ların süresini kısa tut (maksimum 10-15 dakika), `jti` mekanizmasını asla ihmal etme ve acil durum iptal listesini hızdan ödün vermeden sistemin kalbine yerleştir."
