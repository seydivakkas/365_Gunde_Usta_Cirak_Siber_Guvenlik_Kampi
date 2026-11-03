# Hafta 17 / Gün 113: Kimlik Doğrulama ve Yetkilendirme — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: Kimlik Doğrulama (AuthN) ve Yetkilendirme (AuthZ) Arasındaki Mimari Ayrım ve OWASP A01 vs A07 Zafiyetlerinin Temel Dinamikleri

### 1. Soru Başlığı ve Tanımı
Geliştiricilerin sıklıkla birbirine karıştırdığı **Kimlik Doğrulama (Authentication - AuthN)** ile **Yetkilendirme (Authorization - AuthZ)** kavramları arasındaki yapısal farklar nelerdir? Bu iki katmanın birbirinin yerine geçmesi veya birinin atlanması durumunda ortaya çıkan **OWASP Top 10 (A01:2021 Broken Access Control ve A07:2021 Identification and Authentication Failures)** zafiyetlerinin kök nedenleri nasıl açıklanır?

### 2. Derinlemesine Teknik Analiz
Mühendislik düzeyinde AuthN ve AuthZ, birbiriyle sıralı bağımlılığı olan ancak tamamen farklı matematiksel ve mantıksal prensiplere dayanan iki farklı güvenlik katmanıdır:

1. **AuthN Katmanı (Özne Doğrulama - Identity Assurance):**
   - Sorumluluk alanı, gelen isteği gönderen varlığın (insan, makine, mikroservis) iddia ettiği kimliğin doğrulanmasıdır.
   - Burada kriptografik entropi, tuzlu karma algoritmaları (PBKDF2-HMAC-SHA256, Argon2id, bcrypt), asimetrik imza teyidi (RSA/ECDSA), asimetrik şifre çözme veya MFA token doğrulaması işletilir.
   - **A07:2021 Başarısızlığı:** Parolaların düz metin saklanması, yetersiz karma iterasyonu, oturum belirteçlerinin tahmin edilebilir üretilmesi (zayıf PRNG), oturum sabitleme (Session Fixation - CWE-384) veya brute-force korumasının bulunmamasıdır.

2. **AuthZ Katmanı (Erişim Kararı - Authorization Decision):**
   - Sorumluluk alanı, kimliği kesinleşmiş öznenin, sistemdeki hedef kaynaklar üzerindeki yetki sınırlarının çizilmesidir.
   - Mantık: $Erişim(Özne, Kaynak, Eylem) \in \{ALLOW, DENY\}$.
   - Politika Karar Noktası (PDP) ve Politika Uygulama Noktası (PEP) mimarisine dayanır.
   - **A01:2021 Başarısızlığı:** Kullanıcının kimliği başarıyla doğrulanmasına rağmen, arka planda "Bu kullanıcı bu işlemi yapabilir mi?" kontrolünün yapılmaması veya güvenilmeyen istemci parametrelerine (`is_admin=true` veya nesne kimliği `id=55`) güvenilmesidir.

Eğer AuthN başarılı olup AuthZ atlanırsa, sistemdeki her kayıtlı kullanıcı diğer tüm kullanıcıların ve yöneticilerin yetkilerine erişebilir hale gelir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekom operatörünün fatura görüntüleme portalında kullanıcılar sisteme SMS OTP ve parola ile (mükemmel bir AuthN) giriş yapmaktadır. Ancak fatura indirme API'si şu şekildedir:  
`GET /api/v1/faturalar/105820/indir`  
Saldırgan Ali, kendi fatura numarası `105820` yerine rakamı `105821` yaptığında, sistem Ali'nin oturumunun geçerli (AuthN) olduğunu görerek Veli'nin faturasını Ali'ye teslim etmektedir.

**Pratik Çözüm:**
Uygulamada İki Kademeli Geçit (Dual-Gate PEP) zorunlu kılınmalıdır:
```python
# 1. Aşama: AuthN Denetimi (Kimsin?)
session = authn_engine.validate_session(request.bearer_token)

# 2. Aşama: AuthZ ve Nesne Düzeyi Denetimi (Bu nesne senin mi?)
fatura = db.query(Fatura).filter_by(id=fatura_id).first()
if not fatura:
    raise ResourceNotFoundError()

# IDOR ve Yetki Kontrolü:
if fatura.sahip_id != session.user_id and "admin" not in session.roles:
    # CWE-639 IDOR Engellemesi
    raise InsecureDirectObjectReferenceError("Bu faturaya erişim yetkiniz bulunmamaktadır.")
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, hiçbir zaman 'kullanıcı oturum açtıysa her şeyi yapabilir' deme. Kapıdaki bekçi (AuthN) ziyaretçinin kimlik kartına bakar ve binaya sokar. Ama odalardaki kilitler (AuthZ) o ziyaretçinin kasayı mı yoksa sadece bekleme salonunu mu kullanacağını belirler. Bekçiyi kilit yerine koyarsan, binayı soygunculara teslim edersin."

---

## Soru 2: Sabit Zamanlı Özet Karşılaştırması (secrets.compare_digest) ve CWE-208 Zamanlama Yan Kanalı Saldırılarının Kriptografik Anatomisi

### 1. Soru Başlığı ve Tanımı
Parola özetleri, API anahtarları veya HMAC imzaları doğrulanırken neden standart dize karşılaştırma işlemleri (`a == b`) kullanılamaz? **CWE-208: Observable Timing Discrepancy** zafiyeti tam olarak nasıl sömürülür ve Python'ın `secrets.compare_digest()` fonksiyonu bunu kriptografik olarak nasıl engeller?

### 2. Derinlemesine Teknik Analiz
Standart dize ve bayt karşılaştırma algoritmaları (örneğin C dilindeki `memcmp` veya Python'daki standart `==` operatörü) **erken çıkışlı (early-exit / short-circuit)** çalışır:

```c
// Standart Karşılaştırma Mantığı (Zafiyetli - Erken Çıkış)
int insecure_compare(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0; // İLK EŞLEŞMEYEN KARAKTERDE ÇIKAR! (Zaman farkı yaratır)
        }
    }
    return 1;
}
```

Eğer saldırgan 64 karakterlik bir HMAC imzasını tahmin etmeye çalışıyorsa:
- İlk bayt yanlış olduğunda sunucu 1 döngü işletip `False` döner (Örn. 5.1 mikrosaniye).
- İlk bayt doğru, ikinci bayt yanlış olduğunda sunucu 2 döngü işletip `False` döner (Örn. 5.3 mikrosaniye).

Saldırgan binlerce istatistiksel istek göndererek (zamanlama analizi), doğru baytları tek tek tespit eder ve $256^{32}$ permütasyon denemek yerine sadece $256 \times 32$ denemeyle geçerli imzayı veya karma değerini yeniden üretir.

`secrets.compare_digest(a, b)` fonksiyonunun kriptografik çalışma prensibi:
```c
// Sabit Zamanlı Karşılaştırma Mantığı (Güvenli - Constant-Time)
int safe_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]); // XOR işlemi; tüm dizilim baştan sona taranır
    }
    return (result == 0); // Eşleşmeme olsa dahi tüm uzunluk eşit sürede taranır
}
```
Burada hiçbir koşullu atlama (`branching`) ve erken çıkış yoktur; her bayt XOR işlemine tabi tutulur ve işlem süresi dizelerin içeriğinden bağımsızdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir ödeme geçidinde web kancası (webhook) bildirimleri HMAC-SHA256 imzasıyla korunmaktadır. Geliştirici doğrulama kodunu şöyle yazmıştır:
```python
# ZAFİYETLİ KOD:
beklenen_imza = hmac.new(gizli_anahtar, govde, hashlib.sha256).hexdigest()
if gelen_imza == beklenen_imza:  # CWE-208 ZAMANLAMA AÇIĞI!
    odemeyi_onayla()
```
Bir siber saldırgan yerel ağdan veya düşük gecikmeli bir sunucudan mikrosaniye farklarını ölçerek geçerli webhook imzasını üretmeyi başarmış ve sahte "Ödeme Tamamlandı" bildirimleri göndermiştir.

**Pratik Çözüm:**
```python
# GÜVENLİ KOD:
import secrets

beklenen_imza = hmac.new(gizli_anahtar, govde, hashlib.sha256).hexdigest()
# secrets.compare_digest veya hmac.compare_digest sabit zamanlıdır
if secrets.compare_digest(gelen_imza, beklenen_imza):
    odemeyi_onayla()
else:
    raise InvalidSignatureError("İmza doğrulanamadı!")
```

### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, kriptografide 'doğru çalışması' ile 'güvenli çalışması' aynı şey değildir. `a == b` fonksiyonel olarak doğru sonucu verir, ama arkasından geçen zamanı düşmana fısıldar. Gizli bir anahtar, özet veya belirteç kıyaslıyorsan klavyenden `==` harflerini sil; sadece ve sadece `secrets.compare_digest` kullan."

---

## Soru 3: Insecure Direct Object References (IDOR - CWE-639) Tehdidine Karşı Nesne Düzeyinde Erişim Denetimi ve Çok Kiracılı (Multi-Tenant) İzolasyon Tasarımı

### 1. Soru Başlığı ve Tanımı
Geleneksel rol tabanlı erişim kontrolü (RBAC) modelleri neden tek başına **IDOR (Insecure Direct Object Reference — CWE-639)** ve **Çok Kiracılı İzolasyon İhlallerini (CWE-284)** engellemeye yetmez? Kurumsal SaaS sistemlerinde nesne düzeyinde erişim denetimi (Object-Level Access Control) ve kiracı sınırları nasıl kurgulanmalıdır?

### 2. Derinlemesine Teknik Analiz
RBAC modeli, kullanıcıları rollere, rolleri de izinlere eşler (Örn: `Role: Customer` $\rightarrow$ `Permission: VIEW_INVOICE`).
Ancak RBAC'ın **özne-kaynak bağıntısı (contextual ownership)** konusunda hiçbir farkındalığı yoktur. 

Bir müşteri `VIEW_INVOICE` yetkisine sahiptir, evet. Ancak bu izin müşteriye **"sistemdeki TÜM faturaları"** mı yoksa **"SADECE KENDİ faturasını"** mı görme hakkı verir?

Eğer arka plandaki yetkilendirme motoru sadece:
$$\text{has\_permission}(user, "VIEW\_INVOICE")$$
kontrolü yaparsa, kullanıcı `invoice_id=999` parametresini değiştirerek başka bir şirketin veya kullanıcının faturasını indirebilir.

Bu zafiyeti engellemek için **Öznitelik Tabanlı Erişim Kontrolü (ABAC)** veya **Nesne Düzeyinde Güvenlik Kontrolü (Object-Level Authorization)** devreye alınmalıdır:
1. **Kiracı İzolasyonu (Tenant Boundary):** İstek sahibinin ait olduğu `tenant_id` ile kaynağın ait olduğu `tenant_id` kesin olarak eşleşmelidir ($\text{tenant}_{user} == \text{tenant}_{resource}$).
2. **Sahiplik İzolasyonu (Ownership Boundary):** Kaynak nesnesi bir kullanıcıya aitse ve kullanıcı sistem yöneticisi (admin) değilse, $\text{owner}_{resource} == \text{username}_{user}$ şartı sağlanmalıdır.
3. **Açık Red İlkesi (Default Deny):** Sahiplik veya kiracı doğrulaması başarısız olursa istisnasız `AccessDeniedError` veya `InsecureDirectObjectReferenceError` fırlatılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Çok kiracılı (multi-tenant) bir bulut İK yazılımında A Şirketi ve B Şirketi barınmaktadır. A Şirketinin İK Yöneticisi olan Ahmet, çalışan izin belgelerini onaylamaktadır. Ahmet izin onay formunda URL'deki çalışan ID'sini B Şirketindeki Mehmet'in ID'siyle değiştirdiğinde, sistem her iki kullanıcının da sistemde kayıtlı olduğunu görerek Mehmet'in tüm kişisel sağlık ve maaş verilerini Ahmet'in ekranına getirmektedir.

**Pratik Çözüm:**
Yetkilendirme Motorunda (PDP) Çok Aşamalı Nesne Sahiplik Kontrolü:
```python
def authorize_resource_access(subject: UserContext, resource: Resource, action: str):
    # 1. Aşama: Kiracı İzolasyon Kontrolü (CWE-284)
    if subject.tenant_id != resource.tenant_id:
        raise TenantMismatchError(f"Çapraz kiracı erişim ihlali: {subject.tenant_id} != {resource.tenant_id}")

    # 2. Aşama: Rol Yetki Kontrolü (CWE-862)
    required_permission = resource.get_permission_for(action)
    if not subject.has_permission(required_permission):
        raise AccessDeniedError("Rolünüz bu işlemi yapmaya yetkili değil.")

    # 3. Aşama: Nesne Düzeyinde Sahiplik Kontrolü (CWE-639 IDOR)
    is_admin = subject.has_role("admin") or subject.has_role("tenant_admin")
    if not is_admin and resource.owner_id != subject.user_id:
        raise InsecureDirectObjectReferenceError("Bu kaynağın sahibi değilsiniz; nesne erişimi reddedildi.")

    return True
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, veritabanına sorgu atarken asla sadece `SELECT * FROM fatura WHERE id = :id` yazma! Bir güvenlik mimarı o sorguyu daima `SELECT * FROM fatura WHERE id = :id AND tenant_id = :tenant_id AND user_id = :user_id` diye yazar. Güvenlik kontrollerini sadece kod seviyesinde değil, veri katmanının en derin çekirdeğine kadar zincirle bağla."
