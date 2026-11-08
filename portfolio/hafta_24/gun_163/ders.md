# Gün 163: NoSQL Injection ve ORM Sınırları — Usta-Çırak Derinlemesine Teknik Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Usta Girişi: "SQL'den Kaçarken NoSQL ve ORM Bataklığına Düşmek"

Evlat, yazılım dünyasında en tehlikeli yanılgılardan biri şudur: *"Biz projede MongoDB / NoSQL kullandık, SQL yok ki injection olsun!"* veya *"Biz doğrudan SQL yazmıyoruz, SQLAlchemy / Prisma / TypeORM / Hibernate kullanıyoruz; ORM bizi her şeyden korur."*

Bu iki iddia da siber güvenlik açısından ölümcül birer cehalet örneğidir.

NoSQL veritabanları (MongoDB, CouchDB vb.) SQL sözdizimi kullanmazlar, doğru; fakat **veri ile mantık arasındaki sınır** burada da çöker. SQL dünyasında saldırgan tırnak işaretleriyle string literallerinden çıkıp SQL AST'sini manipüle ederken; NoSQL dünyasında saldırgan, HTTP istek gövdesine gömülü JSON/BSON veri yapılarını kullanarak veritabanı sürücüsünün sorgu motoruna doğrudan **operatör nesneleri (`$ne`, `$gt`, `$regex`, `$where`, `$in`)** enjekte eder.

ORM (Object-Relational Mapping) katmanlarına gelince; evlat, ORM geliştiriciyi temel SQL injection'dan koruyan parametrik sorgu mekanizmasını otomatik kurar; ancak mimariye bambaşka bir kabus sokar: **Kütlesel Atama (Mass Assignment / Over-Posting / Auto-Binding)** ve **N+1 / Lazy Loading sızıntıları**.

Bugün bu derste hem NoSQL sorgu motorlarının iç yapısını hem de ORM soyutlamasının arkasındaki güvenlik açıklarını cerrahi bir hassasiyetle masaya yatıracağız.

---

## 2. NoSQL Operatör Enjeksiyonunun Anatomisi

### 2.1 JSON Nesnelerinin Sorgu Sözlüğüne Doğrudan Aktarılması Faciası
Geleneksel bir Express.js / Node.js veya Python / Flask uygulamasında geliştirici şöyle bir giriş kodu yazar:

```python
# ZAFİYETLİ KOD: Gelen JSON sözlüğü doğrudan find() fonksiyonuna aktarılıyor!
username = request.json.get("username")
password = request.json.get("password")

user = db.users.find_one({"username": username, "password_hash": password})
if user:
    # Oturum açıldı!
```

Eğer istemci normal bir form doldurursa istek gövdesi şöyledir:
```json
{"username": "admin", "password": "SecretPassword123"}
```
Veritabanı sürücüsü `{"username": "admin", "password_hash": "SecretPassword123"}` şartını arar.

Fakat saldırgan bir HTTP JSON gövdesiyle şunu yollarsa:
```json
{"username": "admin", "password": {"$ne": ""}}
```
`request.json.get("password")` ifadesi geriye bir `str` (dize) değil, bir `dict` (sözlük) döndürür: `{"$ne": ""}`.
Sorgu motoru bunu şu şekilde yorumlar:
> *"Kullanıcı adı 'admin' olan VE parola özeti boş dizeye EŞİT OLMAYAN ilk kaydı getir!"*

Sistemde admin'in parolası boş olmadığı sürece sorgu **DOĞRU (True)** döner ve saldırgan tek bir karakter parola bilmeden sistem yöneticisi oturumunu ele geçirir!

### 2.2 Tehlikeli NoSQL Operatörleri Matrisi

| Operatör | Anlamı | Saldırı Senaryosu ve Etkisi |
| :--- | :--- | :--- |
| **`$ne`** | Not Equal (Eşit Değil) | Parola doğrulamayı bypass eder (`{"$ne": ""}` her zaman True). |
| **`$gt` / `$gte`** | Greater Than (Büyük / Eşit) | Boş dizeden büyük tüm kullanıcıları sızdırır, kimlik aşımı yapar. |
| **`$regex`** | Regular Expression | Kör (Blind) veri sızdırma: Parolayı veya gizli token'ı harf harf regex ile (`^A.*`, `^Ad.*`) sorgulayarak çıkarır. |
| **`$where`** | Server-Side JavaScript Eval | Veritabanı motoru içinde doğrudan JS kodu çalıştırır; DoS, bellek tüketimi ve RCE riski doğurur. |
| **`$in` / `$nin`** | In / Not In | Çoklu hesap numaralandırma ve yetkisiz veri kümesi çekme. |
| **`$exists`** | Field Exists | Şema dışı gizli alanları veya token varlığını brute-force ile keşfeder. |
| **`.` (Nokta)** | Dot Notation / Path Pollution | Gömülü nesne yollarını manipüle ederek (`profile.is_admin: true`) yetki denetimlerini atlatır. |

---

## 3. ORM Güvenlik Sınırları ve Mass Assignment (Kütlesel Atama)

### 3.1 Kütlesel Atama (Over-Posting) Nedir?
Modern MVC ve API çatılarında (Spring Boot, ASP.NET Core, Ruby on Rails, Django REST Framework, NestJS vb.) geliştirici kolaylık olsun diye HTTP istek gövdesini doğrudan veritabanı modeline bağlar (binding).

```python
# ZAFİYETLİ ORM GÜNCELLEMESİ:
@app.route("/api/user/profile", methods=["PUT"])
def update_profile():
    user = db.session.query(User).filter_by(id=current_user.id).first()
    data = request.get_json()
    
    # Tüm alanları sorgulamadan modele kopyalıyor!
    for key, value in data.items():
        setattr(user, key, value)
    db.session.commit()
```

Kullanıcı arayüzünde sadece `full_name` ve `email` alanları bulunabilir. Fakat saldırgan HTTP isteğinde fazladan alanlar ekler:
```json
{
  "full_name": "Saldırgan Kullanıcı",
  "is_admin": true,
  "role": "SUPERADMIN",
  "balance": 999999.00
}
```
Eğer modelde bu alanlar kısıtlanmamışsa veya DTO (Data Transfer Object) filtresi yoksa, saldırgan kendi hesabını saniyeler içinde sistem yöneticisi yapar veya hesabına para yükler!

### 3.2 ORM'lerin Savunmasız Kaldığı Diğer Kritik Noktalar
1. **Ham SQL İfadeleri (Raw SQL Fragments):** Birçok ORM, `where("id = " + user_input)` veya Django `extra(where=["..."])` gibi ham metin fonksiyonlarına izin verir. ORM kullanmak ham SQL yazıldığında koruma sağlamaz.
2. **HQL / JPQL / GraphQL Enjeksiyonu:** Hibernate veya GraphQL sorgularında dinamik string birleştirme yapılırsa SQL injection türevi HQL/JPQL injection meydana gelir.
3. **N+1 Sorgu ve Kaynak Tüketimi DoS:** Kötü niyetli kullanıcılar karmaşık ilişkileri tetikleyen REST/GraphQL sorguları atarak veritabanında on binlerce alt sorgu oluşturabilir.

---

## 4. Savunma Stratejisi: Usta Reçetesi

### 4.1 Reçete 1: Katı Tip Denetimi (Strict Type Enforcement)
NoSQL'de kimlik doğrulama veya arama filtreleri KESİNLİKLE dize (`str`) veya sayı (`int`) gibi skaler ilkel tipler olmalıdır. İstemciden gelen değer bir nesne/sözlük (`dict`) ise istek derhal 400 Bad Request ile reddedilmelidir.

```python
def validate_scalar(val: Any, allowed_types=(str, int, float)) -> None:
    if not isinstance(val, allowed_types):
        raise ValueError(f"Geçersiz veri tipi: {type(val)}. Yalnızca ilkel tipler kabul edilir.")
```

### 4.2 Reçete 2: BSON / Mongo Sanitization
Tüm anahtarlar taranarak `$` ile başlayan veya nokta (`.`) içeren anahtarlar temizlenmeli veya engellenmelidir (örn. Node.js `express-mongo-sanitize` veya Python özel temizleyicisi).

### 4.3 Reçete 3: DTO (Data Transfer Object) ve Katı Beyaz Liste (Allowlist)
ORM güncellemelerinde model asla doğrudan istek gövdesine maruz bırakılmaz. Her API uç noktası için yalnızca güncellenmesine izin verilen alanları tanımlayan DTO sınıfları kullanılır:

```python
# GÜVENLİ DTO YAKLAŞIMI:
class UserProfileUpdateDTO:
    ALLOWED_FIELDS = {"full_name", "email", "phone_number"}

    @classmethod
    def sanitize_payload(cls, data: dict) -> dict:
        return {k: v for k, v in data.items() if k in cls.ALLOWED_FIELDS}
```

---

## 5. Çırağa Öğütler ve Saha Deneyimi
Evlat, NoSQL ve ORM teknolojileri modern yazılımın hızını artırır ama geliştiriciyi düşünmekten alıkoymaz. Veritabanına inen her baytın tipini, sınırını ve hedefini bilmek zorundasın. Güvenlik, kütüphanelerin varsayılan ayarlarına emanet edilemeyecek kadar ciddidir!
