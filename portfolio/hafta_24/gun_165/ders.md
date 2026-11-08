# Gün 165: CORS ile Güvenlik Sınırı — Usta-Çırak Derinlemesine Teknik Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Usta Girişi: "CORS Bir Güvenlik Duvarı Değildir!"

Evlat, web güvenliği mülakatlarında ve saha denetimlerinde en sık karşılaştığım ölümcül yanılgı şudur: Geliştiriciye sorarsın: *"CORS nedir?"*
Geliştirici cevap verir: *"Hocam, CORS sitemize dışarıdan saldırı gelmesini engelleyen bir güvenlik mekanizmasıdır."*

İşte bu cevap, bir siber güvenlik uzmanının kulağını tırmalayan en büyük cehalettir!
İyi dinle evlat: **CORS (Cross-Origin Resource Sharing), bir güvenlik duvarı DEĞİLDİR!**
Tam tersine, CORS tarayıcının en temel güvenlik kalkanı olan **Aynı Köken İlkesi'ni (Same-Origin Policy - SOP) DELMEK ve ESNETMEK için icat edilmiş bir izin mekanizmasıdır!**

Varsayılan durumda SOP ne yapar?
Sen `evil-attacker.com` sitesindeyken, o sitedeki JavaScript kodu `fetch("https://banka.kurum.internal/api/bakiye")` çağrısı yaparsa tarayıcı der ki:
> *"Dur bakalım! Sen evil-attacker.com kökenindesin, banka.kurum.internal kökenine ait bir yanıtı JavaScript ile OKUYAMAZSIN!"*

İşte CORS; banka sunucusunun tarayıcıya:
> *"Ey tarayıcı, ben `https://portal.kurum.internal` kökenini tanıyorum; benim döndüğüm yanıtı onun JavaScript koduna okutabilirsin!"*
demesini sağlayan HTTP başlıkları bütünüdür.

Eğer sen bu başlıkları yanlış yapılandırırsan, SOP'un sağladığı o devasa güvenlik kalkanını ellerinle parçalamış olursun!

---

## 2. CORS Anatomisi ve Preflight (Uçuş Öncesi) Kontrolü

### 2.1 Basit İstekler (Simple Requests) vs Preflight Gerektiren İstekler
Tarayıcı her istekte sunucuya sormaz. HTTP standardı istekleri ikiye ayırır:

1. **Basit İstekler (Simple Requests):**
   - Yöntem: Sadece `GET`, `HEAD`, `POST`.
   - Başlıklar: Yalnızca standart tarayıcı başlıkları (`Accept`, `Accept-Language`, `Content-Language`).
   - `Content-Type`: Yalnızca `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`.
   - *Davranış:* Tarayıcı doğrudan isteği gönderir; ancak dönen yanıtta geçerli bir `Access-Control-Allow-Origin` (ACAO) başlığı yoksa yanıt gövdesini JavaScript'e teslim etmez, hata fırlatır.

2. **Preflight Gerektiren İstekler (Karmaşık İstekler):**
   - Yöntem: `PUT`, `DELETE`, `PATCH` gibi durum değiştiren metotlar.
   - `Content-Type`: Modern API'lerin vazgeçilmezi olan `application/json`.
   - Özel Başlıklar: `Authorization: Bearer ...`, `X-CSRF-Token`, `X-Requested-With`.
   - *Davranış:* Tarayıcı asıl isteği atmadan önce sunucuya bir ön keşif uçuşu yapar: **HTTP OPTIONS** isteği gönderir!
     ```http
     OPTIONS /api/transfer HTTP/1.1
     Host: banka.kurum.internal
     Origin: https://portal.kurum.internal
     Access-Control-Request-Method: POST
     Access-Control-Request-Headers: content-type, authorization
     ```
   - Sunucu bu isteğe `204 No Content` ve izin başlıklarıyla (`Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age`) onay verirse tarayıcı asıl POST isteğini gönderir.

---

## 3. Sahada En Sık Görülen Tehlikeli CORS Yanlış Yapılandırmaları (Misconfigurations)

### 3.1 Zafiyet 1: Arbitrary Origin Reflection (Körlemesine Origin Yansıtma)
Modern web çatılarında frontend farklı domainde (`app.sirket.com`), backend farklı domaindedir (`api.sirket.com`).
Geliştirici konsolda CORS hatası görünce internette arama yapar. Bir forumda şunu görür ve backend koduna yazar:

```python
# ÖLÜMCÜL ZAFİYETLİ KOD:
origin = request.headers.get("Origin")
response.headers["Access-Control-Allow-Origin"] = origin  # Gelen her Origin'i yansıtıyor!
response.headers["Access-Control-Allow-Credentials"] = "true"  # Oturum çerezlerine izin veriyor!
```

**Saldırı Senaryosu:**
Saldırgan kurbanı `evil-attacker.com` sayfasına çeker. Sayfadaki JS kodu:
```javascript
fetch("https://api.sirket.com/api/kullanici/profil", { credentials: "include" })
  .then(r => r.json())
  .then(data => sızdır(data));
```
Sunucu isteği alır, `Origin: https://evil-attacker.com` başlığını görür. Geliştiricinin kodu bunu doğrudan ACAO başlığına yazar:
`Access-Control-Allow-Origin: https://evil-attacker.com`
`Access-Control-Allow-Credentials: true`

Tarayıcı bu yanıtı görünce der ki: *"Sunucu bu saldırgan siteye izin vermiş, buyur JavaScript kardeşim tüm profil verisi senin!"*
Kurbanın tüm özel verileri, API anahtarları, finansal raporları tek satır kodla çalınır!

### 3.2 Zafiyet 2: `null` Origin'e Güvenilmesi
Birçok sunucu yapılandırmasında `if origin == "null": allow()` şeklinde bir mantık bulunur.
Geliştirici bunu local dosyalar (`file://`) veya test amaçlı ekler.
Oysa bir saldırgan hedef siteye doğrudan istek atmak yerine isteği **sandbox bir iframe** (`<iframe sandbox="allow-scripts allow-top-navigation" src="...">`) içinden tetiklerse veya `data:` URI kullanırsa tarayıcı isteğin `Origin` başlığını otomatik olarak `null` yapar!
Sunucu `null` kökene izin veriyorsa, saldırgan iframe içinden tüm API verisini okur!

### 3.3 Zafiyet 3: Gevşek Regex Eşleşmesi (Subdomain Prefix/Suffix & Unescaped Dot)
Geliştirici `*.kurum.internal` alt alan adlarına izin vermek ister ama regex'i yanlış yazar:

1. **Ön Ek / Son Ek Atlatması:**
   - Regex: `portal\.kurum\.internal` (Başında `^` ve sonunda `$` yok!).
   - Saldırgan şu domainleri alır:
     - `https://evil-portal.kurum.internal` (Ön ek bypassı)
     - `https://portal.kurum.internal.evil-attacker.com` (Son ek bypassı)
   - Regex her iki saldırgan domaini de onaylar!

2. **Kaçılmamış Nokta (`.`):**
   - Regex: `^https://portal.kurum.internal$`
   - Düzenli ifadelerde nokta (`.`) "herhangi bir karakter" demektir!
   - Saldırgan `https://portalxkurumxinternal` veya `https://portal-kurum-internal` domainini satın alır ve regex'i aşar!

### 3.4 Zafiyet 4: Önbellek Zehirlenmesi (Missing `Vary: Origin`)
Eğer sunucu gelen kökene göre dinamik ACAO başlığı üretiyorsa ve yanıta `Vary: Origin` başlığı eklemezse; aradaki CDN veya ters vekil sunucu (Reverse Proxy) saldırganın isteğine verilen `ACAO: evil.com` yanıtını önbelleğe alır.
Ardından meşru kullanıcı siteye girdiğinde CDN önbellekten saldırgana ait başlığı servis eder; site kilitlenir veya veriler sızar!

---

## 4. Kurumsal Güvenli CORS Mimarisi: Usta Reçetesi

### 4.1 Reçete 1: Katı Beyaz Liste (Exact Allowlist Matching)
Kökenler regex ile değil, tam şema, ana makine ve port içeren katı bir küme (`Set`) ile karşılaştırılmalıdır:

```python
ALLOWED_ORIGINS = {
    "https://portal.kurum.internal",
    "https://mobil.kurum.internal",
    "https://yonetim.kurum.internal:8443"
}

def handle_cors(origin: str):
    norm_origin = normalize(origin)
    if norm_origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = norm_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    else:
        # ASLA ACAO DÖNME! İsteği reddet veya CORS başlığı verme.
        return 403
```

### 4.2 Reçete 2: Asla `null` veya `*` ile Credentials Kullanma
- `Access-Control-Allow-Origin: *` ile `Access-Control-Allow-Credentials: true` kombinasyonu HTTP standardında kesinlikle yasaktır (Tarayıcı engeller).
- `null` kökene hiçbir şart altında izin verilmemelidir.

### 4.3 Reçete 3: Preflight Önbelleğini Sınırla
`Access-Control-Max-Age` süresini makul bir değerde (örn. 1 saat - 24 saat) tutarak istemcinin gereksiz OPTIONS istekleriyle sunucuyu yormasını engelle; ancak politika değişikliklerinin de hızla yansımasını sağla.

---

## 5. Çırağa Altın Kurallar
1. CORS'u güvenlik duvarı sanma; o bir kapı aralığıdır, ne kadar dar açarsan o kadar güvendesin.
2. Gelen Origin'i asla körlemesine geri yansıtma.
3. `null` kökene asla güvenme.
4. Regex yerine tam dize eşitliği (Allowlist) kullan.
5. Dinamik CORS başlıklarına DAİMA `Vary: Origin` ekle.
