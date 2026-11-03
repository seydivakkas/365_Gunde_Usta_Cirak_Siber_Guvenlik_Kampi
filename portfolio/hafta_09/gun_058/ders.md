# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 058: HTTP Yöntemleri ve Idempotency — Metot Semantiği, FinTech Güvenliği ve Verb Tampering

## Usta-Çırak Başlangıç Hasbihali
Evladım, dünkü dersimizde HTTP mesajlarının tel formatını (wire format) ve başlık yapısını çözdük. Bugün ise web mimarisinin ve dağıtık sistemlerin en can alıcı matematiksel kavramına adım atıyoruz: **Eşgüçlülük (Idempotency)** ve **HTTP Metot Semantiği**.

Yazılım geliştiricilerin büyük bir kısmı metotları sadece birer "etiket" sanır. *"GET ile de veri silerim, POST ile de sorgu atarım, çalışıyor ya!"* derler. İşte bu cehalet, kurumsal bankacılık sistemlerinde tek bir ağ kesintisinde müşteriden 3 kez para çekilmesine (double charge), arama motoru botlarının şirketin tüm veritabanını silmesine veya tek bir HTTP `HEAD` isteğiyle güvenlik duvarlarının atlatılmasına (HTTP Verb Tampering) yol açar! Bugün seninle metotların matematiksel felsefesini, güvenli (safe) ve eşgüçlü (idempotent) ilkelerini ve finans dünyasının vazgeçilmez zırhı olan **Idempotency-Key** mimarisini inşa edeceğiz.

---

## 1. Idempotency (Eşgüçlülük) Nedir? Matematiksel ve Ağ Felsefesi

Matematikte eşgüçlülük şu formülle ifade edilir:
$$f(f(x)) = f(x)$$
Yani bir operasyonu **1 kez çalıştırmak ile 1.000 kez ardı ardına çalıştırmak**, sistemin nihai durumunda tamamen aynı sonucu bırakıyorsa o işlem **eşgüçlüdür (idempotent)**.

Gerçek Hayat Analojisi:
- **Asansör Çağırma Butonu (Idempotent):** Asansörün çağırma butonuna 1 kere de bassan, sabırsızlanıp 50 kere de bassan asansör yalnızca 1 kez gelir. Sistemin nihai durumu değişmez.
- **Banka Para Çekme Butonu (Non-Idempotent):** "200 TL Çek" butonuna 1 kez basarsan 200 TL eksilir; butona 3 kez basarsan 600 TL eksilir. Her basış sistem durumunu değiştirir!

---

## 2. HTTP Metotlarının Semantik Ayrımı (RFC 7231 ve RFC 5789)

Bir HTTP metodunun karakterini iki temel soru belirler:
1. **Güvenli (Safe) mi?** Sunucuda hiçbir kalıcı durum değişikliği yapmaz mı? (Read-only)
2. **Eşgüçlü (Idempotent) mi?** Ağ kopması durumunda istemci aynı isteği güvenle tekrar gönderebilir mi?

| Metot | Güvenli (Safe)? | Eşgüçlü (Idempotent)? | RFC Referansı | Açıklama ve Davranış |
|---|---|---|---|---|
| **GET** | **EVET** | **EVET** | RFC 7231 §4.3.1 | Yalnızca bilgi sorgular. 10 kez çağrılsa da sunucuda bakiye düşmez, kayıt silinmez. |
| **HEAD** | **EVET** | **EVET** | RFC 7231 §4.3.2 | GET ile tamamen aynıdır, yalnızca yanıt gövdesi (body) dönmez. Başlık kontrolü içindir. |
| **PUT** | **HAYIR** | **EVET** | RFC 7231 §4.3.4 | Belirtilen URI'deki kaynağı **tamamen yeni temsil ile değiştirir**. Aynı veriyle 10 kez PUT atsan da kaynak aynı kalır. |
| **DELETE**| **HAYIR** | **EVET** | RFC 7231 §4.3.5 | Kaynağı siler. İlk çağrıda kaynak silinir (`204 No Content`); sonraki çağrılarda kaynak zaten yoktur (`404 Not Found`). Ancak nihai durum (kaynağın silinmiş olması) değişmez! |
| **OPTIONS**| **EVET** | **EVET** | RFC 7231 §4.3.7 | Sunucunun desteklediği yetenekleri ve CORS kurallarını sorgular. |
| **POST** | **HAYIR** | **HAYIR** | RFC 7231 §4.3.3 | Yeni bir kayıt üretir veya işlem tetikler. Tekrarı halinde mükerrer sipariş veya çift çekim oluşturur. |
| **PATCH** | **HAYIR** | **HAYIR (Genellikle)**| RFC 5789 | Kaynağa kısmi güncelleme uygular (JSON Patch / Merge Patch). Sayacı 1 artıran bir patch işlemi eşgüçlü değildir! |
| **TRACE** | **EVET (Tehlikeli)**| **EVET** | RFC 7231 §4.3.8 | İstek mesajını geri yankılar. **XST (Cross-Site Tracing)** saldırısına açıktır, kapatılmalıdır. |

### PUT ve PATCH Arasındaki Kritik Fark
- **PUT:** Kaynağın tamamını ezerek yazar (Tam Değiştirme). İstemci tüm nesneyi (`name`, `role`, `email`) göndermek zorundadır. Eşgüçlüdür.
- **PATCH:** Kaynağın sadece değişen parçalarını günceller (Kısmi Değiştirme). İstemci sadece `{"role": "Lead"}` gönderebilir. Eğer işlem `{"$inc": {"balance": -50}}` gibi bağıl bir operasyonsa eşgüçlü değildir!

---

## 3. Dağıtık Finans Sistemlerinde Idempotency-Key Deseni

İnternet doğası gereği güvenilmezdir (unreliable network). Bir kullanıcı mobil bankacılıkta "500 TL Gönder" dediğinde akış şöyle gerçekleşebilir:
1. İstemci `POST /payments` isteğini gönderir.
2. Banka sunucusu 500 TL'yi hesaptan düşer ve veritabanına yazar.
3. Tam banka sunucusu `201 Created` yanıtını dönerken mobil baz istasyonu kopar!
4. Kullanıcının telefonu yanıtı alamaz ve zaman aşımına (Timeout) uğrar.
5. Kullanıcı ekranda hata görünce butona **tekrar basar**.

Eğer sistemde **Idempotency** mekanizması yoksa, müşteriden toplamda **1.000 TL** çekilir (Çifte Çekim / Double Charge Felaketi)!

### Idempotency-Key Nasıl Çalışır? (IETF Standardı & Stripe Deseni)
İstemci her finansal veya kritik POST isteğine benzersiz bir UUID ekler:
`Idempotency-Key: e82b203c-7729-4d64-9418-2e0f4cb7331c`

Sunucu İşlem Mantığı:
1. **Anahtar Denetimi:** Sunucu gelen anahtarı önbellekte (Redis vb.) arar.
2. **İlk İstek:** Anahtar yoksa işlem çalıştırılır, bakiye düşülür, üretilen yanıt (`status_code`, `headers`, `body`) ve gelen gövdenin **SHA-256 özeti** anahtarla birlikte TTL (ör. 24 saat) ile kaydedilir.
3. **Yeniden Deneme (Replay):** Aynı anahtar tekrar gelirse;
   - Önce gövdenin SHA-256 özeti karşılaştırılır. Eğer aynıysa **kod ikinci kez ASLA çalıştırılmaz**.
   - Önbellekteki ilk yanıt, başlığına `Idempotent-Replayed: true` eklenerek anında geri dönülür!
   - Bakiye bir daha eksilmez, çifte çekim imkansız hale gelir.
4. **Gövde Çakışması (Conflict):** Eğer aynı anahtar farklı bir tutarla (ör. 500 TL yerine 1.000 TL) gelirse; sunucu derhal `409 Conflict` veya `422 Unprocessable Entity` fırlatarak işlemi durdurur!

---

## 4. Güvenlik Açığı: HTTP Verb Tampering (Metot Atlatma)

HTTP Verb Tampering, web sunucularında veya kod seviyesinde erişim denetim kurallarının (ACL) özensiz yapılandırılmasından kaynaklanır.

Örnek Güvenlik Kuralı Zaafı (Java `web.xml` veya WAF):
```xml
<!-- YANLIŞ VE ZAYIF KURAL -->
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/delete_user</url-pattern>
        <http-method>POST</http-method> <!-- HATA: Yalnızca POST korunmuş! -->
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

Saldırganın Eylemi:
Saldırgan `/admin/delete_user` adresine `POST` atınca filtre oturum sorar ve engeller. Ancak kurnaz saldırgan isteği `HEAD`, `PUT` veya `GET` olarak gönderir! Filtre yalnızca `POST` kelimesine baktığı için kuralı baypas eder; arka plandaki uygulama kodu ise gevşek yazıldığı için isteği karşılayıp kullanıcıyı siler!
- **Savunma:** Erişim denetimleri metot bazlı değil, **URL bazlı** yapılmalı ve bilinmeyen tüm metotlar varsayılan olarak reddedilmelidir (Deny-by-Default).

---

## 5. Güvenlik Açığı: GET ile Durum Değiştirme Anti-Pattern'ı

Bazı amatör yazılımcılar linklere tıklatarak işlem yaptırmak için GET kullanır:
`GET /account/transfer?to=attacker&amount=1000 HTTP/1.1`

Neden Korkunç Bir Zafiyettir?
1. **Tarayıcı Ön-Yükleyicileri (Prefetching):** Google Chrome gibi modern tarayıcılar sayfadaki linkleri kullanıcı tıklamadan önce arka planda hızlı açılsın diye önceden çağırır (prefetch). Kullanıcı tıklamadan parası gider!
2. **Arama Motoru Botları (Crawlers):** Google botu siteyi tararken bu linki tıklar ve tüm hesapları boşaltır veya veritabanını siler!
3. **Sıfır Etkileşimli CSRF:** Saldırgan herhangi bir foruma `<img src="https://banka.com/transfer?amount=1000">` koyar. Forumu gezen her kullanıcının tarayıcısı otomatik GET isteği atar ve herkes hacklenir!

---

## Ustanın Öğüdü
Evladım; HTTP metotları sadece birer istek kelimesi değildir; web protokolünün anayasasıdır. GET metoduna veri sildiren bir yazılımcı da, ödeme API'sine `Idempotency-Key` koymayan bir mimar da eninde sonunda kurumu milyonlarca liralık zarara uğratır. Metot semantiğine saygı duymayan, ağın fiziksel doğasına saygı duymamış demektir!
