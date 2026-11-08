# Gün 164: CSRF ve Oturum Bağlamı — Usta-Çırak Derinlemesine Teknik Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Usta Girişi: "Tarayıcının Kör Sadakati ve Ortam Yetkisi (Ambient Authority)"

Evlat, Siteler Arası İstek Sahteciliği (Cross-Site Request Forgery - CSRF / CWE-352), web güvenliğinin en sinsi zafiyetlerinden biridir. Neden sinsi bilir misin? Çünkü saldırgan kurbanın parolasını çalmaz, veritabanına sızmaz, sunucuyu hacklemez. Saldırgan, **tarayıcının doğuştan gelen mimari bir davranışını** istismar eder: **Ortam Yetkisi (Ambient Authority)**.

Nedir bu ortam yetkisi?
Sen bir bankaya, e-ticaret sitesine veya kurumsal portala giriş yaptığında, sunucu tarayıcına bir oturum çerezi (`session_id`) verir. Tarayıcı der ki:
> *"Ben bu alan adına (domain) ait her HTTP isteğinde bu çerezi otomatik olarak paketin içine koyarım."*

İşte facia burada başlar evlat! Tarayıcı o isteğin kullanıcının kendi rızasıyla tıkladığı bir butondan mı, yoksa arka planda gizlice açılan `evil-attacker.site` üzerindeki bir gizli `<form>` veya `<img>` etiketinden mi kaynaklandığını ayırt edemez! Tarayıcının gözünde istek meşrudur; çünkü çerez vardır. Sunucunun gözünde istek meşrudur; çünkü çerez vardır. Ama kullanıcının ruhu bile duymaz!

Bugün bu derste CSRF'in kök nedenini, oturum bağlamı (session context) ile işlem yetkilendirmesi arasındaki farkı ve kurumsal savunma kalkanlarını adım adım inşa edeceğiz.

---

## 2. CSRF Saldırısının Anatomisi ve Vektörleri

### 2.1 Vektör 1: Durum Değiştiren GET İstekleri (Görsel ve Link Saldırısı)
Yazılım dünyasındaki en büyük günahlardan biri, veritabanında durum değiştiren (state-mutating) bir işlemi HTTP GET yöntemiyle gerçekleştirmektir:

```http
GET /api/transfer?target=attacker_bob&amount=1000 HTTP/1.1
Host: banka.kurum.internal
```

Saldırgan internette herkese açık bir foruma, bloga veya e-postaya şunu gömer:
```html
<img src="https://banka.kurum.internal/api/transfer?target=attacker_bob&amount=1000" width="0" height="0" />
```
Kurban bu sayfayı açtığı anda tarayıcı resmi yüklemek için bankaya GET isteği atar. Banka çerezi görür, işlemi onaylar ve 1.000 TL transfer edilir!
> **Usta Kuralı 1:** HTTP standardı (RFC 7231) gereğince GET, HEAD, OPTIONS metotları **KESİNLİKLE GÜVENLİ (Safe & Idempotent)** olmak zorundadır. Asla durum değiştiremez!

### 2.2 Vektör 2: Gizli Otomatik Gönderilen POST Formları
Uygulama GET yerine POST kullansa bile, saldırgan kendi sitesine gizli bir HTML formu yerleştirir:

```html
<!-- evil-attacker.site/malicious.html -->
<form id="csrfForm" action="https://banka.kurum.internal/api/transfer" method="POST">
  <input type="hidden" name="target_account" value="3" />
  <input type="hidden" name="amount" value="5000" />
</form>
<script>
  document.getElementById('csrfForm').submit();
</script>
```
Kurban bu sayfayı ziyaret ettiği milisaniyede form otomatik submit edilir. Tarayıcı `banka.kurum.internal` etki alanına POST atarken kurbanın oturum çerezini isteğe ekler.

---

## 3. Kurumsal Savunma Mekanizmaları

### 3.1 Synchronizer Token Pattern (STP) — Standart Kalkan
CSRF'e karşı altın standarttır. Mantığı şudur:
Oturum açıldığında sunucu oturuma özel, tahmin edilemez, kriptografik bir sır üretir (`csrf_secret`). Her form veya durum değiştiren istek için bu sırdan türetilen bir belirteç (Anti-CSRF Token) sayfaya gömülür.

Saldırgan `evil-attacker.site` üzerinden istek tetikleyebilir; ancak **Aynı Köken İlkesi (Same-Origin Policy - SOP)** nedeniyle kurbanın banka sayfasındaki gizli Anti-CSRF belirtecini OKUYAMAZ! İstekte bu belirteç bulunmadığı veya geçersiz olduğu için sunucu isteği 403 Forbidden ile reddeder.

#### Kriptografik Belirteç Mimarisi:
```
Token = <session_id>.<timestamp>.<nonce>.<HMAC-SHA256(Secret, SessionID + TS + Nonce)>
```
1. **Oturum Bağlantısı:** Başka bir kullanıcının token'ı kurbana karşı kullanılamaz.
2. **TTL (Zaman Sınırı):** Belirtecin süresi (örn. 30 dakika) bittiğinde geçersiz kalır.
3. **Tek Kullanımlık Nonce:** Token kullanıldığı anda kara listeye alınarak Replay (yeniden oynatma) saldırıları önlenir.

### 3.2 SameSite Çerez Özniteliği: Derinlemesine Ayrım
SameSite, modern tarayıcılarda çerezlerin siteler arası (cross-site) isteklerde gönderilip gönderilmeyeceğini belirleyen çerez özniteliğidir.

| SameSite Modu | Davranış | CSRF Koruması |
| :--- | :--- | :---: |
| **`SameSite=Strict`** | Çerez SADECE istek aynı siteden başlıyorsa gönderilir. Dış bir bağlantıya tıklandığında bile çerez gitmez. | **TAM KORUMA** |
| **`SameSite=Lax`** | Dış siteden başlatılan POST, PUT, DELETE isteklerinde çerez GİTMEZ. Ancak üst düzey güvenli GET gezintilerinde (bağlantıya tıklama) çerez gider. | **POST İÇİN KORUR, STATE-CHANGING GET'TE KORUMAZ** |
| **`SameSite=None`** | Çerez tüm siteler arası isteklerde iletilir (`Secure` bayrağı zorunludur). | **KORUMA YOK** |

> **Kritik Usta Tuzağı:** "Nasılsa tarayıcılar varsayılan olarak `SameSite=Lax` yapıyor, CSRF bitti!" demek cehalettir!
> 1. Eski tarayıcılar SameSite desteklemez.
> 2. Sistemde hatalı bir durum değiştiren GET uç noktası varsa Lax bunu KORUYAMAZ.
> 3. "Lax + POST" 2 dakikalık penceresi (Chrome Lax-allowing-unsafe bug/behavior) istismar edilebilir.

### 3.3 Origin ve Referer Başlığı Doğrulaması
Sunucu, durum değiştiren POST isteklerinde HTTP `Origin` ve `Referer` başlıklarını denetler.
- `Origin: https://evil-attacker.site` geldiğinde, kurumsal beyaz listeyle (`https://banka.kurum.internal`) eşleşmediği an istek derhal 403 ile düşürülür.
- `Origin: null` (sandbox iframe veya data URL) kesinlikle reddedilmelidir.

### 3.4 Step-Up Authentication (Yeniden Kimlik Doğrulama)
Evlat, savunma derinliği (Defense-in-Depth) ilkesi gereğince kritik işlemlerde (örn. para transferi >= 5.000 TL, parola/e-posta değiştirme) sadece token'a güvenilmez. Kullanıcının son 5 dakika içinde parolasını veya SMS/TOTP kodunu girmiş olması şart koşulur. Bu sayede tüm CSRF filtreleri bir şekilde atlatılsa dahi yetkisiz fon çıkışı engellenir.

---

## 4. XSS vs CSRF: Hiyerarşik Ayrım
Evlat, mülakatlarda veya sahada şu soruyu asla unutma: *"XSS mi daha tehlikeli, CSRF mi?"*
Cevap tartışmasız **XSS**'tir! Neden?
Çünkü CSRF yalnızca kullanıcının adına istek *taklidi* yapabilir; dönen cevabı okuyamaz.
Fakat sistemde bir **XSS (Cross-Site Scripting)** açığı varsa, saldırgan kurbanın tarayıcısında JavaScript çalıştırır. DOM üzerinden sayfadaki Anti-CSRF belirtecini okur (`document.querySelector('input[name="csrf"]').value`), başlığa ekler ve sunucuya meşru gibi istek atar!
**Yani XSS, tüm Anti-CSRF mekanizmalarını tek hamlede çökertebilir.**

---

## 5. Çırağa Altın Kurallar
1. Durum değiştiren hiçbir işlemi GET ile tasarlama.
2. Tüm POST, PUT, DELETE uç noktalarına `Synchronizer Token Pattern` veya `Double Submit Cookie` zorunluluğu koy.
3. Oturum çerezlerine mutlaka `HttpOnly`, `Secure` ve `SameSite=Strict` (veya `Lax`) bayraklarını ekle.
4. Origin ve Referer başlıklarını kurumsal beyaz listeyle denetle.
5. Kritik aksiyonlarda Step-up Authentication ile parolanın tekrar girilmesini iste.
