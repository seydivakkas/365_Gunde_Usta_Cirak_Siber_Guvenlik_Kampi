# Hafta 23 / Gün 159: Girdi Doğrulama ve Çıktı Kodlama

## Usta-Çırak / Hoca Dersi Notları

> **Usta:** *"Evladım, siber güvenlik dünyasında en çok duyacağın ama en çok yanlış uygulanan kural şudur: 'Kullanıcı girdisine asla güvenme!' Çoğu yazılımcı bu kuralı duyunca hemen bir kara liste (Blocklist) yazar; `<script>` kelimesini veya `' OR 1=1` ifadesini silmeye çalışır. Bu, fırtınada şemsiyeyi ters tutmaktan farksızdır! Saldırgan `%253Cscript` yazar, `s<script>cript` yazar veya çift URL kodlaması yapar, o filtreyi delik deşik eder. Gerçek güvenlik; girdi kapıda içeri girerken **Pozitif İzin Listesi (Allowlist)** ile doğrulanır, kapıdan çıkıp ekrana veya veritabanına giderken ise **Bağlama Duyarlı Çıktı Kodlama (Context-Aware Encoding)** ile etkisiz hale getirilir."*
>
> **Çırak:** *"Ustamm, 'Girdi Doğrulama' (Input Validation) ile 'Çıktı Kodlama' (Output Encoding) arasındaki kesin sınır nedir? Neden yalnızca girdi doğrulama yapmak XSS veya SQLi'yi tamamen önlemeye yetmez?"*
>
> **Usta:** *"Bak evlat, bu iki kavram birbirinin alternatifi değil, birbirini tamamlayan iki çelik kalkandır:
> 1. **Girdi Doğrulama:** Veri güven sınırından (Trust Boundary) içeri girerken uygulanır. Amacı, verinin beklenen iş mantığına (Business Logic), biçime, tipe ve uzunluğa uygun olup olmadığını denetlemektir. 'Bu yaş alanı tam sayı mı?', 'Bu e-posta adresi RFC standardında mı?' diye sorar.
> 2. **Çıktı Kodlama:** Veri sistemden çıkıp bir yorumlayıcıya (Browser HTML motoru, JavaScript motoru, SQL motoru, Komut kabuğu) gönderilirken uygulanır. Amacı, verinin yorumlayıcı tarafından 'kod' (executable syntax) olarak değil, yalnızca 'veri' (passive data) olarak algılanmasını sağlamaktır. Bugün seninle bu iki savunma hattını birleştiren kurumsal bir boru hattı inşa edeceğiz."*

---

## 1. Çift Savunma Hattı Mimarisi

Bir web uygulamasına gelen verinin geçtiği aşamalar ve savunma mekanizmaları:

```
[ GÜVENİLMEYEN İSTEMCİ GİRDİSİ ] (Query Param, POST Body, Headers)
                |
                v
 +-------------------------------------------------------------------+
 | 1. KANONİKLEŞTİRME (Canonicalization)                             |
 |    - Çift URL Kodlamasını Çözme (%252e%252e%252f -> ../)          |
 |    - Unicode NFKC Normalizasyonu (Homoglyph karakterleri çözme)   |
 |    - Null Byte (\x00, %00) Temizliği                              |
 +-------------------------------------------------------------------+
                |
                v
 +-------------------------------------------------------------------+
 | 2. GİRDİ DOĞRULAMA (Input Validation - Allowlist)                 |
 |    - Pozitif Model: Sadece izin verilen karakter kümesi (Regex)  |
 |    - Tip, Format ve Uzunluk Kısıtlamaları (Min/Max Length)        |
 |    - Bilinen Tehdit İmzası Taraması (SQLi, XSS, Path Traversal)   |
 +-------------------------------------------------------------------+
                |
                v (Geçerliyse Sisteme Alınır)
 +-------------------------------------------------------------------+
 | 3. İÇ İŞLEME & VERİTABANI DEPOLAMA                                |
 |    - Veritabanına yazarken: Parametreli Sorgu (Prepared Statement)|
 +-------------------------------------------------------------------+
                |
                v (İstemciye Sunulurken)
 +-------------------------------------------------------------------+
 | 4. BAĞLAMA DUYARLI ÇIKTI KODLAMA (Context-Aware Output Encoding)   |
 |    - HTML Body Bağlamı        --> &lt;script&gt;                  |
 |    - HTML Attribute Bağlamı   --> &#x22; (Hex Entity)             |
 |    - JavaScript Değişkeni     --> \u0027 (Unicode Escape)         |
 |    - URL Parametresi          --> %20, %26 (Percent Encoding)     |
 +-------------------------------------------------------------------+
                |
                v
 [ TARAYICI / YORUMLAYICI ] (Veri Asla Kod Olarak Çalışamaz!)
```

---

## 2. Derinlemesine Teknik Mekanizmalar

### 1. Kanonikleştirme (Canonicalization / Normalization)
Saldırganlar güvenlik filtrelerini atlatmak için veriyi alternatif formlarda (URL encode, hex, unicode) kodlarlar.
- **Çift Kodlama (Double Encoding):** Saldırgan `../` yerine `%252e%252e%252f` gönderir. Zayıf filtre ilk turda `%2e%2e%2f` görür ve zararsız sanır. Ancak backend sunucu bu veriyi ikinci kez çözdüğünde dizin geçişi gerçekleşir.
- **Çözüm:** Veri herhangi bir doğrulama kuralına girmeden önce `canonicalize()` fonksiyonu ile tek bir standart forma (Kanonik form) indirgenir:
  1. Recursive URL unquoting (karakter değişmeyene kadar çözme).
  2. Unicode NFKC normalizasyonu (görsel benzeri karakterleri ASCII eşdeğerine çevirme).
  3. Null byte (`\x00`) temizliği.

### 2. Pozitif Güvenlik Modeli (Allowlist vs. Blocklist)
- **Kara Liste (Blocklist) Yanılgısı:** "Girdide `<script>` varsa sil." -> Saldırgan `<SCRIPT>`, `<sCrIpT>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>` yazar ve geçer.
- **İzin Listesi (Allowlist) Prensibi:** "Kullanıcı adı alanı yalnızca `^[a-zA-Z0-9_-]{3,30}$` desenine uyabilir. Nokta dahi içeremez!" Tanımlı kurala uymayan her şey otomatik reddedilir. Böylece bilinmeyen sıfırıncı gün (0-day) saldırıları dahi kapıda elenir.

### 3. Bağlama Duyarlı Çıktı Kodlama (Context-Aware Output Encoding - OWASP C-03)
En büyük hatalardan biri, her yerde standart HTML kaçışı (`html.escape`) kullanmaktır. Kodlama yöntemi, verinin HTML belgesinin **tam olarak neresine** basıldığına göre değişmek zorundadır:

#### A. HTML Gövdesi Bağlamı (HTML Body Context)
- Konum: `<div>KULLANICI_VERISI</div>` veya `<p>KULLANICI_VERISI</p>`
- Tehdit: Saldırgan yeni bir HTML etiketi (`<script>`) açabilir.
- Kodlama:
  - `&` -> `&amp;`
  - `<` -> `&lt;`
  - `>` -> `&gt;`
  - `"` -> `&quot;`
  - `'` -> `&#x27;`

#### B. HTML Öznitelik Bağlamı (HTML Attribute Context)
- Konum: `<input type="text" name="fname" value="KULLANICI_VERISI">`
- Tehdit: Saldırgan `"` tırnak karakteri ile öznitelikten çıkıp yeni bir olay yöneticisi (Event Handler) ekleyebilir: `" onfocus="alert(1)`
- Kodlama: Alfanümerik olmayan tüm karakterler `&#xHH;` hex entity olarak kodlanmalıdır (`"` -> `&#x22;`).

#### C. JavaScript Değişken Bağlamı (JavaScript Context)
- Konum: `<script>var current_user = 'KULLANICI_VERISI';</script>`
- Tehdit: Standart HTML entity kodlaması JavaScript içinde işe yaramaz! Saldırgan `'; alert(1); //` ile dizeyi kapatıp kod çalıştırabilir.
- Kodlama: Alfanümerik dışındaki karakterler `\uXXXX` formatında Unicode kaçışı ile kodlanmalıdır (`'` -> `\u0027`, `;` -> `\u003B`).

#### D. URL Parametresi Bağlamı (URL Parameter Context)
- Konum: `<a href="/search?query=KULLANICI_VERISI">`
- Tehdit: Saldırgan `&` veya `#` ile parametre yapısını bozabilir veya `javascript:alert(1)` protokolü enjekte edebilir.
- Kodlama: RFC 3986 `percent-encoding` (`urllib.parse.quote_plus`).

---

## 3. Geliştirilen Engine Mimarisi

Bugün geliştirdiğimiz `InputValidatorEncoderEngine`:
- **8 Doğrulama Tipi:** `TextAlpha`, `TextAlphanumeric`, `Email`, `NumericInt`, `UuidV4`, `UrlHttpHttps`, `DateIso8601`, `SafeTextMultiline`.
- **5 Kodlama Bağlamı:** `HtmlBody`, `HtmlAttribute`, `JavaScript`, `UrlParam`, `CssString`.
- **Saldırı İmza Sensörü:** SQLi (`UNION SELECT`, `' OR 1=1`), XSS (`<script`, `javascript:`, `onerror`), Command Injection (`; rm`, `| bash`), Path Traversal (`../`) ve Null Byte (`\x00`) saldırılarını milisaniyeler içinde yakalar.

---

## Özet ve Ustanın Altın Kuralı

> *"Evladım, girdi doğrulaması senin kale kapındaki muhafızındır; içeriye yabancı almaz. Çıktı kodlaması ise içerideki muhafızındır; içeri giren misafirin eline silah (yorumlanabilir kod) vermez. İki muhafızın da görevini eksiksiz yaparsa kalen fethedilemez!"*
