# GÜN 015: Soru-Cevap Odası (Derinlemesine Teknik Analiz)
**Konu:** İkili Gösterim, Bayt ve Karakter Kodlaması (Binary, Byte, Hex & UTF-8)  
**Tarih:** 2026-10-27  

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G015-SC1): İkili gösterim, byte ve karakter kodlaması: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Net ve Doğrudan Yanıt
İkili gösterim ve karakter kodlaması; fiziksel donanımdaki bit (0/1) ve bayt (8-bit) dizilimlerinin standart bir kural tablosu (ASCII, UTF-8) aracılığıyla ekrandaki metin karakterlerine dönüştürülmesidir. Bit ile bayt aynı nicelik değildir; UTF-8 değişken genişlikli bir kodlamadır ve metin boyutu karakter sayısına eşit olmayabilir. Güvenlik önemi; bu boyutsal farkın veya özel baytların (`\x00`, homoglyph) dikkate alınmamasının bellek taşması (Buffer Overflow), filtre atlatma ve kimlik avı zafiyetlerine yol açmasıdır.

#### 2. Derin Teknik Gerekçe ve Mantık
Bit ($2^1$) donanımın atomudur; bayt ($2^8$) ise 8 bitlik temel adresleme birimidir. ASCII standardında her karakter tam olarak 1 bayttır (0-127). Ancak modern dünyada kullanılan UTF-8 değişken genişliklidir (1 ila 4 bayt). Bir programlama dili veya işletim sistemi karakter sayısı (`len`) üzerinden sabit tampon bellek ayırdığında, örneğin Türkçe veya emojili bir girdi geldiğinde bayt boyutu karakter sayısının 2 ila 4 katına çıkabilir. Bu durum tampon belleğin taşmasına (Buffer Overflow) veya kesilmesine (Truncation) neden olur. Ayrıca C tabanlı işletim sistemi çekirdekleri metinlerin sonunu `\x00` (Null Byte) ile algıladığından, araya sıkıştırılan null baytlar dosya uzantısı denetimlerini veya yetkilendirme kontrollerini felç edebilir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En ölümcül hata; "1 karakter = 1 bayttır" ezberidir. Bu ezber 1980'lerde kalmıştır. Günümüzde UTF-8 varsayılandır ve tek bir emoji bellekte 4 bayt yer kaplar. Bir diğer hata, `len(str)` çıktısını bellek tahsisinde (`malloc`) doğrudan kullanmaktır.

#### 4. Resmî Standart ve Kaynak
- **The Unicode Standard, Version 15.0:** *Section 3.9: Unicode Encoding Forms (UTF-8, UTF-16, UTF-32)*.
- **IETF RFC 3629:** *UTF-8, a transformation format of ISO 10646*.
- **Microsoft Learn Security:** *Security Considerations: International Features & Character Encodings*.

---

### Soru 2 (G015-SC2): İkili gösterim, byte ve karakter kodlaması: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Net ve Doğrudan Yanıt
Laboratuvarın girdisi; standart ASCII, çok baytlı Türkçe, emojili ve zararlı enjeksiyonlu metin örneklerini içeren veri tabanıdır (`karakter_kodlama_ornekleri.json`). İşlemi; metinlerin her bir karakterinin Unicode kod noktası, UTF-8 baytları ve hex dump dökümünün çıkarılması, bayt-karakter uyumsuzluklarının tespiti ve güvenlik denetimidir. Beklenen sonucu; saf ASCII metinde karakter/bayt eşitliğinin (1:1) doğrulanması, çok baytlı girdilerde genişlemenin raporlanmasıdır. Negatif kontrolü ise; Null Byte (`\x00`) enjeksiyonunun, Homoglyph aldatmacasının ve "Yönetici iznini otomatik güvenli sayma" yanılgısının tespit edilip cezalandırılmasıdır.

#### 2. Derin Teknik Gerekçe ve Mantık
Laboratuvar motoru (`binary_byte_encoding_inspector.py`), girdileri hiçbir dış ağa bağlanmadan yerel sistemde bayt bayt inceler. Pozitif akışta, `SAMPLE-01-ASCII-STANDARD` örneğinde 23 karakterin tam 23 bayt kapladığı ve 100 tam puan aldığı teyit edilir. Negatif kontrollerde ise:
1. `SAMPLE-04-NULL-BYTE-ATTACK` örneğinde metin içindeki `\x00` C sonlandırıcısı yakalanır ve `VULN-01-NULL-BYTE-INJECTION` felaket uyarısıyla 40 puan kırılır.
2. `SAMPLE-05-HOMOGLYPH-SPOOF` örneğinde Kiril 'а' ile Latin 'a' karışımı saptanır ve `VULN-03-HOMOGLYPH-SPOOFING` raporlanır.
3. Yönetici (root/admin) hakkı açıkken dahi bu açıkların devam ettiği doğrulanarak idari yanılgı bertaraf edilir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
Yalnızca pozitif test yapıp "metin ekrana basıldı, bir sorun yok" demek, karakter kodlamasının güvenlik boyutunu ıskalamaktır. Güvenlik analisti ekrandaki çizime değil, bellekteki ikili bayt dizilimine bakar.

#### 4. Resmî Standart ve Kaynak
- **NIST SP 800-53 Rev. 5:** *SI-10: Information Input Validation (Karakter kümesi ve kodlama doğrulama şartı)*.
- **OWASP Top 10:** *A03:2021-Injection (Null Byte Injection ve Canonicalization Flaws)*.

---

### Soru 3 (G015-SC3): 'İkili gösterim, byte ve karakter kodlaması' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Net ve Doğrudan Yanıt
Risk; sistemin veya yazılımın değişken genişlikli karakterleri sabit boyutlu belleğe yazmaya çalışması, kodlamalar arası kanonikleştirme yapmaması ve yönetici yetkisine güvenerek girdi doğrulamasını atlamasıyla oluşur. Tespit; hex dump incelemeleri, metin içindeki `\x00` kontrol karakteri taramaları, Unicode script analizi (karışık alfabe) ve tampon taşması fuzzer testleriyle yapılır. Önleme ise; Unicode normalizasyonu (NFC/NFKC), bayt bazlı bellek tahsisi, sıkı giriş doğrulama (whitelist) ve en az ayrıcalık (PoLP) ilkeleriyle sağlanır.

#### 2. Derin Teknik Gerekçe ve Mantık
- **Risk Mekanizması:** Bir saldırgan, sistemin girdi denetim katmanı (WAF/Validation) ile arka uç işletim sistemi çekirdeği arasındaki kodlama yorumlama farklarını (impedance mismatch) istismar eder. Örneğin bir WAF girdiyi UTF-8 olarak okuyup izin verirken, arka uç C servisi Null Byte ile metni sonlandırabilir veya overlong UTF-8 (`%c0%af`) ile dizin geçişi (`../`) filtresini atlatabilir.
- **Tespit Mekanizması:**
  - *Hex Dump & Binary Denetim:* Verilerin ham bayt seviyesinde `hexdump -C` veya `xxd` ile incelenmesi; `0x00` veya `0xC0 0xAF` gibi anomali baytlarının aranması.
  - *Script Mismatch Analizi:* URL veya kullanıcı adı alanlarında Latin ve Kiril alfabelerinin aynı kelimede yer almasının tespiti.
- **Önleme Kontrolleri:**
  - *Kanonikleştirme (Canonicalization):* Girdi işlenmeden önce tek bir güvenli kodlama standardına (UTF-8 NFC) zorlanır.
  - *Girdi Doğrulama:* Yalnızca beklenen karakter kümesine (örn: `[a-zA-Z0-9_-]`) izin veren katı beyaz liste uygulanır.
  - *Yönetici Yanılgısını Kırmak:* İşlemin root yetkisinde olması girdi kontrolünü gereksiz kılmaz; aksine root yetkisindeki bellek taşması tüm sistemi ele geçirtir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En büyük yanılgı; "Yönetici iznini otomatik olarak güvenli davranış saymaktır." Bir işlem root veya administrator yetkisiyle çalışıyorsa, oraya gönderilen zararlı kodlanmış bir bayt dizisi işletim sistemini çok daha derin bir çöküşe (kernel panic / privilege escalation) sürükler. Güvenlik, yetkide değil; verinin doğruluğunda başlar.

#### 4. Resmî Standart ve Kaynak
- **CWE-172:** *Encoding Error*.
- **CWE-626:** *Null Byte Interaction Error (Null Byte Injection)*.
- **CWE-176:** *Improper Handling of Unicode Encoding*.
- **Unicode Technical Report #36:** *Unicode Security Considerations*.
