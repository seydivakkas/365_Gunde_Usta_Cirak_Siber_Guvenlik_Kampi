# GÜN 076: METİN, REGEX VE KARAKTER KODLAMASI — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G076-SC1: ReDoS (CWE-1333) ve Felaket Düzeyinde Geri İzleme (Catastrophic Backtracking) Dinamikleri ve Savunması

#### Soru Başlığı ve Tanımı
Bir Web Uygulama Güvenlik Duvarı (WAF) veya girdi doğrulama katmanında kullanılan hatalı tasarlanmış bir düzenli ifade (Regex), nasıl tek bir küçük HTTP isteği ile sunucunun CPU'sunu %100'e kilitleyip hizmet dışı bırakabilir (CWE-1333: Inefficient Regular Expression Complexity / ReDoS)? Python'ın standart regex motoru bağlamında bu durumun matematiksel kök nedeni nedir ve savunmacı mimaride nasıl bertaraf edilir?

#### Derinlemesine Teknik Analiz
Python'ın `re` modülü, Perl uyumlu NFA (Nondeterministic Finite Automaton) motoru kullanır. NFA motorları, alternatifli veya tekrarlanan niteleyiciler içeren desenleri eşleştirirken olası yolları dener. Eğer bir desen içinde çakışan (overlapping) ve iç içe açgözlü (nested greedy) gruplar yer alıyorsa:

Örnek zafiyetli desen:
$$R = \text{\textasciicircum}(a+)+\$$$

Bu desende hem içerideki `a+` açgözlüdür (mümkün olduğunca çok 'a' yakalamak ister), hem de dışarıdaki `()+` açgözlüdür (bu gruplardan mümkün olduğunca çok tekrar üretmek ister).

Girdi şu olduğunda:
$$\text{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (30 karakter 'a', sonda '!')}$$

Motor en son karaktere (`!`) geldiğinde eşleşmenin başarısız olduğunu görür. Pes etmek yerine "Belki 'a' karakterlerini farklı gruplara bölseydim eşleşirdi" diyerek geriye döner (backtracking). 30 elemanlı bir dizinin gruplara bölünebileceği kombinasyon sayısı:
$$C(N) = 2^N = 2^{30} \approx 1.073.741.824 \text{ kombinasyon}$$

İşlemci 1 milyardan fazla permütasyonu denerken tek bir CPU çekirdeği tamamen kilitlenir. Girdi 50 karaktere çıktığında deneme sayısı $2^{50}$'ye ulaşır ki bu işlem normal bir sunucuda haftalarca sürebilir.

**Savunmacı Programlama Çözümleri:**
1. **Çakışan Niteleyicilerin Tasfiyesi:** İç içe açgözlü gruplar yerine atomik ve çakışmayan karakter sınıfları kullanılmalıdır (örn. `\S+` yerine `[a-zA-Z0-9]+` gibi açık ve örtüşmeyen sınırlar).
2. **Girdi Uzunluğuna Sert Tavan Konulması (Length Guard):** Bir metin regex motoruna gönderilmeden önce mutlak surette uzunluk denetiminden geçirilmelidir (`len(text) <= 4096`). ReDoS saldırıları dizenin uzamasıyla üstel patladığı için uzunluk sınırlaması riski %95 oranında önler.
3. **Katı Sınır Bağlaçları (`^` ve `$`):** Desenin başına `^` ve sonuna `$` koyarak motorun metnin ortasındaki gereksiz alt dizileri aramasını engellemek.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankanın kullanıcı kayıt servisinde e-posta doğrulaması için kullanılan regex: `^([a-zA-Z0-9_\.-]+)+@([\da-zA-Z\.-]+)\.([a-z\.]{2,6})$` şeklinde yazılmıştır. Kötü niyetli bir kullanıcı kullanıcı adı alanına `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` göndererek 10 adet paralel istek başlatmış; bankanın kimlik doğrulama sunucularının tamamı çökmüş ve internet bankacılığı 2 saat durmuştur.

**Savunmacı Çözüm Mimarisi:**
```python
import re

# 1. Girdi uzunluğu regex öncesinde sınırlandırılır
MAX_EMAIL_LEN = 254 # RFC 5321 standardı gereği

def validate_email_safe(email_str: str) -> bool:
    if not isinstance(email_str, str) or len(email_str) > MAX_EMAIL_LEN:
        return False
        
    # 2. Çakışmayan, iç içe açgözlü gruplar içermeyen savunmacı regex
    SAFE_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    
    return bool(SAFE_EMAIL_RE.match(email_str))
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, regex güçlü bir kılıçtır ama iki tarafı da keser! `(x+)+` gibi desenler yazmak, kendi sunucunun önüne bomba koyup fitili saldırganın eline vermektir. Regex yazarken her zaman kendine soracaksın: 'Eğer bu metnin sonuna eşleşmeyen bir ünlem işareti koyarsam motor geriye kaç adım atar?' Ve unutma: Girdinin boyunu sınırlandırmadan regex motoruna sokan yazılımcı, kapısını kilitlemeden tatile çıkan ev sahibine benzer!"

---

### G076-SC2: IDN Homograf (Homoglyph) Saldırıları, Unicode NFKC Kanonik Normalizasyonu ve Çoklu Alfabe (Mixed-Script) Analizi

#### Soru Başlığı ve Tanımı
Uluslararası Alan Adları (IDN - Internationalized Domain Names) standardı, alan adlarında Latin olmayan alfabelerin (Kiril, Arap, Çin vb.) kullanılmasına izin verir. Kötü niyetli bir aktör Latin harflerine görsel olarak birebir benzeyen Kiril karakterlerini kullanarak nasıl oltalama (phishing) saldırısı düzenler? Python'da `unicodedata.normalize("NFKC")` ve karakter kümesi analizi bu saldırıları nasıl tespit eder?

#### Derinlemesine Teknik Analiz
Unicode standardında görsel olarak aynı veya ayırt edilemeyecek kadar benzer görünen ancak farklı kod noktalarına (code point) sahip karakterler mevcuttur:

| Karakter | Görünüm | Unicode Kodu | Alfabe / Script |
| :--- | :---: | :---: | :---: |
| **Latin Küçük A** | a | `U+0061` | Latin |
| **Kiril Küçük A** | а | `U+0430` | Cyrillic |
| **Latin Küçük O** | o | `U+006F` | Latin |
| **Kiril Küçük O** | о | `U+043E` | Cyrillic |
| **Latin Küçük P** | p | `U+0070` | Latin |
| **Kiril Küçük P** | р | `U+0440` | Cyrillic |

Saldırgan `paypal.com` alan adını taklit etmek için `p` ve `a` harflerini Kiril alfabesinden seçer: `\u0440\u0430yp\u0430l.com`. Tarayıcının adres çubuğunda veya bir e-posta istemcisinde bu dize ekrana çizildiğinde insan gözü meşru `paypal.com` ile hiçbir fark göremez. Ancak DNS çözümleyicisi bunu Punycode formatında `xn--...` olarak çözer ve saldırganın sahte sunucusuna yönlendirir.

**Kanonik Normalizasyon ve Savunma Mekanizması:**
Unicode dört standart normalizasyon formu tanımlar:
1. **NFC (Kanonik Birleşim):** Karakterleri tek birleşik glife indirger.
2. **NFKC (Uyumluluk Birleşimi):** Farklı bağlamlardaki uyumluluk varyantlarını (örn. tam genişlikli Latin karakterler, matematiksel glifler) standart eşdeğerine dönüştürür.
3. **Script (Alfabe) Karışım Tespiti (Mixed-Script Detection):**
   Bir alan adının `.com`, `.net`, `.org` gibi genel üst seviye alan adlarında (gTLD) meşru kullanımı Latin alfabesidir. Eğer bir alan adının içinde hem Latin alfabesi (`LATIN`) hem de Kiril (`CYRILLIC`) veya Yunan (`GREEK`) karakterleri bir arada bulunuyorsa, bu durum %100 bir homograf saldırısı göstergesidir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumun e-posta güvenlik ağ geçidi (Email Security Gateway), gelen e-postalardaki gömülü bağlantıları incelemektedir. Saldırgan `apple.com` yerine `\u0430pple.com` (ilk harf Kiril) içeren bir parola sıfırlama oltası göndermiştir. Güvenlik geçidi yalnızca dize karşılaştırması (`url == "apple.com"`) yaptığı için bu bağlantıyı sahte olarak işaretleyememiş ve 15 personelin kimlik bilgileri çalınmıştır.

**Savunmacı Tespit Motoru:**
```python
import unicodedata

def is_homoglyph_phishing(domain: str) -> bool:
    # 1. NFKC ile kanonik normalizasyon
    normalized = unicodedata.normalize("NFKC", domain.lower().strip())
    
    has_latin = False
    has_cyrillic_or_greek = False
    
    for ch in normalized:
        if ch in ".-":
            continue
        name = unicodedata.name(ch, "")
        if "LATIN" in name:
            has_latin = True
        elif "CYRILLIC" in name or "GREEK" in name:
            has_cyrillic_or_greek = True
            
    # Hem Latin hem Kiril/Yunan bir aradaysa homograf oltalamasıdır
    return has_latin and has_cyrillic_or_greek
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! Siber dünyada gördüğün harfe bile güvenmeyeceksin. Ekranda 'a' gördüğünde onun Amerikan mı yoksa Rus mu olduğunu sadece Unicode kod noktası söyler. Gelen her URL'yi ve alan adını önce NFKC tezgahına yatıracak, sonra script analizinden geçireceksin. Latin ile Kiril aynı kazanda kaynıyorsa orada kesinlikle bir oltalama vardır!"

---

### G076-SC3: Trojan Source Saldırıları (CVE-2021-42574), Unicode Bidi Kontrol Karakterleri ve Log Bütünlüğü

#### Soru Başlığı ve Tanımı
Cambridge Üniversitesi araştırmacıları tarafından ortaya çıkarılan "Trojan Source" (CVE-2021-42574) zafiyeti; Unicode Çift Yönlü Metin (Bidirectional / Bidi) kontrol karakterlerinin kullanılmasıyla kaynak kodların veya dosya adlarının insan gözünün gördüğü halinden tamamen farklı şekilde işletilmesini açıklar. Bu saldırı vektörü Python güvenlik betiklerinde, log analizinde ve dosya türü denetiminde nasıl istismar edilir ve nasıl önlenir?

#### Derinlemesine Teknik Analiz
Unicode standardı, soldan sağa (LTR - Left-to-Right) yazılan diller (İngilizce, Türkçe) ile sağdan sola (RTL - Right-to-Left) yazılan dillerin (Arapça, İbranice) aynı dize içinde sorunsuzca görüntülenebilmesi için görünmeyen biçimlendirme karakterleri tanımlamıştır.

Bu karakterlerin en tehlikelisi `U+202E` kodlu **Right-to-Left Override (RLO)** karakteridir. Bu karakter dizeye yerleştirildiğinde, metin işleme motoruna kendisinden sonraki tüm karakterleri ekranda ters yönde çizmesini emreder.

**1. Dosya Uzantısı Maskeleme Saldırısı:**
Saldırgan bir zararlı çalıştırılabilir dosya hazırlar:
`"financial_report_\u202Ecod.exe"`

Ekranda çizilirken:
- `financial_report_` normal LTR çizilir.
- `\u202E` sonrasındaki `cod.exe` tersine döner ve `exe.doc` olarak ekranda görünür!
- Kullanıcı ekranda `financial_report_exe.doc` görür ve bunu zararsız bir Word belgesi sanarak tıklar.
- Ancak işletim sistemi dosya uzantısını sağdan okur; gerçek uzantı `.exe` olduğundan zararlı yazılım anında çalışır!

**2. Log Sahteciliği ve Enjeksiyonu (Log Forging / Injection):**
Bir saldırgan kullanıcı adı alanına `admin\u202E[INFO] User logged in:` enjekte ettiğinde, SOC analistinin terminalinde log satırları ters yüz olur, hata logları başarı logu gibi görünür veya analistin terminali görsel olarak manipüle edilir.

**Savunmacı Programlama Çözümü:**
Güvenlik yazılımları, kullanıcı girdisi kabul eden her noktada (dosya adı, URL, HTTP başlığı, log parametresi) tehlikeli Bidi kontrol karakterleri kümesini (`\u202A` - `\u202E`, `\u2066` - `\u2069`) açıkça denetlemeli ve bu karakterleri içeren girdileri derhal reddetmelidir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir insan kaynakları portalı adaylardan PDF formatında özgeçmiş yüklemelerini istemektedir. Bir saldırgan sisteme `CV_Seydi_\u202Efdp.exe` adında bir dosya yüklemiştir. Sunucu taraflı kontrol naif bir şekilde `filename.lower().endswith(".pdf")` ile kontrol yapmaktadır:
- `\u202E` dizede varken son karakterler `.exe`'dir ancak ters çevrildiğinde `.pdf` gibi görünür.
- Uygulama dosya adını terminale yazdırdığında `CV_Seydi_exe.pdf` görünmüş ve denetçi dosyanın meşru olduğunu onaylamıştır.

**Savunmacı Bidi Engelleyici Fonksiyon:**
```python
BIDI_CHARS = {"\u202A", "\u202B", "\u202C", "\u202D", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069"}

def sanitize_filename_safe(filename: str) -> str:
    # 1. Null-byte kontrolü
    if "\x00" in filename:
        raise ValueError("Null-byte enjeksiyonu tespit edildi!")
        
    # 2. Bidi Trojan Source kontrolü
    for ch in BIDI_CHARS:
        if ch in filename:
            raise ValueError(f"Trojan Source Bidi karakteri ({hex(ord(ch))}) tespit edildi!")
            
    # 3. Uzantı kontrolü dize değil, os.path veya rsplit ile katı yapılmalı
    name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
    if ext.lower() not in {"pdf", "docx"}:
        raise ValueError("İzin verilmeyen dosya türü!")
        
    return filename
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, gözünün gördüğü ile bilgisayarın işlediği şeyin birbirini tutmadığı yere 'Trojan Source' denir. Unicode'un görünmeyen yönlendirici karakterleri, saldırganların göz bağcılık numarasıdır. Sisteme giren hiçbir dosya adında veya log girdisinde `\u202E` gibi Bidi karakterlerinin yaşamasına izin vermeyeceksin. Metin temiz olacak, berrak olacak, arkasında görünmeyen hiçbir hayalet taşımayacak!"
