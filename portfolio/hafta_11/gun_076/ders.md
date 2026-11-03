# GÜN 076: METİN, REGEX VE KARAKTER KODLAMASI (TEXT, REGEX & CHARACTER ENCODINGS IN CYBER SECURITY)
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞ DERSİ: METİN İŞLEME SADECE BİR BİÇİMLENDİRME DEĞİL, BİR GÜVENLİK SINIRIDIR

Evlat, acemi bir programcı bir metin (string) gördüğünde sadece harflerden oluşan görsel bir mesaj görür. Bir güvenlik ustası ise o metne baktığında potansiyel bir bellek taşması, bir CPU tükenmesi (ReDoS), bir görsel oltalama (Homoglyph) veya bir işletim sistemi enjeksiyon vektörü görür.

Modern siber saldırıların %90'ı bir metin akışı üzerinden taşınır: HTTP istekleri, DNS sorguları, e-posta başlıkları, JSON payload'ları veya sistem logları. Eğer bu metinleri ayrıştıran düzenli ifadelerin (Regex) arkasındaki NFA (Nondeterministic Finite Automaton) motorunun nasıl çalıştığını bilmezsen, tek bir 50 karakterlik girdiyle sunucunun CPU'sunu saatlerce %100'e kilitlerler. Eğer Unicode karakter kodlamalarını ve NFKC normalizasyonunu bilmezsen, Kiril harfleriyle yazılmış bir banka alan adını sisteminden meşru diye geçirirsin.

Metin güvenliği, bir güvenlik mühendisinin dilbilimsel ve algoritmik kalkanıdır.

---

## 2. REGEX'TE HİZMET DIŞI BIRAKMA: ReDoS (REGULAR EXPRESSION DENIAL OF SERVICE - CWE-1333)

Python'ın standart `re` modülü, düzenli ifadeleri eşleştirmek için bir NFA (Geri İzlemeli Sonlu Durum Otomatı) motoru kullanır. Bu motor, bir deseni dizeyle eşleştirmeye çalışırken alternatif yolları dener; eşleşme başarısız olursa geriye dönerek (backtracking) alternatif dalları tekrar sınar.

### Felaket Düzeyinde Geri İzleme (Catastrophic Backtracking):
Eğer bir regex deseninde iç içe geçmiş belirsiz (ambiguous) ve tekrarlanan niteleyiciler (nested greedy quantifiers) bulunuyorsa, motorun denemek zorunda olduğu permütasyon sayısı $O(N)$ doğrusal büyümez; $O(2^N)$ üstel (exponential) patlar!

```python
# ❌ ÖLÜMCÜL ReDoS DESENİ (CWE-1333):
vulnerable_regex = re.compile(r"^(a+)+$")

# Masum girdi: "aaaaa" -> Milisaniyede eşleşir.
# Saldırgan girdisi (Sonda eşleşmeyen bir karakter!):
# "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (30 adet 'a' ve 1 adet '!')
```
Bu girdi karşısında motor, 30 tane 'a' harfinin iç ve dış artı (`+`) gruplarına nasıl dağıtılabileceğini $2^{30} \approx 1.073.741.824$ (1 milyar) farklı kombinasyonla dener! Tek bir çekirdek %100 CPU tüketir, sunucu yanıt veremez hale gelir.

### Savunmacı Regex İlkeleri:
1. **İç İçe Açgözlü Gruplardan Kaçın:** `(a+)+`, `([a-zA-Z0-9]+)*`, `(a|aa)+$` gibi çakışan grupları asla kullanma.
2. **Girdi Uzunluğuna Sert Tavan Koy (Input Length Guard):** Regex fonksiyonunu çalıştırmadan önce `if len(input_str) > MAX_INPUT_LENGTH:` kontrolü ile girdiyi 4096 veya 2048 karakterle sınırla. 100.000 karakterlik bir girdi regex motoruna hiç ulaşamamalıdır.
3. **Katı Başlangıç ve Bitiş Bağlaçları (`^` ve `$`):** Kısmi eşleşme açıklarını engellemek için deseni daima iki uçtan bağla.

---

## 3. UNICODE NORMALİZASYONU VE IDN HOMOGRAF (HOMOGLYPH) SALDIRILARI

Modern bilişimde karakterler sadece 128 karakterlik ASCII tablosundan ibaret değildir; Unicode standardında 140.000'den fazla karakter bulunur. Farklı alfabelerdeki bazı karakterler görsel olarak birbirinin birebir kopyasıdır (Homoglyph):

- Latin Küçük 'a' harfi: Unicode `U+0061`
- Kiril Küçük 'а' harfi: Unicode `U+0430`

İki karakter ekranda insan gözüne tamamen aynı görünür: `a` vs `а`. Bir saldırgan `p\u0430yp\u0430l.com` adında bir alan adı tescil ettiğinde (IDN - Internationalized Domain Name), kurban tarayıcısında `paypal.com` gördüğünü sanır ancak arka planda Rusya'daki bir saldırgan sunucusuna bağlanır!

### Unicode Normalizasyon Formları (NFC vs NFKC):
Unicode'da aynı karakter birden fazla şekilde temsil edilebilir (örn. `é` karakteri hem tek bir kod noktası `\u00E9` hem de `e` + aksan `\u0301` olarak yazılabilir).
- **NFC (Canonical Composition):** Kanonik eşdeğerleri tek koda indirger.
- **NFKC (Compatibility Composition):** Güvenlik için en kritik formdur! Görsel varyantları, ligatürleri, üst/alt simgeleri ve tam genişlikli karakterleri standart ASCII/Latin formlarına dönüştürür.

```python
import unicodedata

# NFKC ile kanonik dönüşüm:
normalized = unicodedata.normalize("NFKC", domain_str)
```

### Savunmacı Homograf Algoritması:
Bir alan adında Latin karakterler ile Kiril/Yunan karakterlerinin bir arada kullanılması (Mixed-Script) %99 ihtimalle bir oltalama saldırısıdır. Sistemlerimiz `unicodedata.name(char)` ile karakterin alfabe kökenini inceleyerek karma alfabeleri sınırda bloklar.

---

## 4. NULL-BYTE (`\x00`) ENJEKSİYONU VE DİZE KESME (STRING TRUNCATION)

C ve C++ dillerinde dizeler sonlandırıcı Null karakteri (`\0` veya `\x00`) ile biter. Python dize nesneleri bellekte boyut bilgisi (`PyASCIIObject.length`) ile tutulsa da, Python işletim sistemi çağrısı yaptığında (`open()`, `socket()`) veya C kütüphanelerine veri aktardığında dize C biçimine (`char*`) dönüştürülür.

### Saldırı Senaryosu:
Bir web uygulaması sadece resim dosyalarına (`.png`, `.jpg`) izin vermektedir:
```python
filename = "shell.php\x00.png"
if filename.endswith(".png"): # Python seviyesinde True döner!
    os_save_file(filename)     # C seviyesinde \0 görünce kesilir -> "shell.php" yazılır!
```
Saldırgan güvenlik duvarını ve doğrulama mantığını atlatarak sunucuya PHP web shell yükler.

**Savunmacı Kural:** Her girdi doğrulama fonksiyonunun ilk satırında `if "\x00" in raw_str: raise ValueError("Null-byte enjeksiyonu!")` kontrolü yapılmalıdır.

---

## 5. TROJAN SOURCE SALDIRILARI (CVE-2021-42574) VE UNICODE BIDI

Unicode standardı, Arapça ve İbranice gibi sağdan sola yazılan diller için çift yönlü metin (Bidirectional / Bidi) kontrol karakterleri içerir:
- `\u202E` (RLO: Right-to-Left Override): Kendisinden sonra gelen tüm metni ters yönde yazdırır.

### Güvenlik Tehdidi:
Bir saldırgan kötü niyetli bir dosyayı şu şekilde adlandırır:
`payroll_\u202Ecod.exe`
İşletim sistemi veya dosya yöneticisi bu adı ekrana çizerken RLO karakteri sebebiyle `cod.exe` kısmını ters çevirir ve ekranda şunu gösterir:
`payroll_exe.doc`
Kullanıcı dosyayı masum bir Word belgesi sanarak tıklar, oysa işletim sistemi gerçekte `payroll_...exe` dosyasını çalıştırır!

Savunmacı motorlarımız, loglarda ve dosya adlarında bu tehlikeli Bidi karakter kümesini (`BIDI_CONTROL_CHARS`) tespit ederek işlemi anında durdurur.

---

## 6. İSİMLENDİRİLMİŞ YAKALAMA GRUPLARI (NAMED CAPTURE GROUPS) VE KATI BAĞLAÇLAR

Spagetti regex'lerde gruplara indeks numarasıyla erişmek (`match.group(1)`, `match.group(4)`) kodun okunabilirliğini ve güvenliğini bozar. Desen güncellendiğinde indeksler kayar ve sessiz veri bozulmaları oluşur.

### Temiz ve Savunmacı Regex Mimarisi:
```python
LOG_PATTERN = re.compile(
    r'^(?P<ip>[0-9a-fA-F.:]+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>HTTP/[0-9.]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)$'
)

parsed_dict = match.groupdict()
# parsed_dict['ip'] -> Doğrudan ve tip güvenli erişim!
```

- **`^` ve `$`:** Başlangıç ve bitiş bağlacı olmadan yazılan regex'ler, arkasına `; DROP TABLE` eklenmiş enjeksiyonlu dizeleri "kısmen" eşleştirerek içeri alır. Bağlaçlar zorunludur!

---

## 7. USTANIN ÇIRAĞA ÖĞÜTLERİ VE ALTIN KURALLAR

1. **Regex'leri Daima Önceden Derle (`re.compile`):** Döngü içinde sürekli `re.search()` çağırma. Deseni modül seviyesinde bir kez derle; hem mikro-saniye hız kazan hem de sözdizim hatasını uygulama başlarken yakala.
2. **Regex Motoruna Asla Sınırsız Metin Gönderme:** Her regex çağrısından önce `len(text) <= 4096` sınırını koy. ReDoS canavarını aç bırak!
3. **Kullanıcı Girdisinde Null-Byte ve Bidi Ara:** `\x00` ve `\u202E` karakterleri gördüğün an arkana bakmadan alarm üret.
4. **Alan Adlarını Daima NFKC ile Normalize Et:** Oltalama denetiminde Latin ile Kiril harflerini birbirinden ayıran script kontrolü yap.
5. **Gevşek `errors="ignore"` Kullanma:** Bayt çözerken `ignore` dersen bozuk baytların arasına gizlenmiş saldırıyı kaçırırsın. Katı (`strict`) modda yakala veya denetim loguna yazarak (`replace`) temizle.
