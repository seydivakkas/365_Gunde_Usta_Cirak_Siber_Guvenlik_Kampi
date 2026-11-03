# GÜN 015: İkili Gösterim, Bayt ve Karakter Kodlaması
**Aşama 02: Sistem ve Ağ Temelleri | Hafta 03: İşletim Sistemi ve İkili Veri Güvenliği**

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 🧭 1. Hocanın Giriş Sohbeti & Zihinsel Model

Evlat, bugün Aşama 02'nin kapısını aralıyoruz ve sanal dünyanın en derinine, yani makinenin konuştuğu ana dile iniyoruz: **İkili Gösterim (Binary), Bayt Seviyesi ve Karakter Kodlaması (Encoding)**.

Şimdi gözlerini kapat ve şu analojiyi kafanda canlandır:
Bir diplomatik telgraf memurusun. Sana mors alfabesiyle bip-bip sesleri (voltaj darbeleri) geliyor. Karşındaki kağıtta ekrana basacağın harfler var. Eğer elindeki mors şifre kitabı (Karakter Kodlaması) ile göndericinin kullandığı kitap aynı değilse; karşı taraf sana barış mesajı gönderirken sen bunu savaş ilanı olarak tercüme edebilirsin! Ya da gönderici telgrafın arasına "Bu mesaj burada bitti" anlamına gelen sahte bir sonlandırma kodu (Null Byte) sıkıştırırsa, mesajın geri kalanındaki kritik uyarıyı hiç okumadan çöpe atarsın.

İşte bilgisayar dünyasında da durum birebir böyledir!  
Bilgisayarın işlemcisi (CPU) veya belleği (RAM) ekrandaki 'A' harfini, 'ş' harfini ya da bir kalkan emojisini 🛡️ bilmez. İşlemci için yalnızca transistörlerin açık veya kapalı olma durumunu ifade eden elektrik voltajları (1 ve 0) vardır. Bu voltaj akışını ekranda anlamlı bir harfe, bir dosya adına veya bir ağ paketine dönüştüren sözlüğe biz **Karakter Kodlaması (Encoding)** deriz.

Sektöre yeni başlayanların düştüğü en büyük yanılgı şudur:  
*"Bir karakter her zaman bir bayttır, bunu öğrenmeye ne gerek var?"*  
Bu cümle, yazılım ve güvenlik dünyasında milyonlarca dolarlık bellek taşması (Buffer Overflow) zafiyetlerine, kimlik avı (Homoglyph) saldırılarına ve web uygulama bypass'larına yol açan tarihi bir yanılgıdır!

Bugün bu derste; bir metnin ekrandan belleğe inerken nasıl dönüştüğünü, UTF-8'in değişken genişlikli sihrini, Null Byte (`\x00`) enjeksiyonunu ve en önemlisi **"Yönetici iznini otomatik olarak güvenli davranış saymak"** ölümcül hatasının neden felaketle sonuçlandığını iliklerine kadar kavrayacaksın.

---

## 🔬 2. Sıfırdan Kristal Netliğinde Teori (Under the Hood)

Bir siber güvenlik uzmanının gözü, ekrandaki yazıyı değil, arkadaki ham baytları görebilmelidir.

```
+-------------------------------------------------------------------------------+
|             DONANIMDAN METNE DÖNÜŞÜM HİYERARŞİSİ (UNDER THE HOOD)             |
+-------------------------------------------------------------------------------+

  [Fiziksel Voltaj]   ──► Yüksek Voltaj (3.3V) / Düşük Voltaj (0V)
                                │
                                ▼
  [İkili Bit (Binary)]──► 1 ve 0 (En küçük bilgi atomu)
                                │
                                ▼
  [Nibble (4-bit)]    ──► 0100 0001 (Yarım bayt = 1 Onaltılık / Hex Basamağı: 0-F)
                                │
                                ▼
  [Bayt (8-bit / Byte]──► 8 Bit = 1 Bayt (0x00 - 0xFF / 0 - 255)
                                │
                                ▼
  [Karakter Kodlaması]──► Sayıları sembollere dönüştüren sözlük!
                          ASCII (7-bit) | ISO-8859-9 (8-bit) | UTF-8 (Değişken)
```

### A. Temel Nicelikler: Bit, Bayt ve Onaltılık (Hex)
- **Bit (Binary Digit):** 0 veya 1. Donanımsal durum.
- **Bayt (Byte):** 8 bitten oluşan standart bilgi kümesi. $2^8 = 256$ farklı değer alabilir ($0$ ile $255$ arası, ya da onaltılık sistemde `0x00` ile `0xFF` arası).
- **Neden Hexadecimal (Onaltılık) Kullanıyoruz?**  
  Bir baytı ikili yazarsak `11011110` gibi okunması zor 8 basamak gerekir. Onaltılık sistemde ise her 4 bit (nibble) tek bir karaktere ($0-9, A-F$) karşılık gelir. Böylece `1101 1110` dizilimi şık ve okunabilir bir şekilde `0xDE` olur. Bellek adresleri ve paket başlıkları bu yüzden daima Hexadecimal dökülür.

### B. ASCII'den Unicode ve UTF-8 Devrimine
1. **ASCII (American Standard Code for Information Interchange - 1963):**  
   7-bit kullanır ($2^7 = 128$ karakter). Yalnızca temel İngiliz alfabesini, rakamları ve kontrol karakterlerini (`\r`, `\n`, `\0`) içerir. İngilizce dışındaki hiçbir dili (Türkçe, Çince, Rusça) desteklemez.
2. **Unicode Standartı:**  
   Dünyadaki tüm alfabeleri ve sembolleri tek bir çatı altında toplamak için geliştirilmiştir. Her karaktere bir kod noktası (Code Point) atar (Örn: Latin 'A' = `U+0041`, Türkçe 'ş' = `U+015F`, Kalkan Emojisi 🛡️ = `U+1F6E1`).
3. **UTF-8: Değişken Genişlikli (Variable-Width) Kodlama Şaheseri:**  
   Unicode kod noktalarını baytlara dönüştürürken bellek tasarrufu ve geriye dönük ASCII uyumluluğu sağlamak için dinamik bayt uzunluğu kullanır:

| Karakter Kümesi | Unicode Aralığı | UTF-8 Bayt Uzunluğu | İkili Bayt Yapısı |
| :--- | :--- | :---: | :--- |
| **ASCII Karakterler** (A-Z, a-z, 0-9) | U+0000 - U+007F | **1 Bayt** | `0xxxxxxx` (ASCII ile %100 birebir uyumlu) |
| **Türkçe, Latin, Arapça, Kiril** | U+0080 - U+07FF | **2 Bayt** | `110xxxxx 10xxxxxx` (Örn: 'ş' = `0xC5 0x9F`) |
| **Çince, Japonca, Hintçe, Semboller** | U+0800 - U+FFFF | **3 Bayt** | `1110xxxx 10xxxxxx 10xxxxxx` (Örn: '€' = `0xE2 0x82 0xAC`) |
| **Emojiler, Antik Diller, Tarihi Yazılar**| U+10000 - U+10FFFF | **4 Bayt** | `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx` (Örn: 🛡️ = 4 bayt) |

---

## ⚔️ 3. İki Yönlü Bakış: Saldırganın Gözü vs Savunmacının Kalkanı

### 🔴 Saldırganın Gözü (Offensive Perspective)
Bir saldırgan, yazılımcıların karakter kodlamasını anlamamasını bir açık kapı olarak kullanır:
1. **Boyutsal Uyumsuzluk ve Bellek Taşması (Buffer Overflow & Truncation):**  
   Eski veya dikkatsiz bir C/C++ programcısı şöyle bir kod yazar:
   ```c
   char kullanici_adi[10];
   // Programcı 10 karakterlik girdi bekliyor!
   strcpy(kullanici_adi, girdi);
   ```
   Saldırgan 10 adet Türkçe 'Ş' harfi (`ŞŞŞŞŞŞŞŞŞŞ`) veya 5 adet emoji gönderir. Karakter sayısı 10 olmasına rağmen, UTF-8 bayt boyutu 20 veya 40 bayt olur! Sabit 10 baytlık dizi taşar; yığındaki (stack) dönüş adresi ezilir ve saldırgan sisteme uzaktan kod çalıştırır (RCE).
2. **Null Byte Injection (`\x00`):**  
   Python veya PHP gibi modern diller string uzunluğunu bir başlıkta saklar; ancak alt seviye C fonksiyonları (`fopen`, `open`, `execve`) bir metnin sonunu `\x00` (ASCII 0 / Null Terminator) ile algılar.  
   Saldırgan şu dosya adını yükler: `guvenli_rapor.pdf\x00.exe`  
   Web uygulaması son 4 karaktere (`.exe`) bakar veya regex uygular, güvenli sanır. Ancak dosya sisteme kaydedilirken C fonksiyonu `\x00` görünce metni keser ve dosya `guvenli_rapor.pdf` olarak diske yazılır. Tersi durumda da `.php\x00.jpg` ile uzantı kontrolü atlatılır.
3. **Homoglyph / IDN Spoofing (Görsel Karakter Benzetme):**  
   Latin 'a' harfi (`U+0061`) ile Kiril 'а' harfi (`U+0430`) ekranda birbirinin tıpatıp aynısı görünür. Saldırgan `pаypаl.com` alan adını Kiril harfleriyle kaydeder. Kullanıcı orijinal siteye girdiğini sanırken aslında sahte oltalama sunucusuna bağlanır.
4. **Overlong UTF-8 Encoding (Dizin Geçişi - Path Traversal):**  
   Web sunucuları `../` ifadesini filtreler. Ancak saldırgan `/` (eğik çizgi) karakterini standart 1 bayt `0x2F` yerine, geçersiz 2 baytlık overlong UTF-8 `0xC0 0xAF` olarak kodlar (`..%c0%af..`). Filtre 1 baytlık eğik çizgiyi görmediği için geçer; işletim sistemi çözerken bunu `/` olarak ayrıştırır ve dizin geçişi gerçekleşir.

### 🔵 Savunmacının Kalkanı (Defensive Perspective)
1. **Kanonikleştirme ve Normalizasyon (Unicode Normalization - NFC/NFKC):**  
   Girdiler işlenmeden önce Unicode standart formlarına (NFC veya NFKC) dönüştürülür; farklı kodlama kombinasyonları tek bir kanonik forma zorlanır.
2. **Karakter Sayısı Değil, Bayt Uzunluğu Denetimi:**  
   Tampon bellek tahsislerinde `strlen()` veya `len()` değil, ham bayt uzunluğu (`sizeof` / `bytes.length`) esas alınır.
3. **Null Byte ve Kontrol Karakteri Sanitizasyonu:**  
   Metin girdileri içinde `\x00` - `\x1F` aralığındaki kontrol karakterleri beyaz liste (whitelist) süzgecinden geçirilir; beklenmeyen null karakterler derhal reddedilir.
4. **"Yönetici İznini Otomatik Güvenli Sayma" Yanılgısını Kırmak:**  
   En yetkili hesap (Root / Administrator) dahi olsa, bozuk veya zararlı kodlanmış girdi işletim sistemi çekirdeğini çökertebilir veya bellek taşmasına yol açabilir. Yetki, verinin güvenliğini garanti etmez!

---

## 🛠️ 4. Hocayla Birlikte Canlı Laboratuvar

Şimdi terminalimizde bir metnin ham baytlarına, onaltılık dökümüne ve karakter kodlamasına bizzat şahit olacağız.

### Adım 1: PowerShell Üzerinde UTF-8 Baytlarını ve Hex Dökümünü İnceleme
Windows PowerShell'de bir metnin bayt boyutunu ve hex karşılığını görelim:

```powershell
# 1. Standart ASCII ve Türkçe bir metin tanımla
$MetinAscii = "SECURITY"
$MetinTurkce = "GÜVENLİK"

# 2. Karakter sayılarını ekrana bas
Write-Host "ASCII Karakter Sayısı: $($MetinAscii.Length)"
Write-Host "Türkçe Karakter Sayısı: $($MetinTurkce.Length)"

# 3. UTF-8 bayt dizilerine dönüştür
$BaytAscii = [System.Text.Encoding]::UTF8.GetBytes($MetinAscii)
$BaytTurkce = [System.Text.Encoding]::UTF8.GetBytes($MetinTurkce)

Write-Host "ASCII Bayt Boyutu: $($BaytAscii.Length)"
Write-Host "Türkçe Bayt Boyutu: $($BaytTurkce.Length)"  # Boyutsal genişleme!

# 4. Format-Hex ile ham baytları görselleştir
$MetinTurkce | Format-Hex
```

### Adım 2: Linux Terminalinde Hexdump ve XXD İncelemesi
Linux kabuğunda çalışıyorsan:

```bash
# 1. ASCII metnin hex dökümü (1 harf = 1 bayt)
echo -n "LAB" | xxd

# 2. Türkçe metnin hex dökümü ('ü' harfi 2 bayt kaplar: c3 bc)
echo -n "GÜVEN" | xxd

# 3. Null Byte enjeksiyonunu görselleştir
printf "dosya.pdf\x00.exe" | hexdump -C
```

### Adım 3: Geliştirdiğimiz Python Aracı ile Güvenlik Denetimi
Geliştirdiğimiz motor ile laboratuvardaki sentetik örnekleri denetleyelim:

```bash
# 1. Tüm örnekleri topluca denetle
python portfolio/hafta_03/gun_015/uygulama/binary_byte_encoding_inspector.py --veri-tabani portfolio/hafta_03/gun_015/ornek_veri/karakter_kodlama_ornekleri.json --tumunu-denetle

# 2. Türkçe metnin Hex Dump dökümünü ve bayt genişlemesini gör
python portfolio/hafta_03/gun_015/uygulama/binary_byte_encoding_inspector.py --veri-tabani portfolio/hafta_03/gun_015/ornek_veri/karakter_kodlama_ornekleri.json --ornek-id SAMPLE-02-TURKISH-MULTIBYTE --hex-dump

# 3. Null Byte saldırısını denetle (Yönetici yetkisi verilse bile hatayı yakalar!)
python portfolio/hafta_03/gun_015/uygulama/binary_byte_encoding_inspector.py --veri-tabani portfolio/hafta_03/gun_015/ornek_veri/karakter_kodlama_ornekleri.json --ornek-id SAMPLE-04-NULL-BYTE-ATTACK --yonetici-hakki

# 4. Homoglyph (Kiril/Latin aldatmacası) saldırısını yakala
python portfolio/hafta_03/gun_015/uygulama/binary_byte_encoding_inspector.py --veri-tabani portfolio/hafta_03/gun_015/ornek_veri/karakter_kodlama_ornekleri.json --ornek-id SAMPLE-05-HOMOGLYPH-SPOOF
```

---

## ⚠️ 5. Hocanın "Ölümcül Hatalar" Notu

1. **`len()` Fonksiyonunu Bellek Tahsisi Sanmak:**  
   Python'da `len("ş")` cevabı 1'dir; ancak bu 1 karakterdir, 1 bayt DEĞİLDİR! C veya C++ diline aktarırken `char buf[len]` açarsan bellek taşması kaçınılmazdır. Daima `len(metin.encode('utf-8'))` kullanılmalıdır.
2. **Yönetici İznini Otomatik Olarak Güvenli Davranış Saymak:**  
   "Ben bu scripti root/admin olarak çalıştırıyorum, güvendeyim" demek büyük bir gaflettir. Root yetkisiyle çalışan bir servise bozuk kodlanmış bir bayt akışı veya null byte gönderilirse, yetki yüksek olduğu için hasar da tam yetkili (Ring 0 / Kernel seviyesinde) meydana gelir.
3. **Eski Veritabanlarında `utf8` Kullanmak:**  
   MySQL'in eski `utf8` karakter seti aslında 3 bayt ile sınırlıdır (sahte UTF-8). Bir kullanıcı form alanına 4 baytlık bir emoji (örn. 🔒) girdiğinde, veritabanı o noktada veriyi sessizce keser (truncation) ve şifre veya veriler bozulur. Doğrusu daima `utf8mb4` kullanmaktır.
4. **Karakter Kodlamasını Varsaymak:**  
   Bir ağ soketinden veya dosyadan bayt okurken kodlamayı varsaymak ("kesin UTF-8'dir") yerine, açıkça doğrulamak ve hata durumunda (`errors='replace'` veya `errors='strict'`) kontrollü davranmak gerekir.

---

## 🎯 6. Günün Pratik Görevi + Çözüm Yürüyüşü

### Pratik Görev Tanımı:
Sentetik veri tabanında (`karakter_kodlama_ornekleri.json`) yer alan standart ASCII, çok baytlı Türkçe, emojili metin, Null Byte enjeksiyonlu dosya adı ve Homoglyph aldatmacası içeren örneklerin incelenmesi; her birinin karakter sayısı, UTF-8 bayt boyutu ve hex dökümünün çıkarılması; "Yönetici iznini otomatik olarak güvenli davranış saymak" yanılgısının olumsuz testle analiz edilmesi.

### Adım Adım Çözüm Yürüyüşü:
1. **Veri Tabanının İncelenmesi:** `ornek_veri/karakter_kodlama_ornekleri.json` yüklendi.
2. **ASCII vs Türkçe Karşılaştırması:**
   - `SAMPLE-01-ASCII-STANDARD`: 23 karakter == 23 bayt. Her karakter 1 bayt. Skor: 100 (GUVENLI).
   - `SAMPLE-02-TURKISH-MULTIBYTE`: 34 karakter fakat 40 bayt! Türkçe karakterlerin 2 baytlık genişlemesi saptandı.
3. **Zafiyet Analizi (Null Byte & Homoglyph):**
   - `SAMPLE-04-NULL-BYTE-ATTACK`: `\x00` tespitiyle `VULN-01-NULL-BYTE-INJECTION` tetiklendi (-40 puan).
   - `SAMPLE-05-HOMOGLYPH-SPOOF`: Latin ve Kiril alfabelerinin karışık kullanımı `VULN-03-HOMOGLYPH-SPOOFING` ile yakalandı (-25 puan).
4. **Olumsuz Test ve Yönetici Yanılgısı:** `yonetici_hakki_var_mi=True` bayrağı ile çalıştırıldığında, yönetici yetkisinin zafiyeti ortadan kaldırmadığı `FALLACY-05-ADMIN-PRIVILEGE-FALLACY` uyarısıyla kanıtlandı.
5. **Birim Test Kapsamı:** 14 test ile pozitif genişleme, tampon kesilme ve hata durumları 0.022 saniyede %100 doğrulandı.

---

## ❓ 7. Hocanın Soru Odası

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
