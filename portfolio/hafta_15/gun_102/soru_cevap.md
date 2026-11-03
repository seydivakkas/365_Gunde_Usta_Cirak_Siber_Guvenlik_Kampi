# GÜN 102: SORU & CEVAP VE TEKNİK MÜLAKAT DOSYASI
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.*

---

### SORU 1: Gökkuşağı Tabloları (Rainbow Tables) Nedir ve Kriptografik Tuz (Salt) Bu Saldırıyı Matematiksel Olarak Nasıl Engeller?

#### 1. Soru Başlığı ve Tanımı
Gökkuşağı tabloları (Rainbow Tables), önceden hesaplanmış hash değerleri ile düz metin parolaları eşleştiren, zaman-hafıza ödünleşimi (time-memory tradeoff) prensibine dayalı gelişmiş arama yapılarıdır. Tuz (salt) mekanizmasının bu saldırıyı nasıl ve hangi matematiksel gerekçeyle tamamen imkansız hale getirdiğinin incelenmesi.

#### 2. Derinlemesine Teknik Analiz
Düz metin parolaların hashlenmesinde $H = \text{Hash}(P)$ formülü geçerlidir. Parola uzayı $S$ sonlu olduğunda, bir saldırgan olası tüm parolaların hash özetlerini hesaplayabilir. Ancak milyarlarca 32-baytlık hash değerini saklamak devasa depolama gerektirir. Hellman ve Oechslin tarafından geliştirilen gökkuşağı tabloları, bir **İndirgeme Fonksiyonu (Reduction Function $R$)** kullanarak hash zincirleri oluşturur:
$$P_0 \xrightarrow{H} H_0 \xrightarrow{R_1} P_1 \xrightarrow{H} H_1 \xrightarrow{R_2} P_2 \dots \xrightarrow{H} H_k$$
Tabloda yalnızca zincirin başlangıç parolası ($P_0$) ve son parolası ($P_k$) saklanır. Bir hash ele geçirildiğinde, saldırgan indirgeme fonksiyonlarını uygulayarak zincirin sonuna ulaşır ve tablodaki eşleşmeyi bulursa zinciri baştan yeniden işleterek parolanın açık halini dakikalar içinde bulur.

Kriptografik tuzlama (Salt) uygulandığında formül şu şekle dönüşür:
$$H_s = \text{Hash}(S \parallel P)$$
Burada $S \in \{0, 1\}^{128}$ her bir kullanıcı ve her bir parola için `secrets.token_bytes(16)` ile bağımsız olarak üretilen 128-bitlik rastgele bir sayıdır.
- Olası tuz kombinasyonlarının sayısı $2^{128} \approx 3.4 \times 10^{38}$ adettir.
- Bir saldırganın önceden oluşturduğu gökkuşağı tablosu, tek bir tuz değeri için bile geçerli olamaz.
- Saldırganın her bir kullanıcı için $2^{128}$ farklı gökkuşağı tablosu üretmesi gerekir. Evrendeki toplam atom sayısı $10^{80}$ civarındayken, bu miktarda tabloyu depolamak veya hesaplamak fizik yasaları gereği imkansızdır. Dolayısıyla tuz, gökkuşağı tablolarını matematiksel olarak tamamen geçersiz kılar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** 2012 yılında LinkedIn platformundan 6.5 milyon kullanıcının parola hash kaydı sızdırıldı. LinkedIn mühendisleri parolaları tuzlama yapmaksızın düz `SHA-1` ile saklamışlardı (`CWE-759`). Birkaç gün içinde sızan hashlerin %90'ından fazlası internetteki halka açık gökkuşağı tabloları ve tersine hash arama motorları ile saniyeler içinde çözüldü. Milyonlarca yöneticinin ve kullanıcının hesabı ele geçirildi.

**Pratik Çözüm:**
Parola saklama mimarisinde her kullanıcı kaydı için benzersiz 16 baytlık rastgele tuz üretilmeli ve PBKDF2 standardına bağlanmalıdır:
```python
# Kriptografik güvenli tuz üretimi ve PBKDF2 hashleme
import secrets
import hashlib

salt = secrets.token_bytes(16)
derived_hash = hashlib.pbkdf2_hmac(
    hash_name="sha256",
    password=user_password.encode("utf-8"),
    salt=salt,
    iterations=100_000,
    dklen=32
)
# Kayıt formatı: $pbkdf2-sha256$i=100000$s={salt.hex()}${derived_hash.hex()}
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, unutmaman gereken en mühim kural şudur: Tuz gizli bir sır değildir, amacı benzersizliktir. Ancak tuz statik veya tahmin edilebilir olursa (örneğin kullanıcı adı veya sabit bir şirket ismi gibi), saldırgan sadece o şirkete özel küçük bir gökkuşağı tablosu üretir ve yine sistemini delik deşik eder (`CWE-760`). Tuzu daima işletim sisteminin kriptografik entropi havuzundan çek; asla kendi aklından 'rastgele' dize uydurma!"

---

### SORU 2: Kriptografik Biber (Pepper) Nedir, Tuzdan (Salt) Hangi Mimari ve Güvenlik Özellikleriyle Ayrılır?

#### 1. Soru Başlığı ve Tanımı
Parola saklama mimarisinde tuz (salt) ve biber (pepper) kavramlarının karşılaştırılması; biberin nerede saklanması gerektiği ve SQL Injection veya doğrudan veritabanı yedeğinin sızması durumunda sunduğu savunma derinliğinin (defense-in-depth) teknik analizi.

#### 2. Derinlemesine Teknik Analiz
Tuz ve biber kavramları arasındaki temel mimari farklar şunlardır:

| Özellik | Tuz (Salt) | Biber (Pepper) |
| :--- | :--- | :--- |
| **Kapsam** | Kullanıcı bazında benzersiz (Per-user unique) | Sistem/Uygulama genelinde ortak veya rotasyonlu |
| **Gizlilik** | Gizli DEĞİLDİR (Public within DB) | KESİNLİKLE GİZLİDİR (Secret key) |
| **Saklama Yeri** | Veritabanında hash kaydının yanında | Veritabanı DIŞINDA (HSM, KMS, Çevre Değişkeni) |
| **Savunulan Tehdit**| Gökkuşağı tabloları, toplu kırma | Veritabanı sızıntısında çevrimdışı GPU sözlük saldırısı |
| **Matematiksel Rol**| $H = \text{KDF}(P, S)$ | $H = \text{KDF}(\text{HMAC}(Pepper, P), S)$ |

Bir saldırgan SQL Injection zafiyeti (`CWE-89`) kullanarak veya sızdırılmış bir veritabanı yedeği (`.sql.dump`) üzerinden tüm kullanıcı tablosunu ele geçirdiğinde:
- Eğer yalnızca tuz kullanılmışsa, saldırgan elindeki hash ve tuz çiftlerini kendi GPU kırma istasyonuna (Hashcat / John the Ripper) yükler. Saniyede on binlerce parola denemesi yaparak basit parolaları kırabilir.
- Ancak sistemde **Biber (Pepper)** kullanılmışsa, saldırgan veritabanını ele geçirse bile biber anahtarına sahip değildir. Biber veritabanında saklanmadığı için saldırganın elindeki hashler kilitli kalır. Saldırgan deneyeceği parolanın doğruluğunu teyit edecek matematiksel fonksiyona girdi sağlayamaz.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret platformu SQL Injection açığı nedeniyle hacklenir ve 1 milyon kullanıcının `users` tablosu `dump` edilerek Dark Web forumlarında satışa çıkarılır. Tabloda `username`, `salt` ve `password_hash` sütunları yer almaktadır.

**Pratik Çözüm:**
Platform mimarisinde biber anahtarı AWS KMS (Key Management Service) veya Donanımsal Güvenlik Modülü (HSM) üzerinde tutulmalıdır. Parola KDF fonksiyonuna verilmeden önce HMAC ile biberlenir:
```python
import hmac
import hashlib

# Biber HSM/KMS üzerinden izole olarak belleğe alınır
SECRET_PEPPER = get_pepper_from_hsm()

def hash_with_pepper(password: str, salt: bytes) -> bytes:
    # 1. Aşama: Parolayı sistem biberi ile HMAC'le
    keyed_password = hmac.new(SECRET_PEPPER, password.encode("utf-8"), hashlib.sha256).digest()
    # 2. Aşama: PBKDF2 ile tuzlayıp anahtar türet
    return hashlib.pbkdf2_hmac("sha256", keyed_password, salt, 100_000, 32)
```
Saldırgan veritabanını indirse bile HSM'e erişemediği için çevrimdışı (offline) sözlük atağı başlatamaz.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, biberi veritabanında bir sütun olarak saklayan sözde uzmanlara rastlarsan oradan hemen uzaklaş! Biberi veritabanına koymak, kasanın anahtarını kasanın kapağına yapıştırmaya benzer. Biberin tüm kerameti **fiziksel ve mantıksal izolasyonundadır**. Veritabanı çöker veya çalınırsa, biber dışarıdaki güvenli kalede (HSM/KMS) dimdik ayakta kalmalıdır."

---

### SORU 3: Parola Doğrulamasında Sabit Zamanlı Kıyaslama (Constant-Time Comparison) Neden Hayatidir ve Düz `==` İşleci Hangi Zamanlama Zafiyetine (CWE-208) Yol Açar?

#### 1. Soru Başlığı ve Tanımı
Geleneksel string eşitlik kontrolünün (`str1 == str2`) işlemci düzeyinde erken çıkış (early-exit) davranışı nedeniyle yarattığı Zamanlama Saldırısı (Timing Attack - CWE-208) riskinin analizi ve `hmac.compare_digest` fonksiyonunun koruma mekanizması.

#### 2. Derinlemesine Teknik Analiz
Çoğu standart kütüphane ve C tabanlı string karşılaştırıcı (örneğin `memcmp` veya Python'un `==` operatörü), performansı optimize etmek için tasarlanmıştır. İki dizgi kıyaslanırken ilk karakterden başlanır; ilk uyuşmayan bayt ile karşılaşıldığında döngü derhal sonlandırılır (`break`) ve fonksiyon `False` döner.

```c
// Zafiyetli Erken Çıkış (Early-Exit) Kıyaslama Mantığı
int insecure_compare(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0; // İLK HATADA ANINDA DÖNÜŞ! (CWE-208)
    }
    return 1;
}
```

Bu erken çıkış davranışı, işlemcinin harcadığı saat çevriminde (CPU cycles) ve dolayısıyla ağ yanıt süresinde mikro/nano saniye düzeyinde ölçülebilir bir fark yaratır:
- Eğer ilk bayt yanlışsa: Karşılaştırma 1. adımda biter (Örn: 5 nanosaniye).
- Eğer ilk bayt doğru, ikinci bayt yanlışsa: Karşılaştırma 2. adımda biter (Örn: 8 nanosaniye).
- Eğer ilk 10 bayt doğruysa: Karşılaştırma 10. adımda biter (Örn: 30 nanosaniye).

Saldırgan, yerel ağda veya düşük gecikmeli ortamlarda binlerce istek gönderip yanıt sürelerinin istatistiksel dağılımını (ANOVA, Student's t-test) analiz ederek doğru hash karakterlerini bayt bayt tahmin edebilir.

**Sabit Zamanlı Kıyaslama Çözümü (`hmac.compare_digest`):**
Sabit zamanlı algoritmada, baytlar uyuşsa da uyuşmasa da dizginin tamamı taranır ve bit düzeyinde XOR (`^`) işlemi bir akümülatörde toplanır:
```c
// Sabit Zamanlı Güvenli Kıyaslama Mantığı
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]); // Asla erken çıkış yapmaz, tüm baytları işler
    }
    return result == 0;
}
```
Bu sayede doğru bayt sayısı ne olursa olsun işlem süresi tamamen sabittir; saldırgana sıfır bilgi sızdırılır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Yüksek güvenlikli bir bankacılık API'sinde API anahtarları veya parola hashleri `if stored_hash == incoming_hash:` şeklinde kıyaslanmaktadır. Bir saldırgan, API uç noktasına yönelik geliştirdiği zamanlama analizi aracı ile her karakter denemesindeki ortalama yanıt gecikmesini milisaniyenin yüzde biri hassasiyetinde ölçerek 64 karakterlik hash özetini brute-force yapmaksızın birkaç saat içinde ortaya çıkarır.

**Pratik Çözüm:**
Tüm parola ve kriptografik özet doğrulamalarında Python standart kütüphanesinin güvenli fonksiyonu kullanılmalıdır:
```python
import hmac

def verify_hash(candidate_hash: str, expected_hash: str) -> bool:
    # CWE-208 Savunması: Sabit zamanlı bayt karşılaştırması
    return hmac.compare_digest(candidate_hash.lower(), expected_hash.lower())
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, güvenlik dünyasında nanosaniyeler hayat kurtarır veya sistem batırır! Normal bir yazılımcı 'işlemci ilk hatada döngüden çıksın da program hızlı çalışsın' diye düşünür; siber güvenlik uzmanı ise 'erken çıkış bilgi sızdırır, sabit zamanlı çalışmalı' der. Kriptografide hız bazen senin en büyük düşmanındır. Parola ve imza kontrolünde `==` sembolünü aklından sil, daima `hmac.compare_digest` kullan!"
