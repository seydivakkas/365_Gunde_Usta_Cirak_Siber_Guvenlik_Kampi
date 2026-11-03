# GÜN 092: Veri Doğrulama ve Tip Güvenliği — Mülakat ve Saha Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap seti yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz paylaşılamaz veya çoğaltılamaz.*

---

## SORU 1: Tip Karışıklığı (Type Confusion - CWE-843) Nedir ve Dinamik Dillerde Nasıl Önlenir?

### 1. Soru Başlığı ve Tanımı
Dinamik tipli dillerde (Python, JavaScript, PHP) "Tip Karışıklığı" (Type Confusion / Type Juggling) zafiyeti nedir? Python'da `bool` tipinin `int` sınıfından miras alması siber güvenlik araçlarında ve API uç noktalarında ne tür yetkilendirme veya mantık hatalarına yol açar?

### 2. Derinlemesine Teknik Analiz
Tip Karışıklığı (CWE-843); bir sistemin belirli bir veri tipinde (örneğin tamsayı, nesne referansı veya ikili tampon) nesne beklediği bir noktada, başka bir tipteki veriyi doğrulamadan işleme alması sonucu ortaya çıkar.

Python özelinde bu durumun en bilinen örneği `bool` ve `int` ilişkisidir:
- Python 2'den kalan geriye dönük uyumluluk nedeniyle `bool`, doğrudan `int` sınıfının bir alt sınıfıdır (`issubclass(bool, int) == True`).
- Bu nedenle `isinstance(True, int)` ifadesi `True` döndürür.
- Eğer bir güvenlik API'si port numarası veya kullanıcı rolü seviyesi (`role_level = 1`) bekliyorsa ve basitçe `if isinstance(val, int):` ile doğrulama yapıyorsa; saldırganın gönderdiği `{"port": True}` veya `{"role_level": True}` girdisi doğrulayıcıyı atlatır ve `1` değeriyle çalışmaya devam eder.
- Benzer şekilde, string beklenen bir alana liste veya sözlük iletilmesi, arka planda string metotları (`.lower()`, `.strip()`) çağrıldığında beklenmeyen `AttributeError` ile servis çökmesine (DoS) yol açar.

Çözüm: Çalışma zamanında (runtime) sıkı tip denetimi yapmak, `isinstance(val, bool)` istisnasını açıkça kontrol etmek veya fonksiyon girişlerinde dekoratör tabanlı tip zorlaması (`@enforce_types`) uygulamaktır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Güvenli bir port ve yetki seviyesi doğrulama fonksiyonu:

```python
def validate_strict_integer(param_name: str, val: object, min_val: int, max_val: int) -> int:
    """Type Confusion saldırılarını önleyen sıkı tamsayı doğrulayıcı."""
    # 1. bool kontrolü (bool bir int'tir tuzağını kır)
    if isinstance(val, bool):
        raise TypeError(f"Güvenlik İhlali: '{param_name}' tamsayı olmalıdır, boolean kabul edilemez (CWE-843)!")
    
    # 2. Kesin int kontrolü
    if not isinstance(val, int):
        raise TypeError(f"'{param_name}' tamsayı (int) olmalıdır, alınan: {type(val).__name__}")
        
    # 3. Sayısal sınır denetimi
    if not (min_val <= val <= max_val):
        raise ValueError(f"'{param_name}' değeri izin verilen [{min_val}, {max_val}] aralığı dışındadır: {val}")
        
    return val
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, dinamik diller sana kod yazarken hız verir ama güvenlikte dikkat etmezsen ayağına sıkar. `isinstance(x, int)` yazdığında Python'un `True` değerini de tamsayı saydığını asla aklından çıkarma. Güvenlik kritik parametrelerde tip denetimini her zaman en sıkı seviyede tutacaksın."

---

## SORU 2: Pozitif Güvenlik Modeli (Allowlist) vs. Negatif Güvenlik Modeli (Denylist) Neden Fark Yaratır?

### 1. Soru Başlığı ve Tanımı
Girdi doğrulama ve sanitizasyon süreçlerinde "Pozitif Güvenlik Modeli" (Allowlist / Whitelist) ile "Negatif Güvenlik Modeli" (Denylist / Blacklist) arasındaki temel fark nedir? Neden endüstri standardı güvenlik mimarileri kara listeleri yetersiz bulup yalnızca beyaz listeyi zorunlu kılar?

### 2. Derinlemesine Teknik Analiz
- **Negatif Model (Kara Liste / Blocklist):**  
  Sistem yalnızca tehlikeli olduğu bilinen belirli karakterleri veya sözcükleri engeller (örneğin `<script>`, `;`, `--`, `rm`). 
  - **Zafiyet Nedeni:** Siber güvenlikte saldırı vektörlerinin kombinasyonu sonsuzdur. Saldırganlar Unicode normalizasyon farklarını (Homoglyphs), URL encoding (`%27`), çift kodlama (`%2527`), null-byte (`%00`) veya komut ayrıştırma hilelerini (`$IFS`, `\`, `""`) kullanarak kara listeyi rahatlıkla atlatır (Bypass).
- **Pozitif Model (Beyaz Liste / Allowlist):**  
  Sistem yalnızca güvenli ve meşru olduğu bilinen kesin karakter kümesini, uzunluğunu ve formatını tanımlar; bunun dışındaki her şeyi varsayılan olarak reddeder (Default Deny prensibi).
  - **Güvenlik Gücü:** Saldırgan ne kadar karmaşık bir enjeksiyon yükü denerse denesin, eğer yük izin verilen regex veya küme (örneğin yalnızca `[a-zA-Z0-9-]`) sınırlarına uymuyorsa kapıda anında engellenir.

Örnek: Bir IP adresi denetiminde "içinde harf olmasın" demek (kara liste) yetersizdir. "Tam 4 oktet olmalı, her oktet 0-255 aralığında tamsayı olmalı ve baştaki sıfırlar bulunmamalıdır" demek (beyaz liste) kurşun geçirmezdir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir güvenlik aracında ağ protokolü ve alan adı doğrulaması:

```python
import re

# Allowlist: Yalnızca desteklenen protokoller
ALLOWED_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "SCTP"})

# Allowlist Regex: Yalnızca RFC-1123 uyumlu alan adı karakterleri
STRICT_HOSTNAME_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")

def validate_protocol_allowlist(proto: str) -> str:
    p = proto.strip().upper()
    if p not in ALLOWED_PROTOCOLS:
        raise ValueError(f"Yetkisiz protokol: '{p}'. İzin verilenler: {ALLOWED_PROTOCOLS}")
    return p

def validate_hostname_allowlist(host: str) -> str:
    h = host.strip().lower()
    if not STRICT_HOSTNAME_REGEX.match(h):
        raise ValueError(f"Geçersiz alan adı formatı: '{h}'. Özel karakterler veya kabuk ayıraçları yasaktır.")
    return h
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kara liste yazmak dünyanın bütün kötülüklerini bir kağıda listelemeye çalışmak gibidir; her gün yeni bir kötülük çıkar ve listen delinir. Beyaz liste ise kapına bir bekçi koyup sadece davetiyesi olan dostları içeri almaktır. Siber güvenlikte huzur, davetiyeli sistemdedir."

---

## SORU 3: Null-Byte Enjeksiyonu (CWE-158) ve Octal IP (CWE-704) Tuzakları Nasıl Çalışır?

### 1. Soru Başlığı ve Tanımı
Girdi doğrulamada sıklıkla gözden kaçan "Null-Byte (`\x00`) Zehirlemesi" (CWE-158) ve "Octal IP Gösterimi" (CWE-704) saldırıları nasıl gerçekleşir? Yüksek seviyeli diller ile alt seviye C/işletim sistemi API'leri arasındaki fark bu açıkları nasıl tetikler?

### 2. Derinlemesine Teknik Analiz
1. **Null-Byte (`\x00`) Zehirlemesi (CWE-158):**
   - C dilinde dizgiler (strings) bellekte sonlandırıcı bir `\0` (null karakter) ile biter. C kütüphanesi dizgiyi okurken `\0` gördüğü anda dizginin bittiğini varsayar.
   - Python ise modern bir dildir ve dizgilerin uzunluğunu ayrı bir alanda tutar; bu sayede string içinde `\x00` bulunabilir.
   - Eğer bir Python betiği dosya adı olarak `rapor.txt\x00.exe` girdisini alır ve uzantının `.txt` ile bitip bitmediğini denetlemeden C tabanlı `open()` sistem çağrısına iletirse; işletim sistemi `\x00` sonrasını görmez ve diske doğrudan `rapor.txt` yazar ya da tersine güvenlik filtrelerini atlatır.
   - Savunma: Herhangi bir girdi alanında `\x00` karakteri tespit edildiği an işlem derhal durdurulmalı ve `NullByteInjectionError` fırlatılmalıdır.
2. **Octal IP Çözümleme Tuzağı (CWE-704):**
   - Bir IP adresi yazılırken oktetin başına sıfır konulursa (örneğin `192.168.010.1`); bazı C kütüphaneleri (örneğin POSIX `inet_aton`) baştaki sıfırı 8'lik taban (octal) olarak yorumlar.
   - 8'lik tabanda `010`, 10'luk tabanda `8` sayısına eşittir. Böylece sistem `192.168.10.1` yerine `192.168.8.1` adresine bağlanır.
   - Saldırganlar bu yöntemle güvenlik duvarı (Firewall) veya SSRF filtrelerini atlatarak kısıtlanmış iç ağlara erişebilir.
   - Savunma: Oktet denetiminde `len(oktet) > 1 and oktet.startswith("0")` kuralıyla baştaki sıfırlar yasaklanmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
```python
def secure_ip_and_filename_check(ip_str: str, filename_str: str) -> None:
    # 1. Null-Byte kontrolü
    if "\x00" in filename_str or "\x00" in ip_str:
        raise ValueError("Kritik Güvenlik İhlali: Null-Byte karakteri tespit edildi (CWE-158)!")
        
    # 2. Octal IP kontrolü
    parts = ip_str.split(".")
    if len(parts) == 4:
        for p in parts:
            if len(p) > 1 and p.startswith("0"):
                raise ValueError(f"Octal IP çözümleme riski: Baştaki sıfırlar yasaktır '{p}' (CWE-704)!")
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, diller arasındaki dikiş izleri saldırganların en sevdiği yarıkları oluşturur. Python ile işletim sistemi çekirdeği arasında veri taşırken C'nin eski alışkanlıklarını asla unutmayacaksın. Bir Null-byte veya bir sıfır, koca bir güvenlik duvarını görünmez kılabilir."
