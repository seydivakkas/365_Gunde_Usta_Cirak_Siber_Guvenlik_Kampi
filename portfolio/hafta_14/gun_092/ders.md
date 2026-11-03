# GÜN 092: Veri Doğrulama ve Tip Güvenliği — Usta-Çırak Siber Güvenlik Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz çoğaltılamaz, dağıtılamaz veya ticari projelerde kullanılamaz.*

---

## 1. Ustanın Giriş Dersi: Siber Güvenliğin Bir Numaralı Kuralı — "Asla Güvenme, Kapıda Doğrula!"

Evlat, yazılım ve siber güvenlik dünyasında her büyük felaketin arkasında tek bir ihmal yatar: **Girdiyi doğrulamadan kabul etmek.**

İster bir web uygulaması, ister bir güvenlik duvarı denetleyicisi, isterse bir adli bilişim ayrıştırıcısı yazıyor ol; dış dünyadan sistemine gelen her veri baytı potansiyel olarak zehirlidir. Saldırgan; bir port numarası beklediğin yere bir SQL enjeksiyonu yükü, bir IP adresi beklediğin yere tampon bellek taşması (Buffer Overflow) dizgisi, ya da bir dosya adı beklediğin yere gizli bir **Null-Byte (`\x00`)** sıkıştırabilir.

Pek çok toy geliştirici, Python gibi dinamik tipli bir dilde kod yazarken "Python zaten veri tiplerini kendi yönetiyor" sanır. Oysa dinamik tipler güvenlik açısından çift tarafı keskin bir kılıçtır. Beklenmeyen bir tip aktarıldığında ya da tip zorlaması (type coercion) yapıldığında **Tip Karışıklığı (Type Confusion - CWE-843)** zafiyeti doğar.

Usta der ki: **"Bir fonksiyonun kapısında bekçi yoksa, içeriye giren her parametre potansiyel bir Truva Atıdır. Verinin tipi, uzunluğu, karakter kümesi ve anlamsal sınırları matematiksel olarak doğrulanmadıkça hiçbir işlem yürütülmemelidir."**

---

## 2. Dinamik Tiplerin Tuzağı: Type Confusion (CWE-843) ve Python'un `bool` Mirası

Python'da tip güvenliği konusunda geliştiricilerin en sık düştüğü ölümcül tuzaklardan biri `bool` ile `int` ilişkisidir:

```python
# PYTHON'UN TARİHSEL MİRASI:
issubclass(bool, int)  # True döner!
isinstance(True, int)  # True döner!
True + True            # 2 döner!
```

Eğer yazdığın güvenlik tarayıcısında port numarasını doğrulamak için sadece `isinstance(port, int)` kontrolü yaparsan; bir saldırgan veya bozuk bir API nesnesi sisteme `{"port": True}` gönderdiğinde bu doğrulama geçer ve Python bunu `1` numaralı port olarak kabul eder! Bu durum, mantıksal parametre zehirlemesine ve yetkilendirme atlamalarına yol açar.

Bu yüzden kurumsal güvenlik kodunda:
```python
if isinstance(val, bool) or not isinstance(val, int):
    raise TypeValidationError("Port değeri kesinlikle tamsayı olmalıdır, bool kabul edilemez!")
```
şeklinde açık ve katı tip kontrolleri zorunludur.

---

## 3. Pozitif Güvenlik Modeli (Allowlist) vs. Negatif Güvenlik Modeli (Denylist)

Girdi doğrulamada iki felsefe vardır:
1. **Negatif Güvenlik Modeli (Kara Liste / Blocklist):**
   "Kötü olduğunu bildiğim karakterleri engellerim" yaklaşımıdır (örn: `<script>` veya `' OR 1=1`). Bu yaklaşım her zaman çökmeye mahkumdur; çünkü saldırganlar filtreyi aşmak için Unicode varyasyonları, URL encoding, octal IP veya beklenmeyen karakter dizilimleri bulur.
2. **Pozitif Güvenlik Modeli (Beyaz Liste / Allowlist):**
   "Yalnızca geçerli olduğunu kesin olarak bildiğim biçim ve karakter kümesine izin veririm, geri kalan her şeyi doğrudan reddederim" yaklaşımıdır.

Siber güvenlikte standart daima **Allowlist** modelidir. Örneğin bir protokol doğrulanırken:
```python
ALLOWED_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "SCTP"})
if proto not in ALLOWED_PROTOCOLS:
    raise ValueRangeError(f"Geçersiz protokol: {proto}")
```

---

## 4. Kritik Siber Güvenlik Veri Tipleri ve Doğrulama Standartları

### A. IPv4 Adres Doğrulaması (Octal Karışıklığı ve Sınırlar)
Bir IPv4 adresi 4 oktetten oluşur ve her oktet $0 \le oktet \le 255$ aralığında olmalıdır.
- **Octal IP Tuzağı:** `192.168.01.1` gibi baştaki sıfırlar bazı işletim sistemleri (Linux `inet_aton`) tarafından 8'lik taban (octal) olarak yorumlanır ve `192.168.1.1` yerine bambaşka bir IP'ye çözümlenir (**CWE-704**). Doğrulayıcımız `len(parca) > 1 and parca.startswith("0")` kontrolüyle bunu anında engeller.

### B. Sayısal Sınır Aşımı (Port Sınırları - CWE-1284)
TCP/UDP portları 16-bit işaretsiz tamsayıdır:
$$1 \le \text{Port} \le 65535$$
0 portu rezerve edilmiştir, 65535'in üstü ise TCP başlığına sığmaz. Bu sınırın dışındaki her girdi derhal `PortRangeError` ile reddedilmelidir.

### C. Hostname ve RFC-1123 Standartları (CWE-88)
Alan adları yalnızca alfanümerik karakterler ve tire (`-`) içerebilir; tire ile başlayamaz veya bitemez.
- En önemlisi: Hostname parametresine asla `;`, `|`, `&`, `` ` ``, `$`, `>`, `<` gibi kabuk metakarakterleri sızamaz. Aksi takdirde arka planda `nslookup $host` veya `ping -c 1 $host` çağrısı yapıldığında sistem doğrudan ele geçirilir.

### D. Null-Byte (`\x00`) Zehirlemesi (CWE-158)
C tabanlı kütüphaneler (işletim sistemi dosya çağrıları) dizgileri Null-Byte karakteriyle sonlandırır. Python ise dizgilerin uzunluğunu ayrı bir değişkende tutar. Bir saldırgan `ast-01\x00.exe` gibi bir girdi yollarsa, Python tüm dizgiyi görürken arka plandaki C kütüphanesi sadece `ast-01` kısmını okur. Doğrulama motorumuz girdi içinde `\x00` gördüğü an `NullByteInjectionError` fırlatır.

### E. Kriptografik SHA-256 Doğrulaması
Bütünlük denetimlerinde kullanılan SHA-256 özetleri tam olarak 64 karakter uzunluğunda olmalı ve yalnızca `[0-9a-fA-F]` karakterlerinden oluşmalıdır.

---

## 5. Çalışma Zamanı Tip Güvenliği: `@enforce_types` Dekoratörü

Python'un tip ipuçları (`type hints`) varsayılan olarak yalnızca IDE'lerde görsel uyarı verir, çalışma anında bir şey yapmaz. Bizim geliştirdiğimiz `@enforce_types` dekoratörü ise:
```python
@enforce_types
def execute_security_action(target_ip: str, port: int, is_active: bool) -> None:
    ...
```
çağrıldığı anda fonksiyon imzasını (`inspect.signature`) ve tip ipuçlarını (`get_type_hints`) inceler. Eğer birisi `port="443"` ya da `is_active=1` gönderirse derhal `TypeValidationError` fırlatarak zafiyetin oluşmasını kapıda engeller.

---

## 6. Çırağa Öğütler ve Altın Kurallar

1. **Girdiyi Asla Doğrudan Kullanma:** Kullanıcıdan, bir formdan, bir JSON'dan veya bir ortam değişkeninden gelen veriyi asla filtreden geçirmeden bir fonksiyona sokma.
2. **Değiştirilemez (Immutable) Varlıklar Tasarla:** Güvenlik nesnelerini `@dataclass(frozen=True)` olarak tanımla ki, doğrulandıktan sonra bellekte hiçbir fonksiyon yanlışlıkla o nesnenin alanlarını değiştiremesin.
3. **Açık ve Anlaşılır Hatalar Üret:** Doğrulama başarısız olduğunda sistem çökmemeli; hatanın hangi alanda ve hangi kural ihlali yüzünden çıktığını belirten net güvenlik istisnaları üretilmelidir.
