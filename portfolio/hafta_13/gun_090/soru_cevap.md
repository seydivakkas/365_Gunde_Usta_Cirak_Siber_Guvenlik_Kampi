# GÜN 090: Tarih-Saat, UTC ve Saat Dilimi — Mülakat ve Saha Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap seti yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz paylaşılamaz veya çoğaltılamaz.*

---

## SORU 1: Naive vs. Aware Datetime Ayrımı Nedir ve Neden Güvenlik Açıklarına (CWE-613) Yol Açar?

### 1. Soru Başlığı ve Tanımı
Python'da ve yazılım güvenliğinde "Naive Datetime" ile "Timezone-Aware Datetime" arasındaki fark nedir? Saat dilimi bilgisi içermeyen zaman damgalarının kimlik doğrulama, oturum sonlandırma ve log korelasyonunda kullanılması ne gibi kritik güvenlik açıklarına (CWE-613) yol açar?

### 2. Derinlemesine Teknik Analiz
Python `datetime` nesnelerinde saat dilimi farkındalığı `tzinfo` özniteliğiyle belirlenir:
- **Naive Datetime (`tzinfo is None`):** Zaman damgasının hangi meridyene, saat dilimine veya yaz saati uygulamasına (DST - Daylight Saving Time) ait olduğu belirsizdir. Sistem bunu anlamsız bir sayı dizisi olarak tutar.
- **Aware Datetime (`tzinfo is not None`):** Zaman damgası mutlak bir referansa (örneğin UTC veya belirli bir GMT ofsetine) bağlıdır.

**Güvenlik Riski (CWE-613 / Yetersiz Oturum Süresi):**  
Bir web uygulamasında kullanıcının oturum süresi (session timeout) 30 dakika olarak belirlenmiş olsun. Sunucu oturum bitiş zamanını naive datetime olarak `2026-11-01 14:30:00` şeklinde veritabanına kaydederse;
1. Farklı bir saat dilimindeki mikroservis (örneğin UTC+3 olan İstanbul sunucusu) bu tarihi UTC olarak yorumlarsa oturumu hemen kapatabilir ya da 3 saat fazladan açık tutabilir.
2. Yaz saati uygulaması geçiş gecesinde (Daylight Saving Time) saatler 1 saat geri alındığında, oturumlar veya tek kullanımlık tokenlar fazladan 1 saat geçerli kalabilir.
3. Adli bilişimde farklı sunuculardan toplanan naive loglar birleştirildiğinde kronolojik sıra altüst olur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankacılık API'sinde oturum açma tokenlarının doğrulanması:

```python
from datetime import datetime, timezone, timedelta

def is_token_expired(token_expire_time_str: str) -> bool:
    """
    Token süresinin dolup dolmadığını kesin UTC zamanıyla denetler.
    Naive zaman damgalarını güvenlik gereği reddeder.
    """
    # 1. ISO formatından ayrıştır
    dt = datetime.fromisoformat(token_expire_time_str.replace("Z", "+00:00"))
    
    # 2. Saat dilimi farkındalığını (aware) zorunlu kıl
    if dt.tzinfo is None:
        raise ValueError("Güvenlik İhlali: Naive zaman damgası kabul edilemez!")
    
    # 3. Anlık zamanı kesinlikle timezone.utc ile al (datetime.utcnow() DEPRECIATED oldu!)
    anlik_utc = datetime.now(timezone.utc)
    
    # 4. UTC seviyesinde mutlak karşılaştırma yap
    return anlik_utc > dt.astimezone(timezone.utc)
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kodunda `datetime.now()` veya eski `datetime.utcnow()` gördüğün an kırmızı alarm çalmalıdır. Python 3.12 ile birlikte `utcnow()` resmen kullanımdan kaldırıldı çünkü geliştiricilere sahte bir güven veriyordu. Her zaman `datetime.now(timezone.utc)` kullanacaksın. Saat dilimsiz zaman, hedefi olmayan mermiye benzer; nereye çarpacağı belli olmaz."

---

## SORU 2: Saat Sapması (Clock Skew) Nedir ve Replay Attack (CWE-1385) Saldırılarına Karşı Nasıl Korunulur?

### 1. Soru Başlığı ve Tanımı
Dağıtık mimarilerde (Kerberos, OAuth 2.0, JWT, AWS API) "Saat Sapması" (Clock Skew) neyi ifade eder? İstemci ile sunucu arasındaki zaman farkının denetlenmemesi veya gereğinden fazla esnek tutulması ne tür saldırılara (Replay Attack - CWE-1385) zemin hazırlar?

### 2. Derinlemesine Teknik Analiz
Dağıtık sistemlerde sunucuların donanımsal kristal osilatörleri, ağ gecikmeleri veya sanallaştırma yükleri nedeniyle sistem saatleri birebir aynı mikrosaniyede kalamaz. İstemcinin saati ile yetkilendirme sunucusunun saati arasındaki bu $\Delta t$ farkına **Clock Skew** denir.

Güvenlik protokolleri istemciden gelen isteklerin zaman damgası içermesini şart koşar (`timestamp`, `iat`, `exp`). 
- Eğer sunucu istemcinin saatini olduğu gibi kabul eder ve zaman kontrolü yapmazsa; saldırgan ağ trafiğini dinleyerek ele geçirdiği meşru bir kimlik doğrulama paketini saatler veya günler sonra sunucuya tekrar gönderir (**Replay Attack**).
- Eğer sunucu çok katı davranıp $\Delta t = 0$ saniye şartı ararsa; en ufak ağ gecikmesinde meşru kullanıcılar sistemden atılır (False Positive / Denial of Service).

Bu nedenle endüstri standardı protokollerde (özellikle RFC 4120 Kerberos V5 ve RFC 7519 JWT):
1. **İzin Verilen Saat Sapması (Clock Skew Tolerance):** Kerberos için standart olarak en fazla **300 saniyedir (5 dakika)**.
2. **Replay Cache (Tekrar Oynatma Önbelleği):** 5 dakikalık bu pencere içinde aynı `authenticator` (istemci kimliği + zaman damgası) ikinci kez gelirse sunucu bunu önbellekten yakalayıp engeller.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir API Gateway üzerinde gelen isteklerin zaman damgası doğrulaması:

```python
from datetime import datetime, timezone

MAX_CLOCK_SKEW_SECONDS = 300  # 5 dakika

def validate_request_timestamp(client_timestamp_iso: str) -> bool:
    """İstemci zaman damgasını saat sapması ve Replay Attack riskine karşı denetler."""
    # İstemci zamanını UTC'ye çevir
    client_dt = datetime.fromisoformat(client_timestamp_iso.replace("Z", "+00:00")).astimezone(timezone.utc)
    server_dt = datetime.now(timezone.utc)
    
    # Mutlak sapmayı hesapla
    skew = abs((client_dt - server_dt).total_seconds())
    
    if skew > MAX_CLOCK_SKEW_SECONDS:
        # Saat sapması çok büyük: İstek ya bayat (replay) ya da istemci saati bozuk
        return False
        
    return True
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, saat sapması toleransını bir lastik gibi gereğinden fazla esnetirsen, araya giren saldırgan o boşlukta cirit atar. Kerberos'un 5 dakikalık altın kuralını aklından çıkarma. Eğer bir sistemde token sürelerini 24 saat yapıp saat sapmasını denetlemiyorsan, sisteminin kapısını açık bırakmışsın demektir."

---

## SORU 3: Adli Bilişimde (DFIR) Heterojen Log Kaynakları ve Windows FileTime Dönüşümü Nasıl Yapılır?

### 1. Soru Başlığı ve Tanımı
Bir siber olay müdahalesinde (Incident Response); Linux Syslog, Nginx erişim logları, Unix Epoch kullanan IoT sensörleri ve Windows Active Directory'den gelen Windows FileTime kayıtları tek bir ortak zaman çizgisine (Forensic Timeline) nasıl oturtulur? Windows FileTime'ın matematiksel dönüşüm mantığı nedir?

### 2. Derinlemesine Teknik Analiz
Olay müdahalesinde bir saldırının başlangıç anı (Initial Access), ayrıcalık yükseltme (Privilege Escalation) ve veri sızdırma (Data Exfiltration) adımları farklı sunucularda gerçekleşir. Farklı işletim sistemleri zamanı farklı formatlarda saklar:
1. **Unix Epoch:** 1 Ocak 1970 00:00:00 UTC başlangıçlı saniye değeridir.
2. **Windows FileTime:** Microsoft sistemleri (NTFS `$MFT`, Active Directory `lastLogonTimestamp`, Windows Olay Günlükleri) zamanı **1 Ocak 1601 UTC** tarihinden itibaren geçen **100 nanosaniyelik aralıklarla** (ticks) 64-bit tamsayı olarak tutar.

1601 yılı ile 1970 yılı arasında tam 369 yıl, yani **11,644,473,600 saniye** fark vardır. 
Bunu 100 nanosaniyelik adımlara dönüştürdüğümüzde ($10^7$ ile çarptığımızda) karşımıza sihirli sabit sayı çıkar:
$$\text{Fark} = 116,444,736,000,000,000$$

Dolayısıyla bir Windows FileTime tamsayısını Unix Epoch saniyesine dönüştürmek için:
$$\text{Unix Saniyesi} = \frac{\text{FileTime} - 116444736000000000}{10000000}$$
formülü uygulanır ve elde edilen saniye UTC datetime nesnesine dönüştürülür.

Tüm kaynaklar UTC saniyesine indirgendikten sonra adli bilişim analisti olayları basit bir sayısal sıralama (`sort by epoch_seconds`) ile kesin bir kronolojik zaman çizgisine dizebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Active Directory `lastLogonTimestamp` alanının Python ile adli çözümlenmesi:

```python
from datetime import datetime, timezone

WINDOWS_TICK = 10000000
SEC_TO_UNIX_EPOCH = 116444736000000000

def parse_windows_filetime(filetime_int: int) -> datetime:
    """Windows 64-bit FileTime değerini standart UTC datetime nesnesine dönüştürür."""
    if filetime_int <= SEC_TO_UNIX_EPOCH:
        raise ValueError("Geçersiz veya Unix öncesi FileTime değeri!")
        
    unix_seconds = (filetime_int - SEC_TO_UNIX_EPOCH) / WINDOWS_TICK
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)

# Örnek AD Kaydı: 134374314050000000
dt = parse_windows_filetime(134374314050000000)
print(f"Adli Çözümlenmiş UTC Zamanı: {dt.strftime('%Y-%m-%dT%H:%M:%SZ')}")
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, adli bilişimde zaman çizgisi hazırlarken tek bir formatı kaçırırsan, suçluyu mağdur, mağduru suçlu durumuna düşürebilirsin. Windows dünyasına girdiğinde o 18 haneli devasa sayılardan korkma; arkasındaki 1601 matematiğini bildiğin sürece en karmaşık Active Directory saldırısını bile saniyesi saniyesine gün ışığına çıkarırsın."
