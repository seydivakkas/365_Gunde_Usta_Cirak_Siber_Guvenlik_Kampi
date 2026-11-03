# GÜN 090: Tarih-Saat, UTC ve Saat Dilimi — Usta-Çırak Siber Güvenlik Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz çoğaltılamaz, dağıtılamaz veya ticari projelerde kullanılamaz.*

---

## 1. Ustanın Giriş Dersi: Siber Güvenlikte Zaman Neden Hayatidir?

Evlat, siber güvenlikte saldırganlar ardında iz bırakır; ama bu izleri birleştiren tutkal **zamandır**. 

Bir kurum siber saldırıya uğradığında, birbiriyle ilgisiz görünen yüzlerce farklı kaynaktan log yağar:
- İstanbul ofisindeki yerel web sunucusu (UTC+03:00),
- Londra'daki API ağ geçidi (UTC+00:00),
- New York veri merkezindeki Active Directory etki alanı denetleyicisi (UTC-04:00 veya Windows FileTime formatında),
- Tokyo'daki sınır güvenlik duvarı (UTC+09:00),
- Ve bulutta çalışan mikroservislerin Unix Epoch saniyeleri.

Eğer bir adli bilişim (DFIR - Digital Forensics and Incident Response) uzmanı veya SOC analisti zaman damgalarını tek bir küresel referansa, yani **UTC (Coordinated Universal Time)** standardına normalize etmeyi bilmezse; saat 14:00'te olan bir saldırıyı saat 11:00'de olmuş sanır, saldırganın ilk sızma noktasını (Patient Zero) yanlış belirler ve olayın kök nedenini (Root Cause) asla çözemez.

Daha da fenası: Bir kimlik doğrulama sisteminde saat dilimi veya saat sapması (Clock Skew) doğru yönetilmezse, Kerberos biletleri reddedilir veya saldırganlar eski bir oturum belirtecini (Token) tekrar kullanarak **Yeniden Oynatma Saldırısı (Replay Attack - CWE-1385)** gerçekleştirir.

Usta der ki: **"Siber güvenlikte 'yerel saat' diye bir şey yoktur; yalnızca UTC vardır. Yerel saat yalnızca insanoğlunun kolundaki saatte güzel durur; loglarda ve güvenlik protokollerinde ise bir felakettir."**

---

## 2. Naive vs. Aware Datetime: Python'daki Büyük Güvenlik Tuzağı

Python geliştiricilerinin düştüğü en büyük tuzak **"Naive Datetime"** kullanmaktır:

```python
# YANLIŞ VE TEHLİKELİ (Naive Datetime)
from datetime import datetime
simdi = datetime.now()  # Saat dilimi bilgisi yok! (tzinfo is None)
```

Naive bir datetime nesnesi, sistemin o an hangi coğrafyada çalıştığını bilmez. Bir Linux sunucuda sunucu saati UTC olarak yapılandırılmışken, bir analistin Windows laptopunda UTC+3 olarak çalışabilir. İki naive tarih birbirinden çıkarıldığında Python hiçbir hata vermeden 3 saatlik gizli bir zaman kayması hesaplar.

Dahası, yıllarca kullanılan `datetime.utcnow()` fonksiyonu da Python 3.12 ile birlikte **resmen kullanımdan kaldırılmıştır (deprecated)**; çünkü `utcnow()` fonksiyonu saat dilimi bilgisi olmayan bir naive nesne döndürüyordu!

### Doğru ve Güvenli Yaklaşım (Timezone-Aware Datetime):
```python
# DOĞRU VE MODERN (Timezone-Aware Datetime)
from datetime import datetime, timezone

# Her zaman açıkça UTC belirtilmelidir
guvenli_simdi = datetime.now(timezone.utc)
assert guvenli_simdi.tzinfo == timezone.utc
```

---

## 3. Saat Sapması (Clock Skew) ve Replay Attack Savunması

Dağıtık sistemlerde iki sunucunun saati fiziksel donanım, NTP gecikmeleri veya sanallaştırma kaynaklı olarak milisaniyeler veya saniyeler mertebesinde kayabilir. Buna **Saat Sapması (Clock Skew)** denir.

### Kerberos ve OAuth Protokollerinde Zaman Eşiği:
- **Kerberos Protokolü:** Bir istemci KDC'den (Key Distribution Center) aldığı TGT veya TGS biletini servis sunucusuna sunduğunda, biletin oluşturulma zamanı ile sunucunun anlık zamanı karşılaştırılır. Eğer fark **300 saniyeden (5 dakika)** büyükse, bilet `KRB_AP_ERR_SKEW` hatasıyla reddedilir.
- **Neden 5 Dakika?** Çünkü eğer bu tolerans çok geniş tutulursa (örneğin 1 saat), saldırgan ağdan dinlediği (sniff ettiği) bir kimlik doğrulama paketini 50 dakika sonra tekrar hedefe yollayarak sisteme sızabilir (**Replay Attack - CWE-1385**).
- **JWT (JSON Web Token):** `nbf` (Not Before) ve `exp` (Expiration) alanları değerlendirilirken de mutlaka küçük bir saat sapması payı (leeway) bırakılmalı, ancak bu pay asla oturum güvenliğini tehlikeye atacak boyutlara ulaşmamalıdır.

Formül:
$$\Delta t = |T_{\text{istemci\_UTC}} - T_{\text{referans\_UTC}}|$$
Eğer $\Delta t > \Delta t_{\text{maks}}$ (örneğin 300 saniye) ise istek derhal reddedilmeli ve güvenlik alarmı üretilmelidir.

---

## 4. Farklı Zaman Formatlarının Adli Analizi ve Matematiksel Dönüşümü

Siber güvenlik analizinde karşına çıkacak 3 temel zaman formatı:

### A. ISO-8601 ve RFC-3339
Uluslararası standart formattır: `YYYY-MM-DDTHH:MM:SSZ` veya `YYYY-MM-DDTHH:MM:SS+HH:MM`.
Sondaki `Z` harfi "Zulu" (sıfır meridyeni / UTC) anlamına gelir.

### B. Unix Epoch (POSIX Time)
1 Ocak 1970 00:00:00 UTC tarihinden beri geçen saniye sayısıdır.
- Saniye formatı (10 hane): `1793543415`
- Milisaniye formatı (13 hane): `1793543415000`
- Mikrosaniye formatı (16 hane): `1793543415000000`

### C. Windows FileTime (Active Directory & NTFS)
Windows işletim sistemlerinde dosya sistemleri (NTFS) ve Active Directory kayıtları zamanı 1 Ocak 1601 UTC tarihinden itibaren geçen 100 nanosaniyelik aralıklarla (intervals) saklar. 64-bitlik büyük bir tamsayıdır.
Dönüşüm matematiği:
$$\text{Unix Saniyesi} = \frac{\text{FileTime} - 116444736000000000}{10000000}$$

---

## 5. Çırağa Öğütler ve Altın Kurallar

1. **Log Kaydederken Asla Yerel Saat Kullanma:** Bütün sistemlerini, veritabanlarını ve betiklerini log üretirken doğrudan ISO-8601 UTC formatında (`%Y-%m-%dT%H:%M:%SZ`) yazmaya zorla.
2. **Kullanıcı Girdisi Zaman Damgalarına Asla Güvenme:** Bir API'ye dışarıdan iletilen `timestamp` parametresi daima sunucu saatiyle karşılaştırılmalı ve saat sapması toleransını aşan talepler reddedilmelidir.
3. **NTP Senkronizasyonunu İzle:** Altyapındaki tüm sunucuların güvenilir yerel veya kurumsal NTP (Network Time Protocol) sunucularıyla senkronize olduğundan emin ol. Saati kaymış bir sunucu, güvenlik loglarını geçersiz kılar.
