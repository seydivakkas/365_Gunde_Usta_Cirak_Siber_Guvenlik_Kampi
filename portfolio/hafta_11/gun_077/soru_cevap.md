# GÜN 077: MİNİ PROJE 10 — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G077-SC1: Heterojen Log Ayrıştırmada Çoklu Savunmacı Regex Mimarisi ve Bilinmeyen Formatların Güvenli İzolasyonu

#### Soru Başlığı ve Tanımı
Kurumsal ağlarda merkezi bir log toplayıcıya (SIEM / Syslog Server) gelen akış tek tip değildir; web sunucusu (Apache/Nginx), işletim sistemi kimlik doğrulama (SSHD) ve çekirdek güvenlik duvarı (iptables/Netfilter) logları aynı hatta akar. Tek bir Python betiğinde çoklu regex mimarisi nasıl kurulmalıdır ve tanımlı şablonlara uymayan malforme/bozuk satırlar sistemin çökmesini engellemek için nasıl izole edilmelidir?

#### Derinlemesine Teknik Analiz
Çok formatlı heterojen log ayrıştırma motorunda en büyük risk, ayrıştırıcının beklenmeyen bir karakter dizisi veya format uyuşmazlığı karşısında `AttributeError`, `IndexError` veya `ValueError` fırlatarak tüm akış hattını (pipeline) durdurmasıdır.

**Mimari Tasarım İlkeleri:**
1. **Önceden Derlenmiş ve Sıralı Eşleştirme:**
   Her log biçimi için sınıf seviyesinde `re.compile()` ile derlenmiş bağımsız bir desen tanımlanır (`WEB_PATTERN`, `SSHD_PATTERN`, `FIREWALL_PATTERN`). Regex desenleri en sık görülen veya en seçici olandan başlanarak ardışık olarak sınanır.
2. **Kapsayıcı ve Güvenli Fall-Through (Bilinmeyen Format İzolasyonu):**
   Eğer gelen satır hiçbir regex kalıbıyla eşleşmezse, sistem kesinlikle istisna fırlatıp çökmemelidir. Bunun yerine satır güvenli şekilde etiketlenir:
   `{"log_type": "UNRECOGNIZED", "raw_line": clean_line, "status": "PARSE_SKIPPED"}`
   Bu kayıt izole bir "ayrıştırılamayanlar" kuyruğuna aktarılır ve sayaç artırılır. Böylece hat boyunca akan meşru ve kritik logların işlenmesi asla aksamaz.
3. **Katı Sınır Doğrulaması:**
   Ayrıştırılan alanlar (`ip`, `status`, `port`) sözlükten alındığı gibi bırakılmamalı; `ipaddress.ip_address()` ve `int()` tip dönüşümleriyle sözdizimsel olarak doğrulanmalıdır.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankanın SOC merkezinde logları işleyen bir betik çalışmaktadır. Bir saldırgan ağa bilerek bozuk ikili (binary) çöp veri ve UTF-8 dışı baytlar göndermiştir. Betik `match.group(1)` satırında `AttributeError: 'NoneType' object has no attribute 'group'` hatası vererek çökmüş, log akışı durduğu için saldırganın 10 dakika boyunca yürüttüğü veri sızdırma operasyonu SIEM panellerine hiç yansımamıştır.

**Savunmacı ve Dayanıklı Çözüm:**
```python
def parse_heterogeneous_log(line: str) -> dict:
    # 1. Ön temizlik ve uzunluk denetimi
    if len(line) > 4096 or "\x00" in line:
        return {"log_type": "MALFORMED_DROP", "status": "DROPPED"}
        
    # 2. Sıralı güvenli eşleştirme
    web_m = WEB_PATTERN.match(line)
    if web_m:
        return process_web_log(web_m.groupdict())
        
    ssh_m = SSHD_PATTERN.match(line)
    if ssh_m:
        return process_ssh_log(ssh_m.groupdict())
        
    fw_m = FIREWALL_PATTERN.match(line)
    if fw_m:
        return process_fw_log(fw_m.groupdict())
        
    # 3. Çökmeyen güvenli izolasyon
    return {"log_type": "UNRECOGNIZED", "raw_line": line, "status": "LOGGED_FOR_AUDIT"}
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, güvenlik motorunun birincil kuralı 'asla devrilmemektir' (Zero Downtime). Karşıdan ne kadar çamurlu su (bozuk log) gelirse gelsin, motorun suyu süzecek ama tıkanıp patlamayacak. Bilmediğin formatı düşman belleyip sistemi kapatmayacaksın; onu nazikçe 'UNRECOGNIZED' sepetine koyup yoluna devam edeceksin!"

---

### G077-SC2: URL Kodlama (URL Encoding / %20) Arkasına Gizlenen Web Saldırı İmzalarının Kanonikleştirme ile Tespiti

#### Soru Başlığı ve Tanımı
Web uygulaması saldırılarında (SQL Injection, Cross-Site Scripting, Directory Traversal), saldırganlar WAF ve log analiz filtrelerini atlatmak için URI içinde karakterleri URL kodlaması (Percent-Encoding, örn. `%20`, `%2e%2e%2f`) arkasına gizlerler. Güvenlik imzası denetimi yapan bir log ayrıştırıcı neden ham URI üzerinde arama yapmamalıdır? `urllib.parse.unquote_plus()` ile kanonikleştirme (canonicalization) yapılmamasının doğurduğu güvenlik açığı nedir?

#### Derinlemesine Teknik Analiz
Bir web sunucusu (Apache/Nginx/IIS), istemciden gelen HTTP isteğini işlerken RFC 3986 uyarınca URL kodlu karakterleri çözer. Ancak sunucunun erişim loguna (access.log) yazılan URI çoğu zaman istemcinin gönderdiği **ham (raw / encoded)** biçimdir:

Örnek ham log satırı:
`GET /products.php?id=1%20UNION%20SELECT%20null,password%20FROM%20users HTTP/1.1`

Eğer güvenlik kural motorunda imza şu şekilde tanımlanmışsa:
$$\text{Signature} = \text{r"(?i)UNION\textbackslash s+SELECT"}$$

Bu regex, `UNION` kelimesinden sonra bir veya daha fazla boşluk (`\s`) arar. Ancak ham URI içinde `UNION` ile `SELECT` arasında bir boşluk karakteri (ASCII 32) yoktur; `%20` karakter dizisi (ASCII 37, 50, 48) bulunmaktadır!
- Ham dize üzerinde `compiled_re.search(raw_uri)` çalıştırıldığında eşleşme **sağlanamaz** (`None` döner).
- Saldırı WAF/Log ayrıştırıcı tarafından "masum bir GET isteği" olarak değerlendirilir.
- Oysa web sunucusu ve arka uç veritabanı `%20`'yi boşluk olarak çözer ve SQL Injection başarıyla icra edilir!

**Savunmacı Kanonikleştirme Çözümü:**
Tüm imza ve kural taramalarından önce URI kanonik (çözülmüş) biçimine dönüştürülmelidir:
$$\text{Kanonik URI} = \text{urllib.parse.unquote\_plus}(raw\_uri)$$
`unquote_plus` metodu hem `%20` kodlarını hem de form verilerinde boşluk anlamına gelen `+` işaretlerini standart boşluk karakterine dönüştürür.
Ardından savunmacı motor hem ham URI'yi hem de kanonikleştirilmiş URI'yi eşzamanlı test ederek enjeksiyonu yakalar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kamu kurumunun log inceleme yazılımı, web sunucu loglarında `UNION SELECT` ve `../../etc/passwd` aramaktadır. Saldırgan `sqlmap` aracına `--tamper=space2comment` veya standart URL encoding bayrağı vererek tüm boşlukları `%20` ve noktaları `%2e%2e` olarak kodlamıştır. Log motoru hiçbir tehdit alarmı üretmemiş, kurumun 50.000 vatandaşlık veritabanı sessizce sızdırılmıştır.

**Savunmacı İmza Kontrol Motoru:**
```python
import urllib.parse

def check_web_attack_signatures_pure(raw_uri: str, signatures: list) -> list:
    # 1. URL kodlaması çözülerek kanonik form elde edilir
    canonical_uri = urllib.parse.unquote_plus(raw_uri)
    
    detected_attacks = []
    for sig in signatures:
        # Hem ham hem kanonik dize test edilir (Çift Bariyer İlkesi)
        if sig["re"].search(raw_uri) or sig["re"].search(canonical_uri):
            detected_attacks.append(sig["name"])
            
    return detected_attacks
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! Saldırgan asla kapıdan takım elbiseyle girmez; kılık değiştirir, şapka takar, gözlük takar (%20, %2e, Unicode). Sen log ayrıştırıcı olarak kapıdaki dedektifsin. Şapkasını çıkarmadan (URL unquote yapmadan) kimsenin yüzünü tanıyamazsın. Girdiyi önce çırılçıplak soyup kanonik formuna getireceksin, sonra imza dedektörünün önüne koyacaksın!"

---

### G077-SC3: Siber Olay Müdahalesinde (DFIR) Kayan Pencere (Sliding Window) Brute-Force Tespiti ve Dinamik IP Bloklama

#### Soru Başlığı ve Tanımı
Geleneksel sayaçlar (`failed_attempts[ip] += 1`), zamandan bağımsız olarak hatalı girişleri toplar veya her saat başında sıfırlanır (Fixed Window). Kötü niyetli bir saldırgan saat başı sıfırlanan sayaçları nasıl atlatır? Kayan Pencere (Sliding Window) algoritması zaman tabanlı kaba kuvvet saldırılarını (Brute-Force) nasıl matematiksel kesinlikle yakalar?

#### Derinlemesine Teknik Analiz
Sabit zaman pencerelerinde (Fixed Window, örn. 12:00:00 - 12:01:00 arası 5 hata limiti):
- Saldırgan saat 12:00:55'te 4 deneme yapar.
- Saat 12:01:00'da pencere sıfırlanır.
- Saldırgan saat 12:01:05'te 4 deneme daha yapar.
- **Sonuç:** Saldırgan 10 saniye içinde 8 parola denemiştir ancak hiçbir pencerede limit (5) aşılmadığı için kilit mekanizması asla tetiklenmez!

**Kayan Pencere (Sliding Window) Algoritması:**
Kayan pencerede zaman dilimleri statik bloklar değildir; **mevcut anın geriye doğru $T$ saniyelik dinamik kesitidir**.

Algoritma Adımları:
1. Her kaynak IP için başarısız girişlerin zaman damgaları (`timestamp`) bir kuyrukta (list/deque) tutulur:
   $$\text{Attempts}(IP) = [t_1, t_2, t_3, \dots, t_n]$$
2. Yeni bir başarısız giriş ($t_{now}$) geldiğinde:
   - $t_{now}$ listeye eklenir.
   - Pencere sınırı hesaplanır: $t_{limit} = t_{now} - \Delta T$ (örn. $t_{now} - 60 \text{ sn}$).
   - $t_{limit}$'ten daha eski olan tüm zaman damgaları listeden atılır ($O(K)$ temizlik):
     $$\text{Attempts}(IP) = [t \in \text{Attempts}(IP) \mid t \ge t_{limit}]$$
3. Kalan eleman sayısı test edilir:
   $$\text{len}(\text{Attempts}(IP)) \ge \text{Threshold}$$
   Eğer koşul sağlanırsa, saldırganın 60 saniyelik herhangi bir hareketli pencere içinde eşiği aştığı matematiksel olarak kesinleşir ve IP derhal bloklanır (`locked_out_ips.add(ip)`).

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumsal Linux sunucusunda çalışan `fail2ban` benzeri bir güvenlik betiği sabit sayaç kullandığı için, saldırgan saatte 200 denemeyi 59. ve 01. saniyelere dağıtarak 3 gün boyunca parola denemiş ve sonunda bir servis hesabının parolasını kırarak sisteme sızmıştır.

**Savunmacı Kayan Pencere İmplementasyonu:**
```python
import collections
import time

class SlidingWindowRateLimiter:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window = window_seconds
        self.ip_history = collections.defaultdict(list)
        self.locked_ips = set()
        
    def record_failure(self, ip: str) -> bool:
        now = time.time()
        self.ip_history[ip].append(now)
        
        # Kayan pencere temizliği
        cutoff = now - self.window
        self.ip_history[ip] = [t for t in self.ip_history[ip] if t >= cutoff]
        
        # Eşik kontrolü
        if len(self.ip_history[ip]) >= self.threshold:
            self.locked_ips.add(ip)
            return True # Kilitlendi!
            
        return False
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, zaman statik bir takvim yaprağı değildir; akan bir nehirdir. Saldırgan senin saat başı nöbet değiştiğini (sayacın sıfırlandığını) bildiği an nöbet değişim saatinde içeri sızar. Güvenlik mekanizman her an, her saniye son 60 saniyelik nehir akıntısını (kayan pencereyi) gözleyecek. Ancak o zaman hiçbir kaba kuvvet saldırganı senin kapından geçemez!"
