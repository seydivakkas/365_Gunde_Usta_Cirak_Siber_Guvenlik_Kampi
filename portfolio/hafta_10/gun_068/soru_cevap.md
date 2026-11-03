# Hafta 10 Gün 68: Ağ Günlükleri ve Kişisel Veri Soru-Cevap

---

### G068-SC1: Ağ Günlüklerinde IP Adresleri ve MAC Adresleri Hukuken Neden Kişisel Veridir ve Nasıl Arındırılmalıdır?

#### 1. Soru Başlığı ve Tanımı
Ağ paket başlıklarında yer alan kaynak/hedef IP adresleri ve Ethernet MAC adresleri teknik olarak salt birer donanım ve ağ adresi olmasına rağmen, KVKK ve GDPR kapsamında neden "kişisel veri" (PII) kabul edilir? SOC ortamında bu adresler adli değerini kaybetmeden nasıl arındırılmalıdır?

#### 2. Derinlemesine Teknik Analiz
Bir verinin "kişisel veri" sayılması için yalnızca isim-soyisim içermesi gerekmez; ek bilgilerle birleştirildiğinde bir bireyin belirlenebilir (identifiable) kılınması yeterlidir:

1. **IP Adresleri:**
   - Statik IP'ler zaten doğrudan belirli bir aboneye veya çalışanın masasına tahsis edilmiştir.
   - Dinamik IP'ler ise DHCP veya RADIUS logları ile eşleştirildiğinde (özellikle ISS veya kurumsal Active Directory ortamında) paketi atan kişinin kimliğini saniyesinde ortaya koyar. Avrupa Adalet Divanı'nın *Breyer (C-582/14)* içtihadı uyarınca dinamik IP'ler de kişisel veridir.
2. **MAC Adresleri:**
   - 48 bitlik benzersiz bir donanım tanıtıcısıdır (EUI-48). İlk 24 bit üreticiyi (OUI), son 24 bit cihazı (NIC) temsil eder.
   - Wi-Fi ağlarında istemci probları (Probe Requests) üzerinden bir kullanıcının fiziksel konumu, hangi kafelerde bulunduğu ve ofise giriş-çıkış saatleri adım adım haritalanabilir.

**Arındırma Çözümü:**
- **Alt Ağ Maskeleme (Subnet Truncation):** IPv4 adresinin son okteti sıfırlanarak (`192.168.1.0/24`) kullanıcının belirli cihazı gizlenir, ancak bağlı olduğu alt ağ korunur.
- **OUI Korumalı MAC Maskeleme:** İlk 3 oktet (üretici firma tespiti için gerekli) korunur, son 3 oktet `XX:XX:XX` ile maskelenir (`00:1A:2B:XX:XX:XX`). Böylece analist ağda dolaşan cihazın Apple mı yoksa Cisco mu olduğunu anlar ama cihazın spesifik seri numarasını göremez.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir üniversite kampüsünde kablosuz ağ günlükleri siber tehdit avcılığı için Zeek (Bro) ile kaydedilmektedir. Ancak KVKK denetçileri öğrencilerin MAC adreslerinin ve IP'lerinin açık saklanmasının kişisel verilerin izinsiz takibi suçu oluşturabileceği uyarısında bulunur.

```python
# Zeek / Suricata Log Pipeline Arındırma Fonksiyonu
import ipaddress

def sanitize_flow_ip(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 4:
        # Son 8 bit maskelenir (/24)
        octets = ip_str.split(".")
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    else:
        # IPv6: İlk 48 bit korunur
        return f"{ip.exploded.split(':')[0]}:{ip.exploded.split(':')[1]}::/48"
```

**Müdahale:**
1. Log toplayıcı logstash / vector ajanında yukarıdaki maskeleme kuralı işletilir.
2. Ham IP ve MAC adresleri SIEM ana veritabanına girmeden önce uçta (edge) arındırılır.
3. Denetim sonucunda kurum "KVKK Uyumlu Güvenli Ağ İzleme" sertifikası alır.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! "Bu sadece bir sayı, insan ismi değil" diyerek IP ve MAC adresini hafife alma. Bir kişinin evinin dış kapı numarası da sadece bir sayıdır, ama postacı o kapıdan içeri kimi bulacağını çok iyi bilir. Ağ adresleri dijital dünyanın kapı numaralarıdır. Görevin binayı bilmek olsun, yatak odasının anahtarını cebinde taşımak değil!

---

### G068-SC2: Adli Bilişim Soruşturması ile KVKK/GDPR Uyumu Arasındaki Denge "Sözde-Anonimleştirme (Pseudonymization)" ile Nasıl Kurulur?

#### 1. Soru Başlığı ve Tanımı
Bir siber güvenlik olayına müdahale (Incident Response) sürecinde saldırganın hareketlerini (Lateral Movement) takip edebilmek için loglardaki tutarlılık şarttır. Veriyi tamamen anonimleştirmeden, yasal uyumu sağlamak adına **Sözde-Anonimleştirme (Pseudonymization / Salted Hashing)** nasıl uygulanır?

#### 2. Derinlemesine Teknik Analiz
Tam anonimleştirme (Anonymization) ile sözde-anonimleştirme (Pseudonymization) arasındaki fark GDPR Madde 4(5)'te açıkça belirtilmiştir:

- **Tam Anonimleştirme:** Verinin hiçbir ek bilgiyle bir daha asla eski haline getirilememesidir (Geri döndürülemez). Bu yöntemde tüm IP'ler `[REDACTED]` yapılırsa, SOC analisti saldırganın 10 farklı sunucuya sıçradığını göremez; çünkü hepsi aynı etiketi almıştır ve korelasyon çöker.
- **Sözde-Anonimleştirme (Pseudonymization):** Verinin tek başına bir kişiyi tanımlayamayacak hale getirilmesi, ancak ayrı ve güvenli saklanan bir anahtarla (Tuz / Kriptografik Anahtar) geriye dönük eşleştirilebilmesidir.

**HMAC-SHA256 ile Tuzlu Sözde-Kimlik Mimarisi:**
1. Güvenlik yöneticisi (CISO) donanımsal bir güvenlik modülünde (HSM) veya güvenli anahtar kasasında (KMS) gizli bir tuz anahtarı (`MASTER_SALT_KEY`) saklar.
2. Log boru hattında her IP adresi bu tuzla HMAC özetine dönüştürülür:
   $$\text{Pseudonym} = \text{HMAC-SHA256}(\text{IP}, \text{MASTER\_SALT\_KEY})[:12]$$
3. **Deterministik Özellik:** $X$ IP'si logda 100 kez de geçse her seferinde `IP_PSEUDO_a8f9c1b2` kodunu alır. Analist saldırganın ayak izlerini SIEM üzerinde günlerce filtreleyip korelasyon kurabilir.
4. **Hukuki Koruma:** SIEM analisti veya sisteme sızan bir hacker bu hash'ten orijinal IP'yi çıkaramaz. Sadece mahkeme kararı veya resmi olay müdahale tutanağı olduğunda CISO anahtarı kullanarak ters eşleme tablosunu açar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kuruluşunda veri sızıntısı şüphesi doğar. Güvenlik analistleri dışarıdan kiralanan üçüncü taraf bir siber adli bilişim (MDR) firmasına 6 aylık web erişim loglarını teslim edecektir. Ancak hukuk departmanı müşteri IP'lerinin ve e-postalarının üçüncü tarafa açık verilmesini kesinlikle yasaklar.

**Uygulanan Çözüm:**
1. Loglar üçüncü tarafa verilmeden önce `MASTER_SALT` ile arındırma motorundan geçirilir:
   - Tüm IP'ler `IP_PSEUDO_xxxx` formatına sokulur.
   - E-postalar `a***z@banka.com` yapılır.
   - Oturum çerezleri temizlenir.
2. MDR firması korelasyon analizini tamamlar ve rapor sunar: *"IP_PSEUDO_e3b0c442 kimlikli istemci, 14 gece yarısı sunuculardan şüpheli veri çekmiştir."*
3. Kurum içi disiplin ve adli komite tutanakla bu sözde-kimliği çözerek içerideki köstebek çalışanın IP'sini resmi mercilere teslim eder.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Veriyi tamamen yok edersen kör olursun; tamamen açık bırakırsan kanun önünde suçlu olursun. Usta bir mühendis siyah ile beyaz arasında sıkışmaz; kriptografinin matematiğini kullanarak sözde-anonimleştirmenin güvenli gri alanını inşa eder. Anahtar kasada güvendeyse, analistin gözü açık, vicdanı ve sicili temizdir!

---

### G068-SC3: Web ve Proxy Loglarında Açıkta Kalan Hassas Başlıklar (Authorization, Cookie) ve URL Parametreleri WAF/SIEM Seviyesinde Nasıl Maskelenir?

#### 1. Soru Başlığı ve Tanımı
Geliştiricilerin HTTP GET sorgularında parametre olarak taşıdığı hassas veriler (`?email=...&token=...`) ile HTTP başlıklarındaki oturum jetonları (`Authorization: Bearer`, `Cookie`) web sunucusu ve proxy loglarına açık metin olarak kaydedildiğinde ne gibi siber riskler doğar ve WAF/Log Forwarder seviyesinde nasıl temizlenir?

#### 2. Derinlemesine Teknik Analiz
Web mimarisinde HTTP GET istekleri doğası gereği önbelleğe alınabilir (cacheable) ve ağdaki vekil sunucular (Reverse Proxy, CDN, Yük Dengeleyici) tarafından URL bazında loglanır.

**Kritik Güvenlik ve Gizlilik Riskleri:**
1. **Oturum Çalma (Session Hijacking):** Eğer `Cookie` veya `Authorization` başlığı log sunucusuna açık aktarılırsa, log sistemine erişimi olan herhangi bir stajyer veya yetkisiz personel aktif oturum jetonunu çalarak kullanıcının hesabına doğrudan giriş yapabilir.
2. **Kişisel Veri İhlali (Credential Leaking in URI):** Geliştiriciler bazen tembellik edip şifre sıfırlama veya doğrulama linklerinde kullanıcı e-postasını veya TCKN'sini GET parametresi olarak gönderir (`/verify?email=ali@sirket.com&tckn=12345678901`). Bu URL, tarayıcı geçmişinden proxy sunucu erişim loguna kadar 10 farklı ara noktada açıkça kaydedilir.

**Çözüm Mimarisi (Log Sanitization Pipeline):**
- **URI Query Sanitization:** Regex ile sorgu parametrelerindeki `email`, `token`, `password`, `tckn`, `card` anahtar kelimeleri tespit edilir ve değerleri URL-encoded güvenli maskelerle değiştirilir.
- **Header Stripping / Masking:** Nginx / Apache / Envoy vekil sunucularında log formatı tanımlanırken `$http_authorization` ve `$http_cookie` değişkenleri doğrudan loglanmaz; yerine `[REDACTED]` yazılır veya token tipi hariç kalanı temizlenir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir sağlık uygulaması WAF loglarını ELK (Elasticsearch-Logstash-Kibana) kümesine aktarmaktadır. Yapılan güvenlik denetiminde hastaların T.C. kimlik numaralarının ve e-posta adreslerinin Kibana panellerinde açıkça aratılabildiği ve tüm BT personelinin erişimine açık olduğu görülür.

**Logstash / Vector Maskeleme Kuralı:**
```ruby
# Logstash Filtresi ile URI ve Başlık Arındırma
filter {
  # 1. Authorization başlığını maskele
  mutate {
    gsub => [
      "[headers][authorization]", "Bearer .*", "Bearer [REDACTED_TOKEN]",
      "[headers][cookie]", ".*", "[REDACTED_COOKIE]"
    ]
  }
  # 2. URI içindeki TCKN parametresini maskele
  mutate {
    gsub => [
      "request_uri", "tckn=[0-9]{11}", "tckn=12*******01"
    ]
  }
}
```

**Sonuç:**
Arındırma motoru devreye alındıktan sonra log akışı kesintiye uğramadan devam eder. Analistler URL'in istek yolunu (`/api/v1/profile`) görmeye devam ederken, hastaların kimlik bilgileri loglardan tamamen temizlenir.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Yazılımcıların "nasıl olsa bu logları sadece biz görüyoruz" rahatlığına asla güvenmeyeceksin. Bir saldırganın ilk hedefi her zaman kimlik doğrulama sunucuları ve log depolarıdır; çünkü aradığı tüm şifreleri ve oturum anahtarlarını orada altın tepside bulur. Kapıyı kilitli tutmak istiyorsan, anahtarı kapının üzerindeki log defterine yazmayacaksın!
