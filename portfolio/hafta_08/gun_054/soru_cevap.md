<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 54: DNS Sorguları ve Kayıt Türleri — Soru Bankası ve Usta-Çırak Mülakatı

---

## Soru 1 (G054-SC1): Temel Mekanizma ve Güvenlik Önemi

### Soru
DNS sorguları ve kayıt türleri bağlamında: Temel mekanizmayı, farklı kayıt türlerinin taşıdığı bilgileri ve "DNS yanıtı her zaman doğrulanmış kimlik değildir" ilkesinin siber güvenlik açısından taşıdığı kritik önemi açıklayınız.

### Usta Cevabı
DNS (Domain Name System - RFC 1034/1035), internetin dağıtık ve hiyerarşik isim çözümleme veritabanıdır. İstemcinin ilettiği metinsel alan adını (QNAME), taşıma katmanında ikili (binary) sorgular aracılığıyla çeşitli Kaynak Kayıtları (Resource Records - RR) ile eşleştirir:
- **A (Tip 1):** 32-bit IPv4 adresi eşlemesi,
- **AAAA (Tip 28):** 128-bit IPv6 adresi eşlemesi,
- **CNAME (Tip 5):** Kanonik ad / takma ad yönlendirmesi,
- **MX (Tip 15):** Öncelik değeriyle birlikte yetkili e-posta sunucusu adresi,
- **TXT (Tip 16):** Serbest metin dizgisi; modern mimaride SPF, DKIM ve DMARC e-posta güvenlik politikalarının yayınlandığı merkez.

"DNS yanıtı her zaman doğrulanmış kimlik değildir" ilkesi siber güvenliğin en temel aksiyomlarından biridir. Standart DNS (UDP Port 53) şifresizdir ve kriptografik kimlik doğrulamasından yoksundur. Çözümleyicinin aldığı bir DNS yanıtı yolda bir ortadaki adam (MITM) tarafından değiştirilmiş, yerel ağda ARP zehirlemesiyle sahtelenmiş veya uzaktaki bir saldırgan tarafından Kaminsky Önbellek Zehirleme saldırısıyla üretilmiş olabilir. Yanıtın formatı doğru olsa dahi, DNSSEC (RRSIG/DNSKEY) ile imzalanmadığı sürece o IP adresinin meşru sunucuya ait olduğu garanti edilemez.

### Kritik Güvenlik / Mühendislik Noktası
DNS paketlerinde alan adları `.` ile değil, uzunluk önekli etiketlerle (Length-Prefixed Labels) kodlanır (`\x07example\x03com\x00`). Her bir etiket RFC 1035 gereği en fazla 63 karakter, toplam alan adı ise en fazla 253 karakter olabilir. Bu sınırların aşılması arabelleğe yazma (buffer overflow) veya ayrıştırma çökmelerine sebep olur.

### Çırak İçin Pratik Çıkarım
Uygulamalarında kullanıcıdan aldığın alan adlarını doğrudan `socket.gethostbyname()` gibi çağrılarla sorgulama. Güvensiz DNS yanıtlarının seni saldırganın kontrolündeki sahte bir IP adresine yönlendirebileceğini bilerek, kritik bağlantılarda mutlaka TLS sertifika doğrulaması (Certificate Pinning / PKI) ve DNSSEC destekli çözümleyiciler kullan.

---

## Soru 2 (G054-SC2): Bağımsız Laboratuvar Tasarımı ve Kontroller

### Soru
DNS sorguları ve kayıt türleri bağımsız laboratuvarının girdisi, işleme adımları, beklenen gözlenebilir sonucu ve negatif kontrolü nedir?

### Usta Cevabı
G054 laboratuvarı dış internete veya üçüncü taraf kütüphanelere ihtiyaç duymaksızın çalışan bağımsız bir yerel DNS kayıt ve güvenlik denetim laboratuvarıdır:
- **Girdi:** 
  1. Gerçekçi DNS Bölge Dosyası ve Şüpheli Sorgu Senaryoları (`ornek_veri/sample_dns_zone_and_queries.json`): A, AAAA, CNAME, sahipsiz CNAME (Subdomain Takeover riski), MX (öncelik 10), TXT (katı SPF ve DMARC) ve yüksek entropili tünelleme sorgusu (`48656c6c6f576f726c64...c2.attacker.com`).
  2. 8 adet kural dışı ve sınır aşımı negatif kontrol senaryosu (`ornek_veri/invalid_dns_inputs.json`).
- **İşlem:**
  1. `DNSType`: Kayıt türü kodlarının (1, 5, 15, 16, 28 vb.) ve isim eşlemelerinin doğrulanması.
  2. `encode_domain_name` / `decode_domain_name`: Alan adlarının RFC 1035 ikili etiket formatına kodlanması ve geri çözümlenmesi.
  3. `DNSHeader` ve `DNSQuestion`: 12 baytlık ikili DNS başlığının (`!HHHHHH`) ve soru bölümünün paketlenmesi ve ayrıştırılması.
  4. `DNSRecord`: A, AAAA, CNAME, MX ve TXT kaynak kayıtlarının alan doğrulamalarıyla oluşturulması.
  5. `DNSSecurityAuditor.audit_email_security_txt`: SPF (`-all`) ve DMARC (`p=reject`) politikalarının incelenmesi; zayıf veya eksik politikaların raporlanması.
  6. `DNSSecurityAuditor.audit_subdomain_takeover`: Üçüncü taraf bulut sağlayıcılarına (S3, GitHub, Azure) işaret eden sahipsiz CNAME kayıtlarının tespit edilmesi (`SUBDOMAIN_TAKEOVER_RISK`).
  7. `DNSSecurityAuditor.audit_dns_tunneling`: Shannon entropisi ve etiket uzunluğu analizi ile veri sızdırma (DNS Tunneling) anomalilerinin yakalanması.
- **Beklenen Sonuç:** 14 birim testin 0.01 saniyenin altında `PASS` alması; sahipsiz S3 CNAME kaydının `CRITICAL` risk olarak işaretlenmesi; hex kodlu sorgunun DNS Tünelleme olarak yakalanması; katı SPF/DMARC politikalarının güvenli onaylanması.
- **Negatif Kontrol:** 63 karakterden uzun etiket, 253 karakterden uzun alan adı, negatif TTL, geçersiz IPv4/IPv6 RDATA adresleri, boş alan adı ve geçersiz Transaction ID verildiğinde sistemin `DNSValidationError` fırlatması (8/8 başarı).

### Kritik Güvenlik / Mühendislik Noktası
DNS Tünelleme (DNS Tunneling) araçları (`dnscat2`, `iodine`), DLP filtrelerini atlatmak için verileri alt alan adı etiketlerine (subdomain labels) basar. Normal bir alan adı etiketinin Shannon entropisi 1.5 - 2.5 aralığındayken, tünellenmiş verilerde entropi 2.8 - 4.0 aralığına fırlar ve etiket boyu 30 karakteri aşar. Bu matematiksel imza, tünellemeyi anında ele verir.

### Çırak İçin Pratik Çıkarım
DNS sorgularını incelerken sadece IP'ye odaklanma. Şirket ağında bir makinenin `a8f3c7...c2.saldırgan.com` gibi anlamsız ve upuzun sorgular attığını görürsen, birisi DNS üzerinden şirket verilerini dışarıya kaçırıyor (data exfiltration) demektir.

---

## Soru 3 (G054-SC3): Tehdit Modeli, Tespit ve Savunma Kontrolleri

### Soru
"DNS sorguları ve kayıt türleri" bağlamında riskler nasıl oluşur, ağ trafiğinde ve bölge dosyalarında hangi sinyallerle tespit edilir ve hangi kontrollerle önlenir?

### Usta Cevabı
- **Risk Oluşumu:** 
  1. **Doğrulanmamış Yanıtlar ve Sahtecilik:** Standart DNS'in imzasız olması nedeniyle saldırganların sahte IP enjekte etmesi (DNS Spoofing / Cache Poisoning).
  2. **Sahipsiz CNAME (Subdomain Takeover):** Şirketin bulut kaynağını (S3 deposu, Azure Web App) silip DNS'teki CNAME kaydını açık unutması sonucu saldırganın aynı kaynak adını tescilleyerek şirketin alt alan adını ele geçirmesi.
  3. **E-posta Sahteciliği (Phishing / BEC):** TXT kayıtlarında SPF'in eksik veya zayıf (`+all`, `?all`) olması, DMARC'ın tanımlanmaması sonucu saldırganların şirket yöneticisi adına sahte e-posta gönderebilmesi.
  4. **DNS Tünelleme (C2 / Veri Kaçırma):** Saldırganın kapalı ağlardan veri sızdırmak veya komuta kontrol kanalı kurmak için DNS sorgularını taşıyıcı olarak kullanması.
- **Tespit Sinyalleri:**
  1. DNS yanıtlarında değişen TTL süreleri veya bilinmeyen ad sunucusu yetkileri (NXDomain yanıtına rağmen farklı IP dönülmesi).
  2. CNAME kaydının işaret ettiği bulut adresinde HTTP 404 (NoSuchBucket / Heroku No Such App) hatası alınması.
  3. Ağ izleme araçlarında (Zeek/Suricata) olağandışı uzunlukta ($>30$ karakter) ve yüksek entropili TXT/A sorgularının saniyeler içinde yinelenmesi.
  4. Şirket adına gönderilen ancak SPF `fail` veren e-posta raporlarının (DMARC RUA) artması.
- **Savunma Kontrolleri:**
  1. **DNSSEC Yaygınlaştırması:** Bölge kayıtları kriptografik olarak imzalanmalı; DNS çözümleyicilerde DNSSEC doğrulaması zorunlu tutulmalıdır.
  2. **DoH (DNS over HTTPS) ve DoT (DNS over TLS):** Uç noktalarda şifreli DNS protokolleri devreye alınarak ağ içi tahrifat engellenmelidir.
  3. **Sıkılaştırılmış E-posta Politikası:** Alan adında mutlaka `v=spf1 ... -all` (HardFail) ve `v=DMARC1; p=reject;` TXT kayıtları bulunmalıdır.
  4. **Sürekli CNAME Denetimi:** Bulut kaynakları silinmeden önce DNS kayıtları güncellenmeli; otomatik scriptlerle sahipsiz CNAME'ler düzenli taranmalıdır.
  5. **DNS Güvenlik Duvarı (RPZ - Response Policy Zone):** Bilinen C2 ve tünelleme alan adları DNS seviyesinde engellenmeli (Sinkholing).

### Kritik Güvenlik / Mühendislik Noktası
Birçok kurum DMARC kaydını ekler ancak `p=none` (yalnızca izleme) modunda bırakır. `p=none` modu saldırganı hiçbir şekilde durdurmaz; sahte e-posta kurbanın gelen kutusuna düşmeye devam eder. DMARC politikası test süreci biter bitmez önce `p=quarantine` (karantinaya al) ve ardından `p=reject` (doğrudan reddet) seviyesine çekilmelidir.

### Çırak İçin Pratik Çıkarım
Bir alan adını devraldığında veya güvenlik denetimi yaptığında ilk işin `dig TXT alanadi.com` ve `dig TXT _dmarc.alanadi.com` komutlarıyla e-posta güvenliğini kontrol etmek olsun. İkinci işin ise tüm CNAME kayıtlarını listeleyip hedeflerinin hala hayatta olup olmadığını denetlemektir.
