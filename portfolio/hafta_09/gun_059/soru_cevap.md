# G059: HTTPS ve TLS El Sıkışması — Soru-Cevap Dokümanı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## G059-SC1: TLS 1.2 vs TLS 1.3 Mimari ve İletme Gizliliği (PFS)

### Soru
TLS 1.2 ile TLS 1.3 protokolleri arasındaki el sıkışma gecikmesi farkı (2-RTT vs 1-RTT) nasıl ortaya çıkmaktadır? TLS 1.3'ün statik RSA anahtar takasını tamamen yasaklayıp Kusursuz İletme Gizliliğini (Perfect Forward Secrecy - PFS) zorunlu kılmasının matematiksel ve operasyonel güvenlik temeli nedir?

### Derin Teknik Cevap
TLS 1.2 protokolünde güvenli bir oturum kurabilmek için istemci ve sunucu arasında en az iki tam gidiş-dönüş (2-RTT) gerekmektedir. 
1. **İlk RTT:** İstemci `ClientHello` ile desteklediği şifreleme paketlerini ve eklentilerini sunar; sunucu `ServerHello`, `Certificate`, `ServerKeyExchange` (DHE parametreleri) ve `ServerHelloDone` mesajlarıyla yanıt verir.
2. **İkinci RTT:** İstemci, sunucunun Diffie-Hellman parametrelerine karşılık kendi açık anahtarını `ClientKeyExchange` paketiyle iletir, ardından her iki taraf `ChangeCipherSpec` ve `Finished` mesajlarını değiş tokuş ederek oturum anahtarlarını (Master Secret) doğrular. Ancak bu iki tur tamamlandıktan sonra uygulama verisi (Application Data) akmaya başlar.

TLS 1.3 (RFC 8446) bu gecikmeyi tek bir gidiş-dönüşe (**1-RTT**) indirmiştir. İstemci, sunucunun yaygın olarak destekleyeceği eliptik eğriyi (özellikle Curve25519 / X25519) öngörerek ilk `ClientHello` paketinin içine `key_share` uzantısını ve kendi geçici açık anahtarını ekler. Sunucu `ServerHello` ile kendi geçici anahtarını döner dönmez, her iki taraf da Diffie-Hellman hesabını ($g^{ab} \pmod p$ veya skaler eliptik eğri çarpımı) tamamlar. Sunucu, sertifikasını ve el sıkışma doğrulamasını dahi şifreli olarak (`EncryptedExtensions`, `Certificate`, `Finished`) bu ilk yanıtta iletir. İstemci yanıtı aldığı anda doğrulamayı bitirip şifreli HTTP verisini gönderebilir.

TLS 1.3'te **statik RSA anahtar takasının yasaklanması**, İletme Gizliliği (PFS) zorunluluğundan kaynaklanır. Statik RSA'da istemci, rastgele ürettiği `Pre-Master Secret` verisini sunucunun uzun ömürlü RSA açık anahtarıyla şifreleyip sunucuya yollar. Eğer bir saldırgan (örneğin istihbarat teşkilatı veya ağ casusu) şifreli ağ trafiğini yıllarca depolar ve 5 yıl sonra sunucunun diskinden veya HSM'inden RSA özel anahtarını ele geçirirse, geçmişe dönük kaydedilmiş TÜM trafiğin Pre-Master Secret değerini çözebilir ve milyonlarca oturumu geriye dönük deşifre edebilir. Eliptik Eğri Geçici Diffie-Hellman (`ECDHE`) protokolünde ise her oturum için bellekte rastgele geçici bir anahtar çifti üretilir ve oturum biter bitmez RAM'den silinir. Sunucunun uzun ömürlü özel anahtarı yalnızca el sıkışmadaki geçici parametreleri dijital olarak imzalamak (kimlik doğrulamak) için kullanılır; anahtar türetiminde kullanılmaz. Bu nedenle sunucunun özel anahtarı çalınsa dahi, geçmiş oturumların geçici anahtarları yok edildiği için kaydedilmiş trafik matematiksel olarak asla çözülemez.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Tehdit aktörleri "Şimdi Kaydet, Sonra Çöz" (**Store Now, Decrypt Later - SNDL**) stratejisiyle devlet kurumlarının ve finans merkezlerinin şifreli trafiklerini terabaytlarca arşivlemektedir. Kuantum bilgisayarların veya içeriden sızdırılan özel anahtarların tehdit oluşturduğu bir dünyada, statik RSA kullanımı stratejik bir felakettir. TLS 1.3, kriptografik zayıflıkları ve statik anahtar kullanımını protokolden donanımsal olarak budayarak, geriye dönük deşifre tehdidini ortadan kaldırır.

### Pratik / Sektörel Yansıma ve Analiz
Kurumsal web sunucularında (Nginx, HAProxy, F5 BIG-IP) yapılan güvenlik taramalarında (örneğin Qualys SSL Labs):
- `TLS_RSA_WITH_AES_128_CBC_SHA` gibi paketlerin bulunması "PFS Yok" uyarısıyla skoru doğrudan düşürür ve PCI-DSS denetimlerinde uygunsuzluk yaratır.
- Modern sektör standardı, `ssl_ciphers` direktifinde yalnızca ECDHE ve TLS 1.3 AEAD paketlerine (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) izin vermek ve statik RSA şifreleme paketlerini tamamen devre dışı bırakmaktır.

---

## G059-SC2: Sürüm Düşürme (Downgrade) Saldırıları ve RFC 8446 Sentinel Mekanizması

### Soru
Aktif bir Man-in-the-Middle (MitM) saldırganı ağdaki TLS el sıkışmasını nasıl manipüle ederek sürüm düşürme (downgrade) saldırısı gerçekleştirir? RFC 8446 standardı, sunucunun `ServerHello.random` alanındaki hangi sentinel baytları aracılığıyla bu saldırıyı istemci tarafında tespit edip engeller?

### Derin Teknik Cevap
TLS el sıkışmasının ilk adımı olan `ClientHello`, henüz şifrelenmemiş açık metin bir pakettir. İstemci bu pakette desteklediği en yüksek TLS sürümünü (`supported_versions` uzantısında `0x0304` = TLS 1.3) ve desteklediği güçlü şifreleme paketlerini beyan eder. İstemci ile sunucu arasında duran aktif bir ağ saldırganı (MitM - örneğin kötü amaçlı bir Wi-Fi erişim noktası veya ARP zehirlemesi yapan bir aktör):
1. İstemcinin gönderdiği `ClientHello` paketindeki `supported_versions` uzantısını siler veya değiştirir.
2. Protokol sürümünü `0x0301` (TLS 1.0) veya `0x0303` (TLS 1.2) seviyesine indirir ve güvenli olmayan zayıf şifreleme paketlerini bırakıp modern paketleri ayıklar.
3. Sunucu, istemcinin eski ve kısıtlı bir istemci olduğunu düşünerek el sıkışmayı zayıf bir sürümle (örneğin CBC modlu TLS 1.2 veya SSL 3.0) başlatır.
4. Böylece saldırgan, modern TLS 1.3 korumalarını devre dışı bırakıp trafiği POODLE, BEAST veya Lucky Thirteen gibi zafiyetlerle kırmaya çalışır.

Bu tehdidi bertaraf etmek amacıyla **RFC 8446 Bölüm 4.1.3**, kriptografik bir sentinel (nöbetçi) mekanizması zorunlu kılmıştır. Sunucu `ServerHello` paketinde 32 baytlık rastgele bir değer (`Server Random`) üretir. Eğer sunucu TLS 1.3 destekliyorsa ancak kendisine gelen ClientHello nedeniyle el sıkışmayı TLS 1.2 ile yürütmek zorunda kalmışsa, ürettiği 32 baytlık rastgele değerin son 8 baytına kesin olarak şu sabit ASCII değerini yazmak zorundadır:
$$\text{DOWNGRD\x01} \quad \text{(Hex: } 44\ 4f\ 57\ 4e\ 47\ 52\ 44\ 01 \text{)}$$
Eğer sunucu TLS 1.1 veya daha eski bir sürüme düşürüldüyse, son 8 bayta şu sentinel yazılır:
$$\text{DOWNGRD\x02} \quad \text{(Hex: } 44\ 4f\ 57\ 4e\ 47\ 52\ 44\ 02 \text{)}$$

Gerçekte TLS 1.3 destekleyen dürüst bir istemci, sunucudan TLS 1.2 yanıtı aldığında `ServerHello.random` alanının son 8 baytını inceler. İstemci kendi kendine der ki: *"Ben sunucuya TLS 1.3 teklif etmiştim; ancak sunucu bana TLS 1.2 döndü ve rastgele baytlarının sonunda DOWNGRD\x01 sentineli var! Bu sentinel, sunucunun gerçekte TLS 1.3 bildiğini ancak benim ClientHello mesajımın ona değiştirilmiş olarak ulaştığını kanıtlar!"* İstemci bu durumu tespit ettiği anda bağlantıyı derhal bir `illegal_parameter` TLS Alert mesajı ile keser.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Sürüm düşürme saldırıları, kriptografik protokollerin tarihindeki en yıkıcı açıkların (POODLE, FREAK, Logjam, DROWN) temel kaldıracı olmuştur. Bir sistem en güçlü şifreleri desteklese bile, geriye dönük uyumluluk nedeniyle eski sürümleri kapatamıyorsa ve sürüm düşürme koruması yoksa, güvenlik seviyesi sistemin desteklediği EN ZAYIF halkaya eşitlenir. RFC 8446 sentineli, araya giren aktif saldırganın varlığını matematiksel bir kesinlikle deşifre eder.

### Pratik / Sektörel Yansıma ve Analiz
- Güvenlik duvarları ve IDS/IPS sistemleri (Suricata, Snort), TLS akışlarında beklenmeyen sürüm uyumsuzluklarını ve istemcinin gönderdiği `supported_versions` ile sunucu yanıtı arasındaki sentinel baytlarını kural tabanlı olarak analiz ederek ağdaki MITM araçlarını (örneğin yetkisiz SSL proxy cihazlarını) tespit edebilir.
- Sektördeki en iyi sertleştirme (hardening) pratiği, geriye dönük uyumluluk gereksinimini tamamen terk edip sunucu tarafında TLS 1.0 ve TLS 1.1'i tamamen yasaklamak (`disable`), yalnızca TLS 1.2 ve TLS 1.3 protokollerine izin vermektir.

---

## G059-SC3: CRIME Saldırısı ve TLS 1.3 0-RTT Replay Tehdit Yönetimi

### Soru
TLS seviyesinde veri sıkıştırmasının (compression) sebep olduğu CRIME saldırısının (CVE-2012-4929) arkasındaki yan kanal (side-channel) mekanizması nedir? Ayrıca, TLS 1.3 ile gelen 0-RTT (Erken Veri) özelliğinin barındırdığı tekrar (replay) riski siber güvenlik ve uygulama mimarisi açısından nasıl kontrol altına alınmalıdır?

### Derin Teknik Cevap
**CRIME (Compression Ratio Info-leak Made Easy - CVE-2012-4929) Saldırısı:**
TLS 1.2 spesifikasyonu, el sıkışma sırasında `CompressionMethods` alanında oturum verilerinin şifrelenmeden önce DEFLATE algoritmasıyla sıkıştırılmasına izin veriyordu. DEFLATE algoritması (LZ77 + Huffman), veri akışı içinde tekrarlanan metin dizgilerini daha kısa belirteçlerle (pointer/offset) temsil ederek boyutu küçültür.
Bir kurbanın tarayıcısına kötü amaçlı bir reklam veya JavaScript enjekte eden bir saldırgan:
1. Tarayıcıdan hedef HTTPS bankacılık sitesine gizli `Cookie: secret=A9F8B2...` taşıyan istekler tetikler.
2. Aynı isteğin gövdesine (body) veya URL parametresine kendi tahmin dizgisini ekler: `data=secret=A`.
3. Eğer saldırganın tahmini doğruysa (`secret=A`), HTTP isteği içinde "secret=A" dizgisi iki kez geçeceği için DEFLATE algoritması bu tekrarı yakalar ve veriyi sıkıştırır.
4. Şifreli TLS Record paketinin toplam uzunluğu 1 bayt KISALIR! Eğer tahmin yanlışsa (`secret=B`), tekrar oluşmadığı için sıkıştırma gerçekleşmez ve paket boyutu aynı kalır.
5. Ağdaki saldırgan, şifreli verinin içeriğini okuyamasa bile paket boyutundaki 1 baytlık daralmayı (Side-Channel Length Leakage) gözlemleyerek çerezin ilk karakterinin 'A' olduğunu kesin olarak anlar! Bu işlem her karakter için 16-32 denemede tekrarlanarak dakikalar içinde tüm oturum çerezi açık metin olarak çalınır. Bu nedenle TLS sıkıştırması protokolden tamamen yasaklanmıştır.

**TLS 1.3 0-RTT Erken Veri ve Tekrar (Replay) Tehdidi:**
TLS 1.3'te istemci daha önce bağlandığı bir sunucuyla oturumu devam ettirirken (session resumption), ilk `ClientHello` paketinin içine doğrudan şifreli uygulama verisini (`early_data`) ekleyerek 0-RTT hızına ulaşabilir. Ancak bu ilk paket, sunucu ile istemci arasında henüz karşılıklı yeni bir el sıkışma tamamlanmadan gönderildiği için **Kusursuz İletme Gizliliği (PFS) sağlamaz ve ağ düzeyinde tekrar (replay) saldırılarına açıktır**.
Ağdaki bir saldırgan, istemcinin gönderdiği 0-RTT paketini kaydedip sunucuya 100 kez yeniden gönderebilir. Eğer bu 0-RTT paketi bir para transferi isteği içeriyorsa (`POST /transfer?amount=1000`), sunucu aynı işlemi mükerrer olarak çalıştırabilir!

**Mimari Çözüm ve Kontrol Stratejisi:**
1. **HTTP Metot Kısıtlaması (RFC 8470):** 0-RTT yüklerinde ASLA durumu değiştiren (state-changing) güvenli olmayan metotlar (`POST`, `PUT`, `DELETE`) kabul edilmemelidir. Yalnızca güvenli ve idempotent olan `GET` ve `HEAD` isteklerine izin verilmeli; sunucu 0-RTT içinde gelen POST isteklerine `425 Too Early` HTTP durum kodu dönerek istemcinin el sıkışma tamamlandıktan sonra 1-RTT içinde tekrar denemesini zorunlu kılmalıdır.
2. **Anti-Replay Mekanizmaları:** Sunucu tarafında kısa ömürlü bir bilet önbelleği (ticket cache / Bloom filter) tutularak aynı oturum biletinin ve tek kullanımlık rastgele değerin (Client Random) 0-RTT içinde ikinci kez kullanılması reddedilmelidir.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Performans optimizasyonları (sıkıştırma ve 0-RTT gecikme azaltımı), kriptografik tasarımda dikkatle sınırlandırılmazsa felaket getiren yan kanal sızıntılarına ve mantıksal tekrar açıklarına dönüşür. Güvenlik mühendisi, hız uğruna güvenlik prensiplerinden taviz verilmesine izin veremez; 0-RTT gibi özelliklerin uygulama katmanındaki semantik etkilerini denetlemek zorundadır.

### Pratik / Sektörel Yansıma ve Analiz
- Tüm modern tarayıcılar (Chrome, Firefox, Safari) TLS sıkıştırmasını tamamen kapatmıştır ve sunucu yapılandırmalarında `gzip` veya `brotli` sıkıştırmasının TLS katmanında değil, uygulama katmanında HTTP Content-Encoding düzeyinde çalıştırılması standarttır (BREACH önlemleriyle birlikte).
- Bulut sağlayıcıları (Cloudflare, AWS CloudFront), TLS 1.3 0-RTT özelliğini varsayılan olarak kapalı tutar veya yalnızca idempotent `GET` sorguları için izin veren sıkı kurallarla yapılandırır.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Soru-cevap dokümanı yalnızca görüntüleme ve eğitim amacıyla paylaşılmıştır.
