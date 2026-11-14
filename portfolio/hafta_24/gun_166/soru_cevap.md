# Gün 166: SSRF Kavramı ve Savunma — Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. Sunucu Taraflı İstek Sahteciliği (SSRF / CWE-918) nedir? Bulut ortamlarında (AWS, Azure, GCP) barındırılan bir sunucudaki SSRF açığı, bir saldırganın tüm bulut altyapısını ele geçirmesine (Full Cloud Compromise) nasıl yol açabilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın SSRF'in yalnızca "iç ağdaki bir web sitesini çağırmak" olmadığını; bulut mimarilerindeki bağlantı-yerel (Link-Local) Metaveri Servislerini (`169.254.169.254`), IAM rol mimarisini ve IMDSv1 ile IMDSv2 arasındaki kritik farkı teknik derinlikle kavrayıp kavramadığını ölçüyorum. Capital One vaka analizi seviyesinde bir teknik hakimiyet bekliyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
SSRF, saldırganın hedef sunucuyu kendi belirlediği bir adrese sunucunun yetkileriyle HTTP/TCP isteği atmaya zorlamasıdır. AWS, GCP veya Azure gibi bulut sağlayıcılarında sanal sunuculara otomatik atanan IAM rollerinin geçici kimlik bilgileri `http://169.254.169.254/` bağlantı-yerel IP adresindeki metaveri servisinden (IMDS) çekilir. Bir saldırgan SSRF açığı üzerinden bu adrese istek attırdığında sunucu, IAM rolüne ait `AccessKeyId`, `SecretAccessKey` ve oturum belirtecini içeren JSON çıktısını saldırgana geri döner. Saldırgan bu anahtarları AWS CLI veya API üzerinden kullanarak S3 kovalarını okuyabilir, veritabanlarını indirebilir ve ayrıcalık yükselterek tüm bulut ortamını ele geçirebilir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Klasik IMDSv1 mimarisinde metaveri servisi basit bir HTTP GET isteğiyle yanıt verir. SSRF kurbanı sunucu gelen `http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol_adi>` isteğini GET ile çağırdığı an tüm anahtarlar sızar.
Bu riske karşı geliştirilen **IMDSv2**, oturum tabanlı bir koruma getirmiştir:
1. İstemci önce `PUT /latest/api/token` isteği atarak ve `X-aws-ec2-metadata-token-ttl-seconds: 21600` başlığını göndererek geçici bir oturum belirteci almak zorundadır.
2. Ardından metaveri sorgusunda bu belirteç `X-aws-ec2-metadata-token` başlığıyla iletilmelidir.
3. Ayrıca ağ paketinin TTL (Hop Limit) değeri 1 olarak ayarlanır; böylece istek ters vekil sunucu veya Docker konteyneri üzerinden atlatılamaz.
SSRF saldırganları genellikle yalnızca GET isteği tetikleyebildikleri ve özel HTTP başlığı enjekte edemedikleri için IMDSv2, bulut metaveri sızıntılarını altyapı düzeyinde kesin olarak engeller.

---

### Soru:
2. Bir web uygulamasında SSRF'e karşı `if "127.0.0.1" in url or "localhost" in url:` şeklinde bir kara liste (Blacklist) kontrolü yapılmıştır. Bir saldırgan bu kontrolü hangi tekniklerle (IP Obfuscation, IPv6, DNS Rebinding) tamamen bypass edebilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın kara liste yaklaşımının neden temelden kusurlu olduğunu; IP adreslerinin işletim sistemi ve ağ kütüphaneleri tarafından farklı sayı tabanlarında (Integer, Hex, Octal) çözümlenebildiğini ve DNS mekanizmasındaki zamanlama hilelerini (DNS Rebinding / TOCTOU) bilip bilmediğini test ediyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Dize tabanlı kara liste kontrolleri SSRF savunmasında tamamen etkisizdir çünkü aynı IP adresi onlarca farklı biçimde temsil edilebilir:
1. **Tamsayı (DWORD) Biçimi:** `127.0.0.1` adresinin matematiksel tamsayı karşılığı `http://2130706433/` olarak yazılır. URL'de "127.0.0.1" geçmez ama işletim sistemi bunu `127.0.0.1`'e bağlar.
2. **Onaltılık (Hex) Biçimi:** `http://0x7f000001/` veya `http://0x7f.0.0.1`.
3. **Sekizli (Octal) Biçimi:** `http://0177.0.0.1`.
4. **Kısaltılmış Biçim:** `http://127.1/`.
5. **IPv6 Varyasyonları:** `http://[::1]/` veya `http://[::ffff:127.0.0.1]/`.
6. **DNS Tabanlı Atlatma ve DNS Rebinding:** Saldırgan `evil.com` alan adının A kaydını `127.0.0.1` yapar. Ya da ilk sorguda genel IP dönüp saniyeler sonra `127.0.0.1` dönerek (DNS Rebinding) kontrolü atlatır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Dize karşılaştırması, IP adresinin derleyici ve soket seviyesindeki davranışını modelleyemez.
Çözüm, **Doğrulama Sıralamasını ve Mantığını Değiştirmektir (Pre-Request DNS & IP Inspection)**:
1. URL dizesinde IP aramak yerine, URL standart parser ile ayrıştırılır.
2. Host dizesi DNS çözümlemesine tabi tutulur (`socket.getaddrinfo`).
3. Dönen tüm IP adresleri standart ikili formata ve `ipaddress` nesnesine dönüştürülür.
4. Bu IP nesnelerinin `is_loopback`, `is_private`, `is_link_local` ve `is_reserved` özellikleri denetlenir.
5. Doğrulanan IP adresi HTTP bağlantı soketine doğrudan sabitlenir (IP Pinning); böylece DNS Rebinding saldırısı olanaksız kılınır.

---

### Soru:
3. Bir uygulamada alan adı beyaz listesi (Domain Allowlist) kullanılmasına rağmen, "HTTP Açık Yönlendirme (Open Redirect)" ve "Protokol Kaçakçılığı (Protocol Smuggling)" zafiyetleri SSRF korumasını nasıl çökertebilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın sadece tek bir HTTP isteğini değil, istek yaşam döngüsünü (Redirect Lifecycle) ve protokol seviyesindeki tehlikeleri analiz edebilmesini bekliyorum. Adaydan; `301/302 Redirect` takibinin nasıl iç ağa sıçrama sağladığını ve `file://` veya `gopher://` şemalarıyla sistem dosyalarının okunması ya da iç ağdaki Redis/Memcached gibi servislere TCP payload enjeksiyonu yapılmasını açıklamasını istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Alan adı beyaz listesi bulunsa bile, eğer izin verilen alan adı üzerinde bir Açık Yönlendirme (Open Redirect) açığı varsa koruma çöker. Örneğin `https://guvenli-partner.com` izinlidir. Saldırgan `https://guvenli-partner.com/redirect?url=http://169.254.169.254/` linkini verir. Sunucu ilk domaini doğrular ve isteği atar; ancak HTTP istemcisi `302 Found` yanıtındaki `Location: http://169.254.169.254/` başlığını körlemesine takip ederse metaveri servisine ulaşılmış olur.
Protokol Kaçakçılığında ise, şema denetlenmediğinde `file:///etc/passwd` ile sunucunun yerel dosyaları okunabilir ya da `gopher://127.0.0.1:6379/_flushall` ile şifresiz iç ağ servislerine (Redis, SMTP) ham TCP baytları enjekte edilerek RCE (Uzaktan Kod Yürütme) elde edilebilir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Bu saldırıların kök nedeni, istemci kütüphanelerinin (cURL, Python requests, Java HttpURLConnection vb.) varsayılan ayarlarıdır:
- `requests.get(url, allow_redirects=True)` varsayılan olarak yönlendirmeleri sonuna kadar takip eder ve ara adresleri doğrulamaz.
- cURL kütüphanesi derleme parametrelerine göre `file://`, `gopher://`, `dict://`, `tftp://` gibi düzinelerce eski protokolü destekler.
Bu nedenle kurumsal savunma kuralı şudur:
1. Yalnızca `http` ve `https` şemaları kabul edilmelidir.
2. Otomatik yönlendirme takibi (`allow_redirects`) kapatılmalı veya yönlendirme döngüsü elle yazılarak her bir `Location` adresi sıfırdan aynı katı SSRF motorundan geçirilmelidir.
3. Sunucu işletim sistemi seviyesinde çıkış güvenlik duvarı (Egress Filtering) kurularak uygulama sunucusunun `169.254.169.254` ve iç ağa doğrudan TCP bağlantısı açması kısıtlanmalıdır.
