# Hafta 10 Gün 66: DNS ve HTTP Anomali İşaretleri (Usta-Çırak Dersi)

> **Usta Notu:**  
> *"Evlat, siber saldırganların kurumsal ağlara sızdıktan sonra dış dünyayla kurdukları iki ana can damarı vardır: DNS ve HTTP/HTTPS. Çünkü hiçbir kurumsal güvenlik duvarı DNS (Port 53) trafiğini tamamen kapatamaz; aksi halde şirketin internet erişimi tamamen felç olur. Aynı şekilde web trafiği (Port 80/443) her daim açıktır. Saldırgan bu gerçeği çok iyi bildiği için C2 (Komuta ve Kontrol) haberleşmesini, veri sızdırmayı (exfiltration) ve tünellemeyi bu iki protokolün arkasına gizler. Sıradan bir analist bu paketlere baktığında yalnızca sıradan bir web gezintisi veya alan adı çözümlemesi görür. Usta bir analist ise Şannon entropisinden, HTTP başlık çatışmalarından ve CRLF enjeksiyonlarından saldırganın ayak izini saniyesinde yakalar!"*

---

## 1. DNS Protokol Anomalileri ve Tehdit Avcılığı

DNS (Domain Name System), istemcilerin alan adlarını IP adreslerine dönüştürmesini sağlayan hiyerarşik ve dağıtık bir sistemdir. Ancak tasarım gereği durumsuz (stateless) ve UDP tabanlı olması, onu istismara açık hale getirir.

### 1.1 DGA (Domain Generation Algorithm) ve Entropi Analizi
Gelişmiş kalıcı tehdit (APT) aktörleri ve modern botnet'ler (örneğin Conficker, Necurs, Mirai), sabit C2 IP adresleri veya alan adları kullanmazlar; çünkü bu adresler tehdit istihbaratı (TI) listelerine hızla girerek DNS Sinkhole veya güvenlik duvarlarınca engellenir.

Bunun yerine kötü amaçlı yazılım, belirli bir tohum (seed - genellikle tarih veya finansal indeks) kullanarak her gün binlerce rastgele alan adı türetir (`xkf92mqp7vla81zk.top`, `qz98xkw7mp201flbv.biz`). Saldırgan bu alan adlarından yalnızca bir veya ikisini kaydeder.

**Tespit Metrikleri:**
1. **Şannon Bilgi Entropisi ($H$):**
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Meşru alan adlarında insan dilinin fonetik yapısından ötürü entropi düşüktür ($2.0 - 3.2$ bit). Rastgele türetilmiş DGA alan adlarında harf çeşitliliği maksimuma yaklaştığı için entropi $3.4$ bit üzerine çıkar.
2. **Sessiz Harf Oranı (Consonant-to-Vowel Ratio):**
   Doğal dillerde sesli ve sessiz harfler dengelidir. DGA dizilerinde arka arkaya çok sayıda sessiz harf veya rakam yer alır. Oran $\ge 0.65$ olduğunda şüphe katsayısı tavan yapar.
3. **Alt Alan Adı Uzunluğu:**
   DGA etiketleri genellikle $12$ karakterden uzundur.

### 1.2 DNS Tünelleme ve Veri Kaçırma (Data Exfiltration)
Saldırgan, kurum içerisindeki bir sunucudan gizli verileri (örneğin kredi kartı numaraları, kimlik bilgileri, kaynak kodları) dışarı aktarmak için DNS sorgularının etiket (label) kısmını taşınabilir bir yük (payload) olarak kullanır (örneğin `dGhpcyBpcyBhIHNhbXBsZSBzZWNyZXQ.t.exfil.org`).

- **TXT ve NULL Kayıtları:** Çok miktarda ikili veri aktarımı için kullanılır.
- **Aşırı Uzunluk:** RFC 1035 uyarınca bir DNS etiketi en fazla 63 oktet, tam alan adı (FQDN) ise en fazla 255 oktet olabilir. Meşru sorgular nadiren 45 karakteri aşarken, tünelleme sorguları bu sınırlara yaklaşır.

### 1.3 DNS Amplification (Yansıtma ve Büyütme DoS)
Saldırgan, sahte kaynak IP adresiyle (IP Spoofing) kurbanın IP'sini kaynak göstererek açık DNS çözümleyicilerine (Open Resolvers) `ANY`, `TXT` veya `DNSKEY` sorguları gönderir.
- 40 baytlık küçük bir UDP sorgusu, DNSSEC kayıtları içeren 3000-4000 baytlık devasa bir yanıta dönüşür.
- Büyütme oranı $\ge 25\times$ olduğunda bu bir amplifikasyon saldırısı göstergesidir.

### 1.4 Fast Flux C2 Ağları
Saldırganlar C2 sunucularının IP adreslerinin kolluk kuvvetleri veya güvenlik firmaları tarafından engellenmesini önlemek için Fast Flux tekniğini kullanır.
- **Mikro-TTL:** TTL süresi 30 saniye veya daha kısadır (örneğin 10-15 sn).
- **Yüksek IP Havuzu:** Tek bir DNS sorgusu yanıtında veya birkaç dakika içinde çözümlenen IP'lerin listesi sürekli değişir ve 5'ten fazla farklı coğrafi IP döner. Bu IP'ler genelde ele geçirilmiş zombi bilgisayarlardır (flux agents).

---

## 2. HTTP Protokol Anomalileri ve Web Saldırı Paternleri

HTTP/1.1 ve HTTP/2 protokolleri web dünyasının omurgasıdır. Ancak istemci-vekil sunucu-arka uç mimarisindeki yorumlama farkları kritik açıklara yol açar.

### 2.1 HTTP Request Smuggling (RFC 7230 İhlali)
Ön uç (Reverse Proxy / Load Balancer) ile arka uç (Backend Web Server) sunucularının gelen bir HTTP isteğinin sınırlarını farklı yorumlamasından kaynaklanır.
- Ön uç `Content-Length` (CL) başlığına göre gövdeyi okurken, arka uç `Transfer-Encoding: chunked` (TE) başlığını baz alabilir (CL.TE zafiyeti).
- Ya da tam tersi (TE.CL zafiyeti).
- **RFC 7230 Kuralı:** Tek bir HTTP isteğinde hem `Content-Length` hem de `Transfer-Encoding` başlığı yer alıyorsa, bu istek standart dışıdır ve derhal engellenmelidir. Saldırgan bu çatışmayı kullanarak bir sonraki masum kullanıcının isteğine kendi zararlı komutunu enjekte eder (Request Smuggling).

### 2.2 HTTP CRLF Enjeksiyonu (HTTP Response Splitting)
CRLF (`\r\n` veya URL encoded `%0d%0a`), HTTP protokolünde başlıkların ve gövdenin sınırlarını belirleyen taşıyıcı karakterdir.
- Güvensiz bir web uygulaması kullanıcı girdisini doğrudan HTTP yanıt başlıklarına eklerse (örneğin yönlendirme parametresi `url`), saldırgan `%0d%0aSet-Cookie: session=evil_session` enjekte ederek başlığı böler ve tarayıcıya sahte çerezler veya sahte HTML gövdeleri (XSS) enjekte eder.

### 2.3 Path Traversal ve LFI (Dizin Geçişi)
Web sunucusunun kök dizininden (webroot) dışarı çıkarak işletim sisteminin hassas dosyalarını okuma girişimidir.
- Göstergeler: `../`, `..\\`, `..%2f`, `..%5c`, `/etc/passwd`, `win.ini`, `boot.ini`.
- WAF atlatma tekniklerinde çift URL kodlama (`%252e%252e%252f`) veya geçersiz UTF-8 dizileri kullanılır.

### 2.4 Otomatik Saldırı Tarayıcıları (Scanner Signatures)
Saldırganların veya siber istihbarat botlarının web sitelerini tararken kullandıkları otomatik araçlar çoğu zaman belirgin `User-Agent` başlıkları bırakır:
- `sqlmap`, `nikto`, `gobuster`, `dirbuster`, `nmap`, `wpscan`, `masscan`, `acunetix`.

---

## 3. SOC Analisti İçin Adli İnceleme Matrisi

| Anomali Türü | İncelenecek Protokol Alanı | Eşik Kriteri / İmza | Müdahale Eylemi |
|---|---|---|---|
| **DGA Alan Adı** | DNS Query Name | Entropi $\ge 3.4$, Sessiz Oranı $\ge 0.65$ | DNS Sinkhole, Uç Nokta İzolasyonu |
| **DNS Tünelleme** | DNS Query Label, Type | TXT tipi, FQDN $> 45$, Base64 yük | Güvenlik Duvarı UDP 53 Kuralı, SOC Alarmı |
| **DNS Amplification** | DNS Query Type, Boyut Oranı | ANY sorgusu, Büyütme $\ge 25\times$ | Rate Limiting (RRL), ANY Engelleme |
| **Fast Flux C2** | DNS Answer TTL, IP Sayısı | TTL $\le 30$ sn, IP $\ge 5$ | C2 Havuzu Engelleme, Tehdit Paylaşımı |
| **Request Smuggling**| HTTP Headers | CL ve TE başlıklarının eşzamanlı varlığı | HTTP/2 Zorunlu Kılma, WAF Güncelleme |
| **CRLF Enjeksiyonu** | HTTP URI / Query String | `%0d%0a`, `\r\n`, `Set-Cookie:` | Girdi Doğrulama, URL Sanitization |
| **Path Traversal** | HTTP URI / Path | `../`, `..\\`, `/etc/passwd` | Chroot Jail, Beyaz Liste Dosya Denetimi|
| **Zararlı Tarayıcı** | HTTP User-Agent | `sqlmap`, `nikto`, `gobuster` | IP Kara Liste, Rate Limiting, Captcha |

---

## 4. Ustanın Çırağa Öğüdü
Çırak! Ağ telemetrisi asla yalan söylemez. Bir saldırgan sistem loglarını silebilir, olay günlüklerini manipüle edebilir; ancak kablodan geçen ve anahtarlama cihazlarından kaydedilen DNS ve HTTP paketlerini geriye dönük değiştiremez. Protokolün standartlarını (RFC belgelerini) avucunun içi gibi bildiğin gün, saldırganın en sinsi manevrası bile gözünde bir fener gibi parlayacaktır.
