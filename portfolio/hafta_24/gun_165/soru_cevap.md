# Gün 165: CORS ile Güvenlik Sınırı — Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. CORS (Cross-Origin Resource Sharing) ile SOP (Same-Origin Policy) arasındaki ilişki nedir? Neden "CORS bir güvenlik duvarıdır" ifadesi teknik açıdan tamamen hatalıdır?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın web tarayıcı güvenlik modelinin temel taşı olan Aynı Köken İlkesi (SOP) ile CORS mekanizmasını birbirine karıştırmamasını bekliyorum. Adaydan; varsayılan güvenlik kalkanının SOP olduğunu, SOP'un bir sitenin başka bir sitenin verisini JavaScript ile okumasını engellediğini; CORS'un ise bir güvenlik kalkanı değil, tam aksine bu kalkanı belirli koşullarla esneten ve dış kökenlere izin kapısı açan bir protokol olduğunu duymak istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
CORS bir güvenlik duvarı veya koruma kalkanı değildir; Same-Origin Policy (SOP) tarafından uygulanan katı izolasyonu kontrollü olarak gevşeten bir izin mekanizmasıdır. Tarayıcılarda varsayılan olarak yürütülen SOP kuralı, `Origin A` üzerindeki bir betiğin `Origin B`'ye ait HTTP yanıt gövdesini okumasını engeller. CORS ise sunucunun tarayıcıya `Access-Control-Allow-Origin` gibi başlıklar aracılığıyla *"Şu dış kökene ait JavaScript kodunun benim yanıtımı okumasına izin veriyorum"* demesini sağlar. Dolayısıyla CORS koruma sağlamaz; izin verir. Eğer CORS yanlış yapılandırılırsa, SOP'un sağladığı güvenlik sınırı zayıflar ve veri sızıntılarına yol açar.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Kritik ayrım şudur: **SOP istek göndermeyi değil, dönen yanıtın JavaScript tarafından okunmasını (read-access) engeller.**
Örneğin bir basit GET veya POST isteği SOP altında bile sunucuya ulaşır ve sunucuda işlenir (bu yüzden CSRF oluşabilir!). Ancak dönen yanıt tarayıcı tarafından tutulur.
CORS başlıkları, sunucunun tarayıcıya bu yanıtı istemci tarafındaki JavaScript koduna teslim edip etmeyeceğini bildirir.
Eğer geliştirici CORS'u bir firewall sanıp tüm yetkilendirmeyi CORS başlıklarına devrederse, sunucu tarafında API güvenliği çöker. Sunucu uç noktaları kimlik doğrulamayı (Authentication) ve yetkilendirmeyi (Authorization) kendi içinde bağımsız olarak doğrulamak zorundadır; CORS yalnızca tarayıcı istemcisine dönük bir izin beyanıdır.

---

### Soru:
2. "Arbitrary Origin Reflection" (Gelen Origin'in Körlemesine Geri Yansıtılması) zafiyeti nasıl ortaya çıkar ve bir saldırgan `Access-Control-Allow-Credentials: true` başlığıyla birlikte kurbanın gizli verilerini nasıl ele geçirir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın sahada en çok karşılaşılan ve kurumsal ortamlarda kritik veri sızıntılarına yol açan CORS misconfiguration zafiyetinin iç yapısını bilip bilmediğini sınıyorum. Adaydan; sunucunun gelen `Origin` başlığını doğrulamadan doğrudan `Access-Control-Allow-Origin` değerine kopyalamasını, `Credentials: true` ile birlikte tarayıcının kurbanın oturum çerezlerini kullanarak yaptığı istekten dönen JSON verisini saldırganın JavaScript koduna teslim etmesini teknik ayrıntılarıyla anlatmasını istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Arbitrary Origin Reflection zafiyeti, backend sunucusunun gelen HTTP isteğindeki `Origin` başlığını hiçbir beyaz liste kontrolünden geçirmeden doğrudan `Access-Control-Allow-Origin: <Gelen_Origin>` olarak geri döndürmesi ve yanıta `Access-Control-Allow-Credentials: true` eklemesiyle oluşur. Saldırgan, hazırladığı zararlı sayfada (`evil.com`) arka planda kurbanın tarayıcısına hedef API'ye (`api.banka.internal`) `credentials: "include"` seçeneğiyle bir fetch isteği attırır. Kurbanın oturum çerezleri tarayıcı tarafından otomatik eklenir. Sunucu isteği karşıladığında gelen `Origin: https://evil.com` değerini yanıt başlığına kopyalar. Tarayıcı bu başlığı görünce `evil.com` kökeninin yanıtı okumasına izin verir ve saldırgan kurbanın tüm gizli profil, bakiye veya finansal verilerini kendi sunucusuna sızdırır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
W3C CORS standardına göre, eğer `Access-Control-Allow-Credentials: true` ayarlanmışsa `Access-Control-Allow-Origin: *` (joker karakter) kullanılması kesinlikle yasaktır ve tarayıcı bu yanıtı engeller.
İşte tam bu noktada tecrübesiz geliştiriciler joker karakter hatasından kaçmak için *"Gelen origin neyse onu geri yazalım"* şeklinde tehlikeli bir dinamik kod yazarlar:
`ACAO = req.headers["Origin"]`
Bu durum pratikte `*` joker karakterinden bile çok daha tehlikelidir; çünkü joker karakterde kimlik bilgisi (cookie/auth) iletilmezken, bu dinamik yansıtma sayesinde saldırgan kimliği doğrulanmış tüm özel verilere tam okuma erişimi kazanır.
Savunma:
Gelen Origin asla dinamik yansıtılmamalı; yalnızca statik, önceden tanımlanmış katı bir beyaz liste (`Set`) içindeyse ACAO başlığı oluşturulmalıdır.

---

### Soru:
3. CORS yapılandırmalarında `Origin: null` başlığına güvenmek neden büyük bir güvenlik açığıdır? Ayrıca dinamik CORS yanıtlarında `Vary: Origin` başlığının bulunmaması hangi saldırıya (Cache Poisoning) zemin hazırlar?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın CORS'un derin köşelerini; sandbox iframe'lerin, `data:` URI'ların ve `file://` şemalarının `null` origin üretmesini ve saldırganların bu mekanizmayı nasıl kullandığını bilmesini istiyorum. İkinci kısımda ise HTTP önbellekleme (caching) mekanizması ile CORS arasındaki etkileşimi ve `Vary: Origin` başlığı eksikliğinde ortaya çıkan Web Cache Poisoning riskini açıklamasını bekliyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Bir sunucu `Origin: null` değerini kabul ettiğinde, saldırgan doğrudan bir domain kullanmak yerine kurbanın tarayıcısında bir **sandbox iframe** (`<iframe sandbox="allow-scripts allow-top-navigation" src="...">`) veya `data:` URL'si üzerinden hedef API'ye istek attırır. Tarayıcı bu tür izole bağlamlardan çıkan isteklerin `Origin` başlığını otomatik olarak `null` yapar. Sunucu `null` kökene izin veriyorsa, saldırgan iframe içinden kurbanın verilerini okuyarak CORS sınırını aşar.
`Vary: Origin` başlığının eksikliği ise, aradaki CDN veya vekil sunucuların (proxy) dinamik CORS yanıtlarını yanlış önbelleğe almasına neden olur. Saldırgan `Origin: evil.com` ile istek atıp `ACAO: evil.com` yanıtını önbelleğe zehirlerse (Cache Poisoning), ardından meşru kullanıcılar siteye girdiğinde CDN bu önbelleklenmiş yanıtı döner; bu da meşru kullanıcıların uygulamaya erişememesine veya verilerin saldırgan kökene sızmasına yol açar.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
`null` origin, RFC 6454 standardında gizlilik veya güvenlik nedeniyle kökeni gizlenmiş bağlamları temsil eder. Geliştiriciler yerel dosya testlerinde (`file:///`) kolaylık olsun diye `if (origin === 'null')` kuralı ekler. Oysa sandbox iframe'ler saldırganların köken kısıtlamalarını by-pass etmek için kullandığı en temel araçtır. Bu nedenle `null` köken KESİNLİKLE beyaz listeye eklenmemelidir.
`Vary: Origin` başlığı ise HTTP önbellek anahtarının (Cache Key) bir parçasıdır. CDN veya ters vekil sunucu, `Vary: Origin` gördüğünde her farklı `Origin` başlığı için ayrı bir önbellek kaydı tutar. Eğer bu başlık yoksa, CDN ilk gelen yanıtı tüm sonraki istemcilere sunar. Bu durum hem DoS (meşru kökenlerin reddedilmesi) hem de kalıcı veri sızıntısı riskleri doğurur.
