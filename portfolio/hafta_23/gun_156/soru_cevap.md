# Hafta 23 / Gün 156: Soru & Cevap

---

## 1. Soru: Kırık Erişim Denetimi (A01 - Broken Access Control) ve IDOR

### Soru
Modern web ve API mimarilerinde **A01: Kırık Erişim Denetimi (Broken Access Control)** neden OWASP Top 10 listesinin 1 numaralı riski haline gelmiştir? Doğrudan Nesne Referansı (IDOR - CWE-639) zafiyeti ile Fonksiyon Seviyesinde Yetkisizlik (Broken Function Level Authorization) arasındaki teknik fark nedir ve çok kiracılı (multi-tenant) sistemlerde bu riskler mimari düzeyde nasıl önlenir?

### Detaylı ve Kapsamlı Teknik Cevap
Erişim Denetimi (Access Control), kimliği doğrulanmış bir kullanıcının (Subject) hangi kaynaklara veya nesnelere (Object) hangi eylemleri (Action) yapabileceğini belirleyen güvenlik mekanizmasıdır. OWASP Top 10'da 1 numaraya yükselmesinin temel sebebi, mikroservis mimarileri ve zengin JavaScript istemcilerinin (SPA - React, Vue) artmasıyla birlikte yetkilendirme mantığının parçalanması ve otomatik DAST/SAST araçları tarafından iş mantığı (business logic) seviyesinde kolayca tespit edilememesidir.

Teknik ayrım şu şekildedir:
1. **IDOR (Insecure Direct Object Reference - CWE-639):** Veri/Nesne seviyesindeki yetki eksikliğidir. Kullanıcı `/api/v1/orders/8841` rotasını çağırma hakkına sahiptir (yani "Sipariş Görüntüle" fonksiyon yetkisi vardır). Ancak URL veya gövdedeki `8841` ID'si sunucuda oturum sahibi kullanıcının şirketi/kimliği ile ilişkilendirilmezse, kullanıcı `8842` yazarak başka bir müşterinin siparişini ve kredi kartı son 4 hanesini indirebilir.
2. **Fonksiyon Seviyesinde Yetkisizlik (BFLA - CWE-862):** Kullanıcının yapmaya hakkı olmayan bir yönetimsel eyleme (Endpoint) doğrudan istek atabilmesidir. Örneğin standart bir kullanıcı, arayüzde görmediği `POST /api/v1/admin/users/promote` veya `DELETE /api/v1/tenants/99` uç noktasına doğrudan HTTP isteği gönderdiğinde sunucunun rol kontrolü (RBAC) yapmamasıdır.

**Çok Kiracılı (Multi-Tenant) Sistemlerde Mimari Çözüm:**
- **Asla İstemci Verisine Güvenmeme:** İstemciden gelen `tenant_id` veya kullanıcı parametreleri filtreleme kriteri olarak kabul edilmez.
- **Kapsamlı Veritabanı Otomasyonu (Row-Level Security - RLS):** PostgreSQL RLS veya Hibernate ORM filtreleri kullanılarak, her sorgunun `WHERE tenant_id = current_setting('app.current_tenant')` koşulunu veri tabanı katmanında zorlaması sağlanır.
- **Yetkilendirme Middleware'i:** Rotalar iş mantığına girmeden önce merkezi bir politika motoru (Policy Enforcement Point - PEP / Örn: Open Policy Agent - OPA) tarafından denetlenmelidir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! İstemciden gelen hiçbir nesne kimliğine (ID) asla güvenme. Veritabanına 'Bana 55 numaralı faturayı getir' deme; 'Bana oturum açmış bu kullanıcının 55 numaralı faturasını getir' de. Veri tabanı sorgunun WHERE bloğunda oturum açmış kullanıcının kimliği yoksa, o kod saatli bir bombadır!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2018 yılında küresel bir araç kiralama şirketinin API servisinde IDOR açığı keşfedildi. Mobil uygulamanın `/api/v2/reservation?id=XXXX` isteğinde kullanıcı kimlik denetimi yapılmıyordu. Bir araştırmacı, basit bir Python döngüsüyle ID değerlerini 1 artırarak 100.000'den fazla müşterinin tam adı, ehliyet numarası, pasaport fotokopisi ve araç teslim lokasyonlarını dakikalar içinde çekmeyi başardı. Olay, şirkete GDPR kapsamında 18 milyon Euro ceza ve büyük itibar kaybı olarak geri döndü.

---

## 2. Soru: Sunucu Taraflı İstek Sahteciliği (A10 - SSRF) ve Bulut Meta Veri Kalkanı

### Soru
**A10: Server-Side Request Forgery (SSRF - CWE-918)** zafiyeti modern bulut (Cloud / Kubernetes) altyapılarında nasıl tam yetkili bir uzaktan kod çalıştırma (RCE) veya veri ihlali felaketine dönüşür? `169.254.169.254` adresi neden kritik bir hedeftir ve DNS Rebinding saldırılarına karşı SSRF koruması nasıl kurgulanmalıdır?

### Detaylı ve Kapsamlı Teknik Cevap
SSRF, savunmasız bir web sunucusunun, saldırgan tarafından sağlanan rastgele bir URL'ye arka planda HTTP/HTTPS isteği yapmaya zorlanmasıdır. Örneğin bir web uygulamasının "URL'den Profil Resmi İçe Aktar" veya "Webhook Doğrula" özellikleri tipik hedeflerdir.

**Bulut Altyapılarında Felaket Senaryosu (AWS / GCP / Azure):**
Bulut platformlarında sanal makineler (EC2, Compute Engine) ve konteynerler, kendilerine atanan geçici IAM rollerini ve kimlik belirteçlerini **Link-Local IP adresi olan `169.254.169.254` (Instance Metadata Service - IMDS)** üzerinden sorgular.
- Saldırgan profil resmi parametresine `http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol_adi>` yazar.
- Savunmasız sunucu bu isteği yerel ağdan yapar (çünkü `169.254.169.254` dışarıya kapalıdır ama sunucunun kendi içine açıktır).
- Yanıtta AWS IAM `AccessKeyId`, `SecretAccessKey` ve `Token` değerleri döner.
- Saldırgan bu anahtarları yerel bilgisayarında `aws configure` ile kullanarak şirketin tüm S3 kovalarını, RDS veri tabanlarını ve yedeklerini ele geçirir.

**DNS Rebinding Saldırısı ve Koruması:**
Saldırgan alan adı seviyesinde koruma yapan filtreleri atlatmak için `attacker.com` alan adını kullanır. İlk DNS sorgusunda IP `1.2.3.4` döner (filtre izin verir). Ancak web sunucusu HTTP isteğini yaparken ikinci kez DNS sorguladığında (TTL=0 sayesinde) IP `127.0.0.1` veya `169.254.169.254` döner.

**Kusursuz Savunma Mimarisi:**
1. **Katı Alan Adı İzin Listesi (Allowlist):** Yalnızca bilinen ve güvenilen harici etki alanlarına istek yapılmasına izin verilir (`*.trustedpartner.com`).
2. **DNS Çözümleme ve IP Doğrulama:** URL'deki alan adı çözümlenir; çıkan IP adresi özel bloklarda (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) veya Link-Local blokta (`169.254.0.0/16`) ise istek derhal iptal edilir.
3. **IMDSv2 Zorunluluğu:** AWS ortamlarında IMDSv2 etkinleştirilerek oturum token'ı almak için `X-aws-ec2-metadata-token-ttl-seconds` başlığı zorunlu tutulur; basit GET istekleri metadata döndüremez.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Sunucunun kendi elleriyle dışarıdan aldığı URL'ye istek atması, kör bir kurşunu kendi odana sıkmak gibidir. Kullanıcıdan URL alıp curl veya requests ile çağıracaksan; Link-Local IP'leri (169.254.0.0/16) ve yerel ağını (RFC 1918) ağ seviyesinde (iptables/WAF) o sunucuya kesinlikle yasaklayacaksın!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2019 yılında Capital One bankasının uğradığı ve 100 milyondan fazla kredi kartı başvurusunun çalındığı tarihi sızıntı tam bir SSRF klasiğidir. Bir WAF yapılandırmasındaki SSRF açığını kullanan eski bir AWS çalışanı, EC2 meta veri servisinden (`169.254.169.254`) WAF rolüne ait geçici IAM anahtarlarını çekmiş ve ardından bankanın müşteri verilerini barındıran 700'den fazla S3 kovasını saniyeler içinde kopyalamıştır.

---

## 3. Soru: Güvensiz Tasarım (A04) vs. Güvenlik Yanlış Yapılandırması (A05)

### Soru
OWASP Top 10 taksonomisinde **A04: Güvensiz Tasarım (Insecure Design)** ile **A05: Güvenlik Yanlış Yapılandırması (Security Misconfiguration)** arasındaki temel kavramsal fark nedir? Mükemmel şekilde hatasız (bug-free) kodlanmış bir uygulama nasıl güvensiz bir tasarıma sahip olabilir ve üretim ortamlarında "varsayılan yapılandırma laneti" nasıl kırılır?

### Detaylı ve Kapsamlı Teknik Cevap
Güvenlik literatüründe çok sık karıştırılan bu iki kategori, hatanın oluştuğu yaşam döngüsü aşaması açısından taban tabana zıttır:

1. **A04: Güvensiz Tasarım (Insecure Design):**
   - Hatanın kaynağı kodlama (implementation) değil, sistemin mimari tasarımı ve iş mantığı modellemesidir.
   - **Örnek:** Bir e-ticaret uygulamasında "Parola Sıfırlama" akışının sadece "Annenizin kızlık soyadı nedir?" sorusuna dayanması. Bu kod sıfır bellek sızıntısıyla, kusursuz SQL parametreleriyle yazılmış olsa bile **tasarım gereği güvensizdir**; çünkü sosyal mühendislikle bu bilgi kolayca toplanabilir.
   - Benzer şekilde, bilet satış sisteminde kullanıcı başına hız sınırlaması (Rate Limiting) konulmaması kodlama hatası değil, tasarım eksikliğidir. Tasarımda tehdit modellemesi (Threat Modeling - STRIDE) yapılmamıştır.

2. **A05: Güvenlik Yanlış Yapılandırması (Security Misconfiguration):**
   - Tasarım ve kodlama doğru olsa bile, altyapının, web sunucusunun (Nginx, Apache), framework ayarlarının veya veritabanının özensiz yapılandırılmasıdır.
   - **Örnekler:** Django/Flask uygulamasında üretimde `DEBUG = True` bırakılması (böylece hata anında tüm ortam değişkenleri ve veritabanı şifreleri ekrana basılır), Elasticsearch veya Redis'in şifresiz olarak `0.0.0.0` portundan internete açılması, HTTP güvenlik başlıklarının (HSTS, CSP, X-Frame-Options) eklenmemesi.

**Varsayılan Yapılandırma Lanetini Kırma Yöntemleri:**
- **IaC (Infrastructure as Code) ve Sıkılaştırma Şablonları:** Sunucu ve konteynerlerin elle değil, Ansible veya Terraform ile otomatik sıkılaştırılmış altın imajlardan (Golden Images / CIS Benchmarks) ayağa kaldırılması.
- **Otomatik CI/CD Güvenlik Kapıları:** Pipeline içerisinde `checkov`, `trivy` veya `conftest` çalıştırılarak debug modlarının veya açık varsayılan şifrelerin bulunması durumunda derlemenin (build) kırılması.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! İyi bir marangoz çürük tahtadan sağlam masa yapamaz. Tasarımı sakat olan bir sisteme istediğin kadar güvenlik duvarı (WAF) kur, o sistem yine çöker. Tasarımda tehdit modelini çizeceksin, üretimde ise 'nasılsa varsayılan ayar iyidir' demeyip her cıvatayı elinle sıkacaksın!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2020 yılında büyük bir sağlık verisi sağlayıcısı, COVID-19 test sonuçlarını sorgulamak için bir web portalı tasarladı. Tasarımcılar sisteme giriş için yalnızca "T.C. Kimlik No" ve "Doğum Yılı" alanlarını zorunlu kıldı; SMS veya e-posta doğrulama koymadı (A04 Güvensiz Tasarım). Üstelik sistemde hiçbir hız sınırlaması da yoktu. Bir saldırgan, sızdırılmış seçmen veritabanındaki T.C. kimlik numaralarını otomatik betikle portala göndererek yüz binlerce vatandaşın pozitif/negatif sağlık raporlarını ve reçetelerini ifşa etti. Kodda tek bir SQLi veya XSS yoktu; sistem sadece kötü tasarlandığı için çöktü.
