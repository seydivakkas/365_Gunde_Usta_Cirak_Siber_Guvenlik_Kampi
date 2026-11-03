<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 006: Soru-Cevap ve Kavram Doğrulama

Bu belge, Tehdit Modelleme Başlangıcı konusuna ilişkin `SORU BANKASI` standartlarına göre katı 4 bölümlü formatta hazırlanmıştır.

---

### G006-SC1: Tehdit modelleme başlangıcı: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
Tehdit modeli; varlık (asset), güven sınırı (trust boundary), saldırı yüzeyi (attack surface) ve kontrol (mitigation) arasındaki nedensel ilişkiyi kuran yapısal bir analiz yöntemidir. En kritik ilkesi şudur: **Her tehdit gerçekleşmiş bir olay değildir.** Tehdit modelleme, sistemin mimarisini Veri Akış Diyagramları (DFD) ile haritalandırarak ve STRIDE metodolojisini kullanarak potansiyel tehlikeleri henüz birer güvenlik ihlaline (incident) dönüşmeden tasarım aşamasında tespit edip bertaraf etmeyi sağlar.

#### 2. Teknik Gerekçe
Yazılım ve sistem mimarisinde bileşenler tek başına güvenli görünse bile, farklı ayrıcalık seviyeleri arasındaki güven sınırlarını (örneğin kullanıcı girdisi ile uygulama belleği veya yerel makine ile internet hattı) aşarken zafiyetler doğar. Tehdit modeli olmadan geliştirilen sistemlerde savunma reaktif kalır; zafiyetler ancak saldırganlar tarafından istismar edildiğinde fark edilir. Tehdit modelleme, saldırı yüzeyini en aza indirerek proaktif güvenliği mimari düzeyde temin eder.

#### 3. Yaygın Hata
Tehdit modellemesini yalnızca sızma testi (penetration test) aşamasında veya sistem canlıya alındıktan sonra hatırlamak; güven sınırlarını belirlemeden sadece güvenlik duvarı veya antivirüs gibi genel geçer ürünlere güvenmek.

#### 4. Standart ve Kaynak
* NIST SP 800-154: Guide to Data-Centric System Threat Modeling.
* OWASP Threat Modeling Project & Microsoft Threat Modeling Process (STRIDE).

---

### G006-SC2: Tehdit modelleme başlangıcı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Laboratuvarımızın girdisi, yerel bir not uygulamasına (`KriptoNot`) ait bileşenleri, güven sınırlarını, veri akışlarını ve STRIDE tehditlerini içeren `not_uygulamasi_dfd.json` veri dosyasıdır. İşlem, `threat_modeler.py` motorunun bileşen ve akış bütünlüğünü doğrulaması, güven sınırlarını geçen akışların kriptografik kontrollerini denetlemesi ve açıkta kalan tehditleri sorgulamasıdır. Beklenen sonuç, 4 bileşen ve 3 sınırın 0 mimari kusurla doğrulanması ve ASCII DFD şemasının basılmasıdır. Negatif kontrol ise akışlardan birinin kaynağı hayalet bir bileşen yapıldığında veya kritik sınır geçişinde şifreleme kaldırıldığında sistemin hata üretmesidir.

#### 2. Teknik Gerekçe
Bir tehdit modelleme aracının teknik geçerliliği, mimarideki kopuklukları (var olmayan bileşene giden akışlar) ve sahte güvenlik iddialarını (internet sınırını düz metin geçen akışlar) matematiksel olarak yakalayabilmesine bağlıdır. Güven sınırını korumasız geçen bir veri akışı sessizce onaylanırsa modelleme amacını yitirir; bu nedenle negatif kontroller mimari güvenliğin temel sigortasıdır.

#### 3. Yaygın Hata
Laboratuvarda yalnızca ideal ve eksiksiz modelleri çalıştırmak; sınır ihlallerini, tanımsız ID'leri ve mitigasyonsuz bırakılan açık tehdit senaryolarını test etmemek.

#### 4. Standart ve Kaynak
* ISO/IEC 27034: Application Security — Application Security Risk Management.
* NIST CSF 2.0: ID.RA (Risk Assessment) ve PR.DS (Data Security).

---

### G006-SC3: 'Tehdit modelleme başlangıcı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; sistem mimarisindeki güven sınırlarının belirsiz bırakılması, veri akışlarının doğrulamasız/şifresiz geçiş yapması veya tehditlerin tespit edilip karşısına hafifletici kontrol konulmamasıyla oluşur. Risk, Veri Akış Diyagramı (DFD) üzerindeki güven sınırı kesişim noktalarının incelenmesi ve STRIDE matrisindeki boşlukların analizi ile tespit edilir. Önleme ise girdi doğrulaması (Input Sanitization), güçlü kriptografi (AES-256-GCM, TLS 1.3), sertifika sabitleme ve en az yetki mimarisi ile sağlanır.

#### 2. Teknik Gerekçe
Saldırganlar sistemin en güçlü zırhına değil, iki bileşen arasındaki güven sınırının denetimsiz kaldığı noktalara (örneğin yerel SQLite veritabanına yazılan verinin tahrif edilmesi veya ağdan gelen paketin doğrulanmaması) saldırırlar. Bir güven sınırında kimlik doğrulama veya bütünlük denetimi yoksa, tehdit doğrudan istismara (Exploit) ve veri sızıntısına dönüşür. Kontroller (HMAC, GCM Auth Tag, TLS) sınır geçişlerini koruma altına alarak riski kabul edilebilir seviyeye indirir.

#### 3. Yaygın Hata
Yerel diskte saklanan veriyi "zaten kullanıcının kendi bilgisayarında" varsayımıyla şifrelemeden saklamak; yerel depolama sınırını (TB2) güvenli bölge sanmak.

#### 4. Standart ve Kaynak
* Microsoft Security Development Lifecycle (SDL) — Threat Modeling Guidelines.
* OWASP Top 10: A04:2021 — Insecure Design (Güvensiz Tasarım).
