# GÜN 123: Güvenli Varsayılanlar ve Fail-Safe Soru - Cevap Dokümanı

## SORU 1: Saltzer-Schroeder 'Fail-Safe Defaults' İlkesi Neden Modern Güvenlik Mimarilerinin Temel Taşıdır ve 'Default-Allow' Modelinin Tehlikeleri Nelerdir?

### 1. Soru Başlığı ve Tanımı
Erişim denetim sistemlerinde "Default-Deny" (Varsayılan Olarak Engelle) yaklaşımı ile "Default-Allow" (Varsayılan Olarak İzin Ver) modeli arasındaki fark nedir ve Default-Allow yaklaşımı neden sistemsel bir güvenlik felaketine yol açar?

### 2. Derinlemesine Teknik Analiz
1975 yılında Saltzer ve Schroeder tarafından ortaya konan "Fail-Safe Defaults" ilkesi, bir yetkilendirme mekanizmasının temel varsayımını tanımlar:
1. **İzinlerin Doğası (White-list vs Black-list):**
   - **Default-Deny (White-list):** Sistemin başlangıç durumu mutlak yasaktır. Bir kullanıcı yalnızca onun için açıkça tanımlanmış bir izin kuralı (explicit allow) varsa kaynağa erişebilir.
   - **Default-Allow (Black-list):** Herkes her şeye erişebilir, yalnızca engellenmesi istenen durumlar kara listeye yazılır.
2. **Default-Allow Modelinin Çöküşü:**
   - İnsan zihni ve yazılım ekipleri tüm olası tehditleri, parametre varyasyonlarını ve saldırı senaryolarını öngöremez.
   - Kara listeye dayalı sistemlerde yeni bir uç nokta, yeni bir mikroservis veya yeni bir veri tabanı tablosu eklendiğinde, geliştirici unutursa o kaynak **varsayılan olarak tüm dünyaya açık kalır!**
   - Karakter kodlama (URL encoding, Unicode), null-byte enjeksiyonu veya HTTP request smuggling gibi tekniklerle kara liste filtreleri kolayca atlatılabilir.
3. **Fail-Safe Defaults Avantajı:**
   - Yeni bir servis açıldığında açık kural yazılmamışsa hiç kimse erişemez. Geliştirici erişemeyince kural yazmak zorunda kalır; yani sistem "güvenli yönde" hata verir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kamu kurumu e-Devlet API'sinde güvenlik duvarı kuralları "Default-Allow" mantığıyla yazılmıştır. Güvenlik ekibi `/api/v1/admin/` yolunu engellemiş ancak geliştiriciler yeni bir sürümle `/api/v2/admin-debug/` yolunu devreye aldığında bu yolu engelleme listesine eklemeyi unutmuştur. Bir saldırgan dizin taraması ile bu yeni yolu bulmuş ve hiçbir kurala takılmadan vatandaşlık veritabanına erişmiştir.

**Pratik Çözüm:**
1. **Mimari Dönüşüm:** API Gateway politikası tek bir satırla kökten değiştirilir: `default: DENY`.
2. **Açık Yetkilendirme Kuralı:** Yalnızca onaylanmış uç noktalar ve roller için `PERMIT` kuralları yazılır.
3. **Kapsam Dışı İstekler:** Tanımsız veya yeni açılmış tüm uç noktalar için `FailSafePDP` otomatik olarak `HTTP 403 Forbidden` döner; saldırganın sisteme sızması matematiksel olarak imkansız hale gelir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kapıyı ardına kadar açıp içeri girecek hırsızların listesini tutamazsın! Dünyadaki hırsızların listesi sonsuzdur. Yapacağın iş basittir: Kapıyı kilitleyeceksin, içeriye yalnızca tanıdığın, güvendiğin ve anahtarı olan kişileri tek tek alacaksın. Güvenlikte kara liste tembellik, beyaz liste ise bilgeliktir."

---

## SORU 2: Kimlik Doğrulama ve Yetki Servislerinde CWE-636 'Fail-Open' Zafiyeti Nasıl Ortaya Çıkar ve Saldırganlar Tarafından Nasıl İstismar Edilir?

### 1. Soru Başlığı ve Tanımı
Bir erişim kontrol mekanizmasının harici bağımlılıklardaki (Veritabanı çökmesi, LDAP/OAuth zaman aşımı, bellek yetersizliği) bir hata anında erişime izin vermesi (Fail-Open / CWE-636) nasıl bir zafiyettir ve bu açık nasıl istismar edilir?

### 2. Derinlemesine Teknik Analiz
CWE-636 ("Not Failing Securely - Failing Open"), bir güvenlik denetim fonksiyonunun istisnai veya hatalı bir durumda güvenli durumu korumak yerine varsayılan olarak yetkilendirme onayını vermesidir.

Bu zafiyetin tipik kodlama hataları şunlardır:
```python
# KÖTÜ KOD (FAIL-OPEN / CWE-636 ZAAFİYETİ)
def check_user_permission(user_id, resource_id):
  try:
    return auth_service.verify(user_id, resource_id)
  except ServiceUnavailableError:
    # "Servis çöktü, müşteriyi bekletmeyelim, geçsin!" -> FELAKET!
    logger.warn("Auth servisi kapalı, geçici izin verildi.")
    return True
```

**Saldırganın İstismar Metodolojisi:**
1. Saldırgan sistemin Fail-Open mantığıyla çalıştığını keşfeder (örneğin auth servisine gönderilen malformed token ile 500 hatası tetiklendiğinde erişimin açıldığını görür).
2. Saldırgan ana sisteme saldırmak yerine, arka uçtaki kimlik doğrulama veya veritabanı servisine hedeflenmiş bir DoS/DDoS saldırısı başlatır (veya SYN Flood, connection pool exhaustion uygular).
3. Auth servisi yanıt veremez hale gelip zaman aşımı (Timeout) üretmeye başladığında, ana uygulama Fail-Open moduna geçer.
4. Saldırgan hiçbir kullanıcı adı ve parola girmeden admin paneline veya gizli verilere doğrudan erişir!

**Doğru Mimari (Fail-Closed / Fail-Secure):**
Hata bloğunda `return False` dönülmeli, erişim kesilmeli (`HTTP 503 Service Unavailable / Denied`) ve SOC ekibine P1 kritik alarm fırlatılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kripto para borsasında, para çekme işlemlerini denetleyen harici kara para aklama (AML) risk motoru mevcuttur. Geliştiriciler "AML servisi yavaşlarsa kullanıcılar şikayet eder" diyerek, servisin yanıt vermediği durumlarda çekim emirlerini onaylayan bir `try-except` koymuştur. Bir siber çete, AML sunucusuna UDP flood ile DoS saldırısı yapmış; servis yanıt veremez hale gelince saniyeler içinde 40 milyon dolarlık Bitcoin'i cüzdanlarına aktarmıştır.

**Pratik Çözüm:**
1. **Fail-Secure İlkesi:** AML servisi yanıt vermezse işlem anında dondurulur (Fail-Closed).
2. **Kuyruk ve Karantina:** Başarısız istekler reddedilir veya güvenli kuyruğa alınır.
3. **CWE-636 Denetimi:** `secure_defaults_failsafe_engine.py` kullanılarak tüm arıza modlarında (`simulate_failure`) sistemin daima `DENY` kararı verdiği otomatik birim testlerle kanıtlanır.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, elektrikler kesildiğinde bankanın kasasının kapağının kendiliğinden açıldığını gördün mü hiç? Görürsen o bankaya para yatırma! Bir yazılımcı 'Kullanıcı deneyimi bozulmasın, sistem aksamasın' diyerek güvenlik kontrollerini arıza anında bypass ediyorsa, o yazılımcı bir hacker'dan daha tehlikelidir. Hata anında sistem durur, kapılar kilitlenir; gerekirse müşteri bekler ama asla veri çalınamaz!"

---

## SORU 3: CISA 'Secure by Default' Standartları Çerçevesinde CWE-1188 (Insecure Default Initialization) Zafiyeti Nasıl Denetlenir ve Otomatik Olarak Engellenir?

### 1. Soru Başlığı ve Tanımı
Bir yazılım veya donanım ürününün fabrika çıkışında veya ilk kurulumunda güvensiz varsayılanlarla gelmesi (CWE-1188) hangi yaygın konfigürasyon hatalarını kapsar ve kurumsal mimaride bu hatalar nasıl otomatik olarak engellenir?

### 2. Derinlemesine Teknik Analiz
CWE-1188 ("Insecure Default Initialization of Resource"), bir sistemin kurulum anında en gevşek ve en savunmasız ayarlarla başlatılmasıdır. Bu durum "kurulumu kolaylaştırma" bahanesiyle yapılır ancak siber saldırıların %80'ine zemin hazırlar.

En kritik 5 CWE-1188 bileşeni:
1. **Fabrika Çıkışlı Kimlik Bilgileri (Default Credentials):** Cihazların `admin:password`, `root:root` gibi bilinen şifrelerle gelmesi. Kullanıcı ilk girişte şifre değiştirmeye zorlanmalıdır.
2. **Debug ve Geliştirme Ayarları:** Web framework'lerinde `DEBUG = True` bırakılması. Bu durum tüm ortam değişkenlerinin, veritabanı şifrelerinin ve API token'larının tarayıcıda açıkça görüntülenmesine yol açar.
3. **Şifresiz İletişim (Insecure Transport):** HTTP'nin varsayılan olması, TLS sertifikası yüklenene kadar verinin açık gitmesi. Doğru yaklaşım: HSTS zorunluluğu ve TLS 1.3 varsayılanıdır.
4. **Permissive CORS Başlıkları:** API sunucularında `Access-Control-Allow-Origin: *` ve `Allow-Credentials: true` kombinasyonu, kötü niyetli sitelerin kullanıcı oturumunu sömürmesini sağlar.
5. **Gereksiz Açık Servis ve Portlar:** Sistem kurulduğunda Telnet, FTP, RDP gibi servislerin otomatik olarak ayağa kalkması.

**Çözüm:** Üretim öncesi CI/CD boru hattında çalışan statik ve dinamik konfigürasyon denetleyicileri (Configuration Linters). Eğer `debug_mode == True` veya `default_access != 'DENY'` ise derleme (build) derhal kırılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir IoT kamera üreticisi, cihazlarını varsayılan olarak `root:xc3511` parolasıyla ve Telnet portu (23) açık olarak piyasaya sürmüştür. Kullanıcıların %95'i şifreyi değiştirmemiştir. Mirai botnet saldırganları interneti tarayarak 600.000 kamerayı dakikalar içinde zombi ordusuna katmış ve küresel DNS altyapısını (Dyn DNS) çökerterek interneti durma noktasına getirmiştir.

**Pratik Çözüm:**
1. **Zorunlu İlk Kurulum Akışı:** Cihaz ilk açıldığında güçlü bir parola belirlenmeden internete paket göndermesi engellenir.
2. **Varsayılan Portların Kapatılması:** Telnet tamamen kaldırılır, yalnızca SSH ve mTLS aktif edilir.
3. **CI/CD Entegrasyonu:** Motorumuzdaki `enforce_secure_defaults()` kuralı derleme sürecine eklenir; varsayılanı güvenli olmayan hiçbir imaj dağıtılamaz.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, bir arabayı müşteriye satarken 'Frenler varsayılan olarak devre dışıdır, isterseniz ayarlardan açabilirsiniz' diyebilir misin? Diyemezsin! Güvenlik opsiyonel bir aksesuar değildir; ürünün kendisidir. Güvenliği kullanıcının insafına ve bilgisine bırakan her tasarım kusurludur. Güvenlik, kullanıcının hiçbir şey yapmasına gerek kalmadan, sistem kutudan çıktığı anda en sert zırhını kuşanmış olmalıdır."
