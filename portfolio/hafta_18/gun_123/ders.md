# GÜN 123: Güvenli Varsayılanlar (Secure by Default) ve Fail-Safe / Fail-Secure Mimarisi

## 1. Usta-Çırak Açılış Konuşması

**Usta:** Evlat, bilgisayar güvenliğinin babaları kabul edilen Jerome Saltzer ve Michael Schroeder, 1975 yılında yazdıkları efsanevi makalede ("The Protection of Information in Computer Systems") şöyle der: *"Unless a subject is given explicit access to an object, it should be denied access by default."* Yani: "Bir özneye bir nesneye erişim için açıkça izin verilmemişse, varsayılan olarak erişim reddedilmelidir!"

Bu prensibe **Fail-Safe Defaults (Güvenli Varsayılanlar İlkesi)** denir. Aradan 50 yıl geçti ama yazılım dünyasının en ölümcül felaketleri hâlâ bu basit kuralın çiğnenmesinden kaynaklanıyor. Geliştiriciler test ederken kolay olsun diye debug modunu açar, varsayılan şifreyi `admin/admin` bırakır, firewall kuralını `ALLOW ALL` yapar ve bunu canlıya çıkarır!

**Çırak:** Hocam, peki bir sistem beklenmedik bir arızayla karşılaştığında —örneğin veritabanı çöktüğünde veya yetki servisi zaman aşımına uğradığında— ne yapmalıdır?

**Usta:** İşte zurnanın zırt dediği yer burasıdır evlat! İki ana yol vardır:
1. **Fail-Open (Açık Kalma / Serbest Geçiş):** Arıza anında "kullanıcılar mağdur olmasın, sistem aksamasın" diyerek kapıları ardına kadar açmak! Siber güvenlikte buna **CWE-636 Zafiyeti** denir ve bir felakettir! Saldırganlar kimlik doğrulama servisine DDoS atıp servisi düşürür, sistem Fail-Open olduğu için şifresiz içeri girer!
2. **Fail-Closed / Fail-Secure (Güvenli Kapanma):** Arıza anında "Önce Güvenlik" diyerek tüm erişimleri anında bloke etmek ve alarm üretmek! Güvenli bir sistem arıza anında kapıyı açmaz, kapıyı sürgüler!

---

## 2. Saltzer-Schroeder Güvenli Tasarım Prensipleri

Siber güvenlik mimarisinin temelini oluşturan bu 8 altın kuralı ezbere bileceksin:

| Prensip | Anlamı ve Güvenlik Karşılığı | İhlal Durumunda Oluşan Risk |
|---|---|---|
| **Fail-Safe Defaults** | Varsayılan durum RED (Deny) olmalıdır; yalnızca istisnalara açık izin verilir. | Tanımlanmamış her istek içeri sızar (Default-Permit açığı). |
| **Complete Mediation** | Her erişim talebi istisnasız her seferinde denetlenmelidir; önbelleğe güvenilip kontrol atlanamaz. | TOCTOU (Time-of-Check to Time-of-Use) ve yetki atlatma (CWE-367). |
| **Economy of Mechanism** | Güvenlik tasarımı mümkün olduğunca basit ve anlaşılır olmalıdır. | Karmaşık kodda gözden kaçan yetki bypass açıkları. |
| **Open Design** | Güvenlik algoritmanın gizliliğine değil, anahtarların gizliliğine dayanmalıdır (Kerckhoffs İlkesi). | Güvenlik açığının gizleme yoluyla saklanması (Security by Obscurity). |
| **Separation of Privilege** | Kritik işlemler tek bir anahtarla değil, çoklu koşulla (MFA, 4-Göz ilkesi) açılmalıdır. | Tek bir hesabın ele geçirilmesiyle tüm sistemin çökmesi. |
| **Least Privilege (PoLP)** | Bir kullanıcıya yalnızca görevini yapacağı asgari yetki verilmelidir. | Gereksiz admin yetkisiyle yanal yayılma ve veri sızıntısı. |
| **Least Common Mechanism** | Kullanıcılar arasında paylaşılan ortak kanallar ve mekanizmalar asgariye indirilmelidir. | Yan kanal saldırıları (Side-channel) ve bilgi sızıntısı. |
| **Psychological Acceptability** | Güvenlik mekanizması kullanıcının işini aşırı zorlaştırmamalı, sezgisel olmalıdır. | Kullanıcıların güvenlik önlemlerini devre dışı bırakması. |

---

## 3. CWE-1188: Güvenli Olmayan Varsayılan Yapılandırmalar

CISA (Amerikan Siber Güvenlik Ajansı) artık yazılımlarda **"Secure by Design & Secure by Default"** zorunluluğu getirdi. Kutudan çıktığı anda şu 6 hatayı barındıran sistemler doğrudan CWE-1188 zaafiyeti taşır:

1. **Debug / Geliştirme Modu Açık:** Hata ayıklama modunda stack trace, bellek dökümü ve kaynak kodların sızması.
2. **Varsayılan Parola Değiştirilmemiş:** Cihazların fabrika çıkışlı `admin:admin` veya `root:toor` parolalarıyla internete bağlanması (Mirai botnet'inin doğuş sebebi!).
3. **Permissive CORS (`Access-Control-Allow-Origin: *`):** Herhangi bir kötü niyetli web sitesinin kullanıcının tarayıcısı üzerinden iç API'lere istek atabilmesi.
4. **Şifresiz İletişim İzni:** HTTP, Telnet veya FTP'nin varsayılan olarak açık gelmesi; TLS zorunluluğunun olmaması.
5. **Şifresiz Depolama:** Veritabanının diski şifrelemeden düz metin (plaintext) yazması.
6. **Default-Permit:** Güvenlik duvarı veya yetki motorunun kural eşleşmediğinde "Geçebilir" demesi.

---

## 4. Fail-Secure (Fail-Closed) vs Fail-Open İkilemi

**Çırak:** Hocam, Fail-Open'ın meşru olduğu hiçbir yer yok mudur?

**Usta:** Vardır evlat, ama yalnızca **İnsan Can Güvenliği (Life-Safety)** söz konusu olduğunda!
- Bir binada yangın alarmı çaldığında, turnikeler ve yangın çıkış kapıları kilitli kalamaz; elektrik kesildiğinde kapılar **Fail-Open** olur ki insanlar içeride yanarak ölmesin!
- Ancak yazılım dünyasında, bankacılıkta, kimlik doğrulamada ve veri güvenliğinde can güvenliği değil **bilgi güvenliği** esastır. Veritabanı yanıt vermiyorsa ATM parayı dağıtmaz; "İşlem yapılamıyor" der ve kartı iade eder! Yetki servisi çöktüyse API kapıları açmaz; `HTTP 503 Service Unavailable / Access Denied` döner!

Bir siber güvenlik sisteminde yetkisiz fail-open uygulamak affedilemez bir kusurdur (**CWE-636**).

---

## 5. Uygulama Mimarisi

Bugün geliştirdiğimiz `secure_defaults_failsafe_engine.py`:
1. `ResourceConfig` ile tüm bileşenleri modeller ve 6 temel CWE-1188 güvenlik varsayılanını otomatik tarar.
2. `PolicyDecisionPoint (FailSafePDP)` ile Saltzer-Schroeder Default-Deny erişim mantığını işletir.
3. Çeşitli sistem arızalarını (`DATABASE_DOWN`, `AUTH_SERVICE_TIMEOUT`, `CORRUPTED_POLICY`, `NETWORK_PARTITION`) simüle eder.
4. Arıza anında erişimi otomatik olarak bloke eden **Fail-Secure** korumasını çalıştırır; yetkisiz Fail-Open girişimlerini `InsecureFailOpenForbiddenError` fırlatarak durdurur.

Evlat, kod yazarken her zaman şu soruyu sor: "Benim kodum patladığında kapı açık mı kalacak, kilitli mi?" Kapıyı daima kilitli bırakan mühendis ol!
