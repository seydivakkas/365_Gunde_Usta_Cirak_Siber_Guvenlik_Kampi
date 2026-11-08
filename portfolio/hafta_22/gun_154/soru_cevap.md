# Gün 154: Aşama 6 Kalite Özeti — Soru & Cevap

---

## 1. Soru: Sıfır Güven (Zero Trust) Mimarisi: Kimlik Doğrulama (AuthN) ve Uç Nokta Sağlığı (Device Posture) Bütünleşmesi

### Soru
Modern kurumsal Sıfır Güven (NIST SP 800-207) mimarisinde, güçlü kimlik doğrulama (FIDO2 MFA) tek başına neden yeterli bir erişim kontrol mekanizması değildir? Uç nokta sağlık kanıtı (Device Attestation / Posture) ile kimlik sinyallerinin Koşullu Erişim (Conditional Access) motorunda eşzamanlı değerlendirilmesi saldırı zincirlerini (Kill Chain) nasıl kırar?

### Detaylı ve Kapsamlı Teknik Cevap
Geleneksel erişim kontrolü modellerinde kimlik doğrulama (Authentication) başarılı olduğunda kullanıcıya talep ettiği kurumsal kaynaklara doğrudan tünel açılırdı. Ancak günümüz tehdit ortamında en büyük risklerden biri **Oturum / Çerez Hırsızlığı (Session Hijacking / Token Theft - MITRE ATT&CK T1539)** ve **Ortadaki Düşman (Adversary-in-the-Middle - AitM)** saldırılarıdır.

**Kimliğin Tek Başına Yetersiz Kaldığı Senaryolar:**
1. **Oturum Çerezi Çalma (Infostealer Malware):** Bir çalışan, şirket hesabına FIDO2 donanım anahtarıyla oturum açmış olabilir. Ancak çalıştığı makinede EDR yoksa veya zararlı bir yazılım (RedLine, Vidar, LummaC2) çalışıyorsa, tarayıcı belleğindeki meşru oturum çerezleri (PRT - Primary Refresh Token, Session Cookies) diskten/bellekten kopyalanır ve saldırganın komuta kontrol sunucusuna iletilir. Saldırgan bu çerezleri kendi tarayıcısına enjekte ederek MFA adımını tamamen atlar (`Bypass MFA`).
2. **Kör Uç Nokta / Zararlı Yazılım Tüneli:** Kullanıcı meşrudur, parolası ve MFA'sı doğrudur; ancak kullandığı bilgisayar ele geçirilmiştir ve saldırgan arka planda uzaktan yönetim aracı (C2) çalıştırmaktadır.

**Uç Nokta Duruşu (Device Posture Attestation) Entegrasyonu:**
Koşullu Erişim (Conditional Access Policy) motoru, erişim isteği geldiğinde iki ana vektörü eşzamanlı doğrulamalıdır:
$$\text{Policy Decision Point (PDP)} = \text{Evaluate}(\text{User Claims} \land \text{Device Health State})$$

* **Cihaz Uyumluluk Sinyalleri (Device Posture Signals):**
  - EDR ajanı aktif mi ve sağlık durumu "Yeşil" mi?
  - TPM 2.0 PCR ölçüm zinciri mühürlü mü (Device Attestation)?
  - BitLocker / FileVault disk şifreleme aktif mi?
  - Cihaz üzerinde çözülmemiş kritik CVE veya yetkisiz yerel admin var mı?
  - İşletim sistemi güncel mi?

Eğer kullanıcı dünyanın en güçlü FIDO2 anahtarına sahip olsa bile, cihazın sağlık skoru eşiğin altındaysa (`Device Non-Compliant`), erişim motoru bağlantıyı **derhal engeller veya izole web tarayıcısına (Browser Isolation) yönlendirir**. Böylece çalınan çerezler güvenilmeyen bir saldırgan makinesinden sunulduğunda IP/Cihaz sertifikası uyuşmazlığı nedeniyle anında geçersiz kılınır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat, kimlik sürücüdür, uç nokta ise otomobildir. Sürücünün ehliyeti (MFA) ne kadar kusursuz olursa olsun, otomobilin frenleri patlamışsa (EDR yok, disk şifresiz, zararlı yazılım aktif) o aracın kurumsal otoyola (iç ağa) çıkmasına asla izin veremezsin! Kimlik ile uç nokta sağlığını birleştirmeyen bir güvenlik mimarisi tek ayakla yürümeye çalışan bir dev gibidir; ilk rüzgarda devrilir.

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2022 yılında dev bir oyun ve teknoloji şirketine yönelik siber saldırıda, tehdit aktörleri şirketin kurumsal Slack ve kod repolarına sızmayı başardı. Şirket tüm çalışanlarında modern SSO ve MFA kullanıyordu. Ancak bir çalışanın kişisel bilgisayarına indirdiği korsan bir yazılım aracılığıyla RedLine Infostealer bulaşmıştı. Zararlı, çalışanın tarayıcısında saklanan geçerli SSO oturum çerezini çaldı. Saldırgan bu çerezi kendi sanal makinesine yükledi ve şirket ağına hiçbir parola veya MFA doğrulaması tetiklemeden doğrudan giriş yaptı. Şirketin koşullu erişim politikaları "Sadece kurumsal MDM/EDR onaylı cihazlardan gelen oturumları kabul et" kuralını zorlamadığı için 150 milyon dolarlık kaynak kod sızıntısı yaşandı.

---

## 2. Soru: Active Directory ve IAM'de "Kalıcı Ayrıcalıkların" (Standing Privileges) Tasfiyesi ve JIT / PIM Mimarisi

### Soru
Kurumsal ortamlarda kalıcı (Standing) `Domain Admins` veya `Enterprise Admins` grubu üyelikleri neden en büyük siber güvenlik riski kabul edilir? Just-In-Time (JIT) ve Ayrıcalıklı Erişim Yönetimi (PAM / PIM) mimarisi bu riski sıfıra indirmek için hangi mekanizmaları kullanır?

### Detaylı ve Kapsamlı Teknik Cevap
Geleneksel sistem yönetiminde sistem mühendisleri veya veritabanı yöneticileri günün 24 saati, haftanın 7 günü `Domain Admins` veya `Local Administrators` grubunun daimi üyesidir. Bu durum saldırganlar için paha biçilmez bir açık büfedir.

**Kalıcı Ayrıcalıkların (Standing Privileges) Yarattığı Tehditler:**
1. **Yanal Hareket ve Bellek Avcılığı (Lateral Movement & LSASS Scraping):** Bir sistem yöneticisi kendi admin hesabıyla rutin e-posta okumak veya internette gezinmek için bir istemci bilgisayarda oturum açtığında, o admin hesabının Kerberos biletleri ve NTLM hash'leri o istemcinin LSASS belleğinde kalır. Saldırgan o istemciyi ele geçirdiği an admin biletini çalarak etki alanına hükmeder (`Pass-the-Ticket`).
2. **İç Tehdit ve Hatalı İşlemler:** Kalıcı yetkiye sahip bir yöneticinin hesabı ele geçirildiğinde saldırgan hiçbir ek yetki yükseltme adımı yapmadan doğrudan etki alanı denetleyicisine müdahale edebilir.

**Just-In-Time (JIT) ve PAM / PIM Çözüm Mimarisi:**
Modern Aşama 6 mimarisinde **Kalıcı Yönetici Üyeliği = 0 (Zero Standing Privileges)** kuralı zorunludur:
* **Günlük Hesap vs Yönetici Hesabı Ayrımı:** Yönetici rutin işleri için yetkisiz standart kullanıcı (`ahmet.yilmaz`) kullanır.
* **Geçici Hak Tanımlama (Time-Bound Elevation):** Yönetici kritik bir bakım veya sunucu kurulumu yapacağı zaman PAM/PIM portalına girer, değişiklik talep numarası (Change Request ID) girerek yetki talep eder.
* **Onay Mekanizması ve Süre Sınırı:** İkinci bir yönetici talebi onaylar (`Dual Control / Four-Eyes Principle`). Yöneticiye en fazla 2 ila 4 saat geçerli olan geçici bir güvenlik grubu üyeliği (veya Kerberos bilet ömrü kısıtlı token) atanır.
* **Otomatik Geri Alma (Revocation):** Süre dolduğu an (örn. 2 saat sonra), sistem arka planda yöneticiyi gruptan otomatik olarak çıkarır.
* **Oturum Kaydı (Session Recording):** Yönetici erişimi esnasında tüm RDP/SSH oturumu video ve tuş vuruşu (Keystroke) seviyesinde adli kanıt olarak kaydedilir.

Bu mimari sayesinde saldırgan bir istemci makineden kimlik bilgisi çalsa dahi, çalınan kimlik o esnada yetkisiz standart bir hesaba ait olduğundan yanal hareket yapamaz.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Çırağım! Bir şirketin Active Directory'sinde `Domain Admins` grubunu açtığında orada 20 tane personel ismi görüyorsan, o şirketin güvenlik mimarı henüz emekleme çağındadır. Kalıcı adminlik bir statü sembolü değil, alnına yapıştırılmış bir hedef tahtasıdır. Yetki sadece ihtiyaç duyulduğu an, ihtiyaç duyulan süre kadar verilmeli ve iş bittiği an geri alınmalıdır!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2021 yılında bir finans kurumunda kıdemli bir sistem yöneticisinin kişisel şifre yöneticisi patlatıldı. Şifre yöneticisi içinde yöneticinin şirket içi `domain_admin` hesabı ve parolası bulunuyordu. Ancak kurum 6 ay önce PAM/PIM mimarisine geçmiş ve tüm personelin kalıcı `Domain Admins` üyeliklerini iptal etmişti. Saldırganlar ele geçirdikleri kullanıcı adı ve parolayla şirketin VPN'ine bağlandıklarında şok yaşadılar: Hesap standart bir kullanıcı gibi yetkisizdi ve hiçbir kritik sunucuya RDP yapamıyordu. JIT yetki talebi açmaya çalıştıklarında ise SMS/FIDO2 ikinci faktör ve yönetici onayı gerektiği için alarm çaldı ve saldırgan 10 dakika içinde hiçbir veriye dokunamadan kapı dışarı edildi. Kalıcı yetkilerin sıfırlanması kurumu kurtardı.

---

## 3. Soru: Değiştirilemez Yedekleme (WORM Storage) ve Çekirdek Savunması: Ransomware'in Son Kalesini Yıkmak

### Soru
Modern kurumsal fidye yazılımları (LockBit, BlackCat, Akira), sistemleri şifrelemeden önce neden ilk iş olarak VSS gölge kopyalarını siler (`vssadmin delete shadows`), yerel yedekleri bozar ve EDR servislerini durdurmaya çalışır? WORM (Write Once, Read Many) ve LSA Protection (`RunAsPPL`) ikilisi bu imha zincirini çekirdek ve depolama seviyesinde nasıl durdurur?

### Detaylı ve Kapsamlı Teknik Cevap
Fidye yazılımı tehdit aktörlerinin ana gelir kaynağı kurbanı "çaresiz bırakmaktır". Eğer kurban 2 saat içinde temiz bir yedekten geri dönebiliyorsa, saldırgan fidye koparamaz. Bu nedenle son nesil fidye yazılımları çok aşamalı bir "savunma ve kurtarma imha rutini" uygular:

1. **Savunmayı Zayıflatma (Defense Evasion - T1562.001):**
   Saldırganlar yerel yönetici veya SYSTEM haklarına eriştiklerinde kayıt defteri üzerinden EDR'ı kapatmaya (`DisableRealtimeMonitoring=1`), Sysmon'u durdurmaya ve Mimikatz ile LSASS belleğini dökmeye çalışır.
2. **Kurtarma Yeteneğini İmha Etme (Inhibit System Recovery - T1490):**
   Komut satırından `vssadmin.exe delete shadows /all /quiet`, `wbadmin delete catalog` ve `bcdedit /set {default} recoveryenabled No` komutlarını çalıştırarak yerel gölge kopyaları ve geri yükleme noktalarını silerler. Ardından ağ paylaşımlarındaki yedek sunucularına saldırarak yedek arşivlerini şifreler veya silerler.

**Aşama 6 Savunma Çözümü:**
Bu iki yönlü yıkıcı saldırı ancak iki bağımsız katmanın kenetlenmesiyle durdurulabilir:

* **Katman 1: Çekirdek ve İşlem Seviyesi Savunma (RunAsPPL & Tamper Protection):**
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` ayarı, LSASS sürecini Protected Process Light seviyesine çıkarır. SYSTEM seviyesindeki zararlı süreç dahi LSASS belleğini okuyamaz.
  - Microsoft Defender / EDR **Tamper Protection** aktif olduğunda, zararlı yazılım kayıt defterini değiştirmeye kalksa dahi Windows Defender filtre sürücüsü (WdFilter.sys) yazma işlemini çekirdek seviyesinde engeller (`Access Denied`).
* **Katman 2: Fiziksel ve Mantıksal Olarak Ayrı WORM Depolama (S3 Object Lock COMPLIANCE Mode):**
  - Yerel gölge kopyalar silinse dahi, kurumsal yedekler ağdan izole edilmiş veya bulutta S3 Object Lock COMPLIANCE modunda saklanır.
  - COMPLIANCE modunda, saklama süresi (Retention Period - örn. 30 gün) dolana kadar **Root kullanıcı veya AWS Hesap Sahibi dahi** o dosyayı silemez, şifreleyemez veya üzerine yazamaz.
  - Saldırgan tüm sunucuları şifrelese ve tüm yerel diskleri silse bile, WORM yedek deposuna dokunamaz. Kurum sıfır veri kaybı ve sıfır fidye ödemesi ile sistemlerini temiz imajlardan ayağa kaldırır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat! Fidye yazılımına karşı savaşıyorsan şunu aklına kazı: Saldırgan er ya da geç bir uç noktada yerel yönetici hakkı elde edebilir. Senin asıl zaferin, onun yerel yönetici olduğu anda bile EDR'ı kapatamayacağını (`Tamper Protection`), LSASS'ı okuyamayacağını (`RunAsPPL`) ve yedekleri silemeyeceğini (`WORM`) bilmendir. Savunmanın derinliği budur: Her kapının ardına bir çelik kapı daha koyacaksın!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2023 yılında küresel bir otomotiv yan sanayi şirketi BlackCat (ALPHV) fidye çetesinin hedefi oldu. Saldırganlar bir servis hesabı üzerinden iç ağa sızarak 400 sunucuyu 3 saat içinde şifreledi. Saldırganlar geleneksel yedek sunucusuna da ulaştılar ve diskleri sıfırladılar. Ardından şirkete 12 milyon dolarlık fidye talebi ilettiler ve "Tüm yedeklerinizi sildik, ödemekten başka çareniz yok" dediler. Ancak şirketin güvenlik mimarı, Aşama 6 prensiplerine uygun olarak her gece alınan tam yedekleri S3 Object Lock COMPLIANCE modunda tutan izole bir WORM deposuna kopyalatıyordu. Saldırganların kullandığı fidye yazılımı S3 kovasındaki dosyaları silmeye çalışmış ama AWS API'sinden "AccessDenied - Object is under WORM retention" hatası alarak başarısız olmuştu. Şirket tek kuruş fidye ödemeden, 18 saat içinde tüm üretim hattını WORM deposundan geri yükledi ve operasyona devam etti.
