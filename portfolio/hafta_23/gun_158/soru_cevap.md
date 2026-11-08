# Hafta 23 / Gün 158: Soru & Cevap

---

## 1. Soru: Oturum Sabitleme (Session Fixation) ve Ayrıcalık Yükseltme Savunması

### Soru
**Oturum Sabitleme (Session Fixation - CWE-384)** saldırısı teknik olarak nasıl gerçekleştirilir? Neden bir kullanıcının kimlik doğrulaması (Login) yapması veya sistem içinde yetki düzeyinin yükselmesi (Privilege Escalation - örneğin User'dan Admin paneline geçiş) durumunda oturum belirtecinin (Session ID) zorunlu olarak yenilenmesi gerekir? Bu kural uygulanmazsa ortaya çıkacak güvenlik felaketi nedir?

### Detaylı ve Kapsamlı Teknik Cevap
Oturum Sabitleme, saldırganın kurbana önceden bildiği meşru bir oturum kimliğini kabul ettirmesi ve kurban bu oturum üzerinde kimlik doğruladıktan sonra saldırganın da aynı oturum kimliğini kullanarak kurbanın yetkileriyle sisteme sızmasıdır.

**Saldırının Aşamaları:**
1. **Oturum Kimliği Elde Etme:** Saldırgan hedef web sitesine gider ve henüz giriş yapmadan sunucudan anonim bir oturum çerezi alır (örneğin `session_id=attacker_known_id`).
2. **Sabitleme / Enjeksiyon (Trap):** Saldırgan kurbana özel bir bağlantı gönderir: `https://portal.sirket.com/login?session_id=attacker_known_id` veya alt alan adındaki bir XSS açığı ile kurbanın tarayıcısına `Set-Cookie: session_id=attacker_known_id` enjekte eder.
3. **Kurbanın Giriş Yapması:** Kurban bağlantıyı tıklar ve kendi kullanıcı adı ve şifresiyle sisteme giriş yapar.
4. **Felaket Noktası:** Eğer web uygulaması giriş yapıldığında oturum kimliğini değiştirmezse (aynı `attacker_known_id` üzerinde kullanıcının durumunu `authenticated=True` yaparsa), saldırgan kendi tarayıcısından `Cookie: session_id=attacker_known_id` başlığıyla siteyi açtığında kurbanın tüm hesabına tam erişim sağlar!

**Ayrıcalık Yükseltmede (Privilege Escalation) Neden Zorunludur?**
Benzer şekilde, standart bir kullanıcı oturum açtıktan sonra daha hassas bir bölüme (örneğin Sistem Yönetim Konsolu / Admin Panel) geçtiğinde veya 2. faktör doğrulamasını (MFA) tamamladığında oturum kimliği **derhal yenilenmelidir**. Aksi takdirde, kurbanın düşük yetkili oturumunu daha önce dinlemiş olan bir saldırgan, kurban yetki yükselttiği anda otomatik olarak admin yetkisine kavuşur.

**Teknik Çözüm:**
- `regenerate_session_id()`: Kimlik doğrulama veya yetki seviyesi değiştiği an, sunucu tarafında eski oturum kaydı kalıcı olarak imha edilir (`REVOKED`) ve CSPRNG ile üretilmiş yepyeni bir oturum kimliği atanır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Kullanıcı kapıdan içeri girmeden önceki kimliği ile kapıdan içeri girdikten sonraki kimliği asla aynı olamaz. Kullanıcı şifresini yazıp 'Giriş'e bastığı milisaniyede eski oturum kimliğini çöpe atacaksın, sıfırdan tertemiz bir oturum kimliği vereceksin. Bu kuralı es geçersen, kapıyı kilitlediğini sanırken anahtarı saldırganın avucuna bırakırsın!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2011 yılında büyük bir çevrimiçi ödeme platformunda Session Fixation zafiyeti raporlandı. Saldırganlar forumlarda "İndirim Kuponu" adı altında oturum parametresi içeren linkler paylaşıyordu. Linke tıklayıp alışveriş yapan kullanıcılar kart bilgilerini girdiklerinde, oturum kimliği yenilenmediği için saldırganlar aynı link üzerinden kurbanların kayıtlı kredi kartlarını ve sipariş adreslerini saniyeler içinde görüntüleyebildi. Şirket, tüm giriş ve ödeme onay adımlarına zorunlu oturum rotasyonu ekleyerek açığı kapattı.

---

## 2. Soru: Boşta Kalma (Idle) vs. Mutlak (Absolute) Zaman Aşımı Mimarisi

### Soru
Kurumsal bir web uygulamasında yalnızca **Boşta Kalma Zaman Aşımı (Idle Timeout)** kullanmak neden yetersizdir? Neden **Mutlak Oturum Zaman Aşımı (Absolute Timeout)** mekanizması mimari olarak zorunlu bir güvenlik katmanıdır? Bu iki zaman aşımının çalışma prensipleri ve hassas sistemlerde (bankacılık, sağlık) ideal süre sınırları nasıl belirlenmelidir?

### Detaylı ve Kapsamlı Teknik Cevap
Bir oturumun geçerlilik süresi (Session Lifespan), güvenlik ile kullanıcı deneyimi arasındaki en kritik dengedir.

1. **Boşta Kalma Zaman Aşımı (Idle / Inactivity Timeout):**
   - **Çalışma Mantığı:** Kullanıcının son HTTP isteğinden bu yana geçen süreyi denetler: `now - last_activity_epoch > IDLE_LIMIT`.
   - **Hedef:** Kullanıcı ekran başından ayrıldığında (bilgisayarı kilitlemeden kahve almaya gittiğinde veya kütüphanede ortak PC'yi açık bıraktığında) yetkisiz kişilerin oturumu kötüye kullanmasını engeller.
   - **Eksikliği:** Eğer kullanıcı veya arka planda çalışan bir JavaScript betiği (örneğin her 30 saniyede bir veri çeken bir dashboard / keep-alive ping) düzenli istek atmaya devam ederse, `last_activity_epoch` sürekli güncellenir ve oturum **haftalarca veya aylarca ASLA KAPANMAZ!**

2. **Mutlak Oturum Zaman Aşımı (Absolute Session Timeout):**
   - **Çalışma Mantığı:** Oturumun oluşturulduğu ilk andan itibaren geçen toplam süreyi denetler: `now - created_at_epoch > ABSOLUTE_LIMIT`.
   - **Hedef:** Kullanıcı ne kadar aktif olursa olsun, oturumun azami geçerlilik ömrünü kesin bir sınırla kısıtlar.
   - **Güvenlik Amacı (Threat Mitigation):**
     - Bir oturum belirteci ağ dinlemesi, XSS veya proxy logları üzerinden çalınmışsa (Stolen Token), saldırgan bu belirteçle sonsuza kadar işlem yapamaz. Belirtecin kullanılabilirlik penceresi (Window of Vulnerability) en fazla mutlak süre kadardır.
     - Günün sonunda kullanıcıyı zorla yeniden parola veya MFA girmeye zorlayarak kullanıcının varlığını teyit eder.

**Standart Süre Matrisi (NIST SP 800-63B & OWASP ASVS):**
- **Bankacılık ve Finans:** Idle Timeout = 5 - 15 Dakika (300 - 900 sn) | Absolute Timeout = 4 - 8 Saat (14400 - 28800 sn).
- **Kurumsal İntranet ve ERP:** Idle Timeout = 15 - 30 Dakika | Absolute Timeout = 8 - 12 Saat (Mesai bitimi).
- **Sosyal Medya / Düşük Risk:** Idle Timeout = Birkaç gün | Absolute Timeout = 14 - 30 Gün.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! 'Kullanıcı aktif, o halde oturumu kapatmayalım' demek gaflettir. Saldırgan oturumu çaldıysa o da aktiftir! Mutlak zaman aşımı, sistemin emniyet sigortasıdır. Mesai saati bittiğinde veya gün döndüğünde kullanıcıyı nazikçe login ekranına davet edeceksin; 'Hoş geldin, güvenliğin için lütfen yeniden kimliğini doğrula' diyeceksin!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2015 yılında bir telekom operatörünün müşteri hizmetleri portalında yalnızca Idle Timeout uygulanmıştı. Ancak portalın arayüzü yeni mesajları kontrol etmek için her 60 saniyede bir arka planda AJAX polling yapıyordu. Bir müşteri temsilcisinin bilgisayarına bulaşan basit bir truva atı oturum çerezini çaldı. AJAX istekleri yüzünden oturum haftalarca hiç kapanmadı ve saldırganlar bu tek bir oturum belirtecini 18 gün boyunca kullanarak yüzlerce müşterinin SIM kart kopyalama (SIM Swap) işlemlerini gerçekleştirdi. Olaydan sonra şirket polling isteklerini aktivite saymayı bıraktı ve 8 saatlik katı Mutlak Zaman Aşımı getirdi.

---

## 3. Soru: User-Agent ve IP Parmak İzi Bağlama ile Oturum Kaçırma (Hijacking) Tespiti

### Soru
Bir saldırgan kurbanın geçerli oturum belirtecini (Session Token) ele geçirdiğinde, sunucu bu belirtecin kurbana mı yoksa saldırgana mı ait olduğunu nasıl ayırt edebilir? **User-Agent ve IP adresi bağlama (Context Binding)** yöntemleri oturum kaçırmayı (Session Hijacking) engellemede nasıl çalışır ve dinamik IP (mobil ağlar) durumunda yanlış alarmlar (False Positive) mimari olarak nasıl yönetilir?

### Detaylı ve Kapsamlı Teknik Cevap
Oturum Kaçırma (Session Hijacking), geçerli bir oturum kimliğine sahip olan saldırganın bu kimliği sunucuya sunarak kurbanın yerine geçmesidir. Sunucu gelen HTTP isteğindeki `session_id`'yi geçerli gördüğü sürece isteği işler.

**Bağlam Bağlama (Context Binding) Mekanizması:**
Sunucu oturumu oluşturduğu an, yalnızca oturum ID'sini değil, isteğin istemci bağlamını da veritabanına kaydeder:
1. **User-Agent Doğrulaması:** Kurban oturumu `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0` ile açmışsa, saldırgan aynı oturum ID'sini kullanarak Linux, macOS veya Python betiği (`python-requests`, `curl`) üzerinden istek attığı an sunucu User-Agent uyuşmazlığını tespit eder ve oturumu derhal `SUSPENDED_HIJACK_RISK` durumuna alarak erişimi keser.
2. **IP / Alt Ağ (Subnet) Bağlamı:** Kurban oturumu belirli bir IP veya C sınıfı alt ağdan (`/24`) açmışsa, aniden farklı bir ülkeden veya farklı bir ISS'den istek gelmesi kritik bir anomali işaretidir.

**Dinamik IP ve Mobil Ağ Sorunu (False Positive Yönetimi):**
Mobil cihazlarda (4G/5G) baz istasyonu değiştikçe kullanıcının IP adresi hızla değişebilir. Bu durumda katı tekil IP kontrolü meşru kullanıcının oturumunu sürekli sonlandırabilir.
- **Mimari Çözüm:**
  - **Alt Ağ (Subnet) Bağlama:** Bireysel IP yerine `/24` (IPv4) veya `/64` (IPv6) alt ağ prefiksi kontrol edilir.
  - **Cihaz Parmak İzi (Client Hints / TLS Fingerprinting - JA3/JA4):** Tarayıcının TLS el sıkışma parametreleri (desteklenen şifreleme paketleri, TLS uzantıları) işletim sistemi ve tarayıcıya özgüdür. JA4 parmak izi IP değişse bile sabit kalır; IP değiştiğinde JA4 uyuşuyorsa oturum kapatılmaz, ancak şüpheli bir User-Agent veya JA4 değişikliğinde derhal oturum askıya alınır veya kullanıcıdan ek MFA doğrulaması istenir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Bir anahtarın üzerinde isim yazmaz; kim çevirirse kapı ona açılır. Ama kapıdaki nöbetçi giren kişinin yüzüne de bakmalıdır. Gündüz takım elbiseyle gelen adam, gece yarısı aynı anahtarla maskeli ve farklı bir arabayla geliyorsa nöbetçi alarm çalmalıdır. User-Agent ve ağ bağlamı işte o nöbetçinin gözüdür!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2022 yılında önde gelen bir oyun geliştiricisinin Slack kanalları saldırganlar tarafından ele geçirildi. Saldırganlar bir şirket çalışanının ev bilgisayarına sızarak tarayıcısından Slack oturum çerezini çaldı. Saldırganlar bu çerezle doğrudan şirketin iç Slack kanalına girdi ve yardım masasına "Telefonumu kaybettim, lütfen MFA kodumu sıfırlayın" yazarak kurumsal ağa sızmayı başardı. Eğer şirket oturum belirtecini çalışanların şirket VPN IP'sine ve şirket laptoplarının cihaz sertifikasına bağlamış olsaydı (Device Binding), harici bir IP'den gelen o çerez anında reddedilecek ve tarihi veri sızıntısı engellenecekti.
