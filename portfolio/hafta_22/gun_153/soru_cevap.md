# Gün 153: Mini Proje 21 — Uç Nokta Risk Panosu — Soru & Cevap

---

## 1. Soru: Çok Vektörlü Uç Nokta Risk Skorlamasında Ağırlık Dağılımı ve Normalizasyon

### Soru
Kurumsal bir uç nokta güvenlik duruşu (Endpoint Security Posture Management - ESPM) motorunda risk skorlaması tasarlanırken, neden saf aritmetik ortalama yerine ağırlıklı füzyon (Weighted Fusion) ve kritik varlık çarpanı (Critical Asset Multiplier) kullanılmalıdır? Ağırlıkların belirlenmesindeki operasyonel ve tehdit odaklı kriterler nelerdir?

### Detaylı ve Kapsamlı Teknik Cevap
Bir uç noktanın güvenliği birbirine eşit etkiye sahip olmayan çok sayıda farklı kontrol mekanizmasından oluşur. Saf aritmetik ortalama kullanıldığında iki büyük matematiksel ve operasyonel yanılsama ortaya çıkar:

1. **Önemsiz Parametrelerin Kritik Açıkları Maskelemesi (False Sense of Security):**
   Örneğin bir sunucuda 10 farklı parametre kontrol ediliyor olsun. Bu parametrelerin 9 tanesi tam puan alırken (örn. güçlü parola politikası, masaüstü kilitlenme süresi, saat senkronizasyonu), yalnızca 1 tanesi ihlal edilmiş olsun: "Sistemde EDR ajanı yüklü değil ve disk şifresiz". Eşit ağırlıklı ortalamada bu sistem `90/100` gibi harika bir puan alır; ancak gerçekte bu sunucu saldırganlar için tamamen savunmasızdır.

2. **Ağırlık Belirlemede Tehdit Odaklı Hiyerarşi:**
   Geliştirdiğimiz motorda ağırlıklar MITRE ATT&CK ve gerçek olay müdahale (IR) istatistiklerine göre optimize edilmiştir:
   * **EDR ve Telemetri (%25):** Görünürlük olmadan hiçbir savunma yapılamaz. Saldırganın ilk hedefi telemetriyi körleştirmektir.
   * **CIS Sıkılaştırma ve Sapma (%20):** Yetkisiz yerel yöneticiler ve devre dışı bırakılmış UAC/ASLR, istismar sonrası yetki yükseltmeyi çocuk oyuncağı haline getirir.
   * **Disk Şifreleme ve TPM (%15):** Fiziksel hırsızlık ve çevrimdışı saldırılara karşı tek savunmadır.
   * **Yedekleme Güvenliği (%15):** Fidye yazılımı karşısında şirketin iflas etmesini engelleyen son kaledir (WORM/Değiştirilemez depolama).
   * **Zafiyet ve Yama Durumu (%15):** Ağ üzerinden sıfır kullanıcı etkileşimiyle içeri sızmayı sağlayan RCE açıklarını modeller.
   * **Uygulama Kontrolü (%10):** Zararlı ikili dosyaların çalışmasını kısıtlar.

3. **Kritik Varlık Çarpanı (Critical Asset Multiplier):**
   Risk formülünde Risk = Tehdit × Zafiyet × **İş Etkisi (Impact)** yer alır. Bir stajyer dizüstü bilgisayarındaki zafiyet ile Active Directory Etki Alanı Denetleyicisindeki (Domain Controller) aynı zafiyetin kuruma maliyeti aynı değildir. Domain Controller ele geçirildiğinde tüm şirket düşer. Bu nedenle kritik varlık bayrağı (`is_critical_asset = True`), nihai risk skorunu doğrudan çarpanla (örn. +%15) yükselterek CISO ve SOC liderlerinin önceliklendirme yapmasını sağlar.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat! Güvenlikte her zafiyet eşit yaratılmamıştır. Bir sistem yöneticisi sana gelip "Panomuz %95 yeşil, ortalama skorumuz çok iyi" derse, ona hemen şu soruyu soracaksın: "O kalan %5'lik kırmızı dilim nerede? Domain Controller'da mı, yoksa dinlenme odasındaki televizyonda mı?" Asla genel ortalamanın seni uyutmasına izin verme; en zayıf halkan kadar güçlüsün!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2020 yılında büyük bir sağlık hizmetleri holdingi, yıllık güvenlik denetiminde uç nokta uyumluluk skorunu "%94 Başarılı" olarak yönetim kuruluna sundu. Kurumun 12.000 bilgisayarı vardı ve gerçekten de %94'ü kusursuz yapılandırılmıştı. Ancak açıkta kalan %6'lık kısım, yoğun bakım ünitelerindeki kritik görüntüleme sunucuları ve dışarıdan bağlanan nöbetçi hekim dizüstü bilgisayarlarıydı. Saldırganlar bir hekimin şifresiz ve EDR'ı devre dışı kalmış dizüstü bilgisayarına uzaktan sızdı, oradan ağa yayılarak tüm hasta veri tabanını şifreledi. Şirket CEO'su yönetim kuruluna "Hani skorumuz %94'tü?" diye hesap sorarken siber güvenlik lideri istifa etmek zorunda kaldı. Çünkü risk panosu kritik varlık ağırlıklandırması yapmıyordu.

---

## 2. Soru: Dış Yüklenici (Contractor) ve Uzaktan Çalışan Cihazlarda Güvenlik Duruşu Sapmaları

### Soru
Filo telemetri analizinde Dış Yüklenici (Contractor) veya BYOD uç noktalarının kurumsal iç ağdaki cihazlara kıyasla sistematik olarak daha yüksek risk bandında (HIGH/CRITICAL) çıkmasının mimari nedenleri nelerdir? Sıfır Güven (Zero Trust) mimarisi bu riski izole etmek için risk panosuyla nasıl entegre çalışmalıdır?

### Detaylı ve Kapsamlı Teknik Cevap
Kurumsal ortamlarda üçüncü taraf yükleniciler, danışmanlar ve tedarikçiler siber saldırganların kurumsal iç ağa sızmak için kullandığı en popüler sıçrama tahtasıdır (Supply Chain / Third-Party Compromise - MITRE T1199).

**Sistematik Risk Farkının Nedenleri:**
1. **Merkezi Yönetim (MDM/GPO) Dışı Olma:** Kurumsal cihazlar Active Directory veya Intune üzerinden zorunlu GPO politikalarıyla sıkılaştırılırken, yüklenici cihazları genellikle bağımsızdır.
2. **Yerel Yönetici Yetkisi İstismarı:** Yükleniciler kendi işlerini hızlı yapabilmek için Defender'ı kapatır, lisanssız yazılımlar kurar veya yerel kullanıcı haklarını sonuna kadar açar.
3. **Yama ve EDR Eksikliği:** Şirketin EDR lisansı veya merkezi yama dağıtım mekanizması üçüncü parti cihazlara kurulmadığında, bu cihazlar aylarca yamasız kalır (`days_since_os_patch > 90`).
4. **Şifresiz Diskler ve TPM Yokluğu:** Taşınabilir dizüstü bilgisayarlarda BitLocker açılmaması, kafelerde veya seyahat esnasında donanımın çalınması riskini doğurur.

**Sıfır Güven (Zero Trust) Entegrasyonu:**
Geliştirdiğimiz uç nokta risk panosu, yalnızca pasif bir izleme aracı olarak kalmamalı; **Dinamik Koşullu Erişim (Conditional Access / Network Access Control - NAC)** sistemine sinyal beslemelidir:
* Uç Nokta Risk Motoru cihazı `HIGH` veya `CRITICAL` olarak sınıflandırdığında, bu telemetri anlık olarak API üzerinden VPN Gateway'e veya Identity Provider'a (Entra ID / Okta) iletilir.
* VPN bağlantısı veya hassas verilere (ERP, Finans DB) erişim derhal askıya alınır (`Device Health Attestation Fail`).
* Cihaz karantina VLAN'ına alınarak yalnızca otomatik iyileştirme sunucularıyla (WSUS, EDR Update) görüşmesine izin verilir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Çırağım! Bir kuruma sızmak isteyen usta bir saldırgan asla kurumun çelik kapısını (güçlü Domain Controller'ı) zorlamaz; dışarıdan iş yapan yüklenicinin, temizlik firmasının veya muhasebe danışmanının dizüstü bilgisayarına bakar. Kendi iç ağındaki sunuculara verdiğin önemin iki katını dış yüklenici telemetrisine vereceksin. Risk panosunda kırmızı yanan bir yüklenici cihazı görürsen, tek saniye beklemeden ağ erişimini keseceksin!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
Tarihin en büyük veri ihlallerinden biri olan 2013 Target saldırısında, saldırganlar perakende devinin sistemlerine doğrudan saldırmadı. Şirketin havalandırma ve iklimlendirme (HVAC) işlerini yürüten taşeron firmanın teknisyenine oltalama e-postası gönderildi. Teknisyenin şahsi/şirket dizüstü bilgisayarında kurumsal EDR yoktu ve antivirüs güncellemesi 6 aydır yapılmamıştı. Saldırganlar teknisyenin bilgisayarına Citadel bankacılık truva atını yükledi, oradan Target'ın tedarikçi portalı kimlik bilgilerini çaldı ve iç ağa sızarak 40 milyon kredi kartı bilgisini ele geçirdi. Eğer Target'ın tedarikçi cihazlarının duruşunu denetleyen dinamik bir risk panosu olsaydı, o teknisyenin bilgisayarı daha ilk kapıdan geri çevrilirdi.

---

## 3. Soru: Uç Nokta Duruş Yönetiminde (ESPM) Teşhisten Tedaviye: Kendi Kendini Onaran (Self-Healing) Ağlar

### Soru
Uç nokta risk panosunun ürettiği telemetrinin salt bir raporlama ekranı olmaktan çıkıp otomatik iyileştirme (Auto-Remediation / SOAR) yeteneğiyle "Kendi Kendini Onaran (Self-Healing)" bir ekosisteme dönüştürülmesinde karşılaşılan operasyonel engeller nelerdir ve güvenli bir orkestrasyon hattı nasıl kurulmalıdır?

### Detaylı ve Kapsamlı Teknik Cevap
Güvenlik operasyonlarında en kıymetli kaynak **zamandır (Mean Time to Remediate - MTTR)**. Bir risk tespit edildikten sonra insan analistin bilet (ticket) açması, sistem yöneticisinin o bileti görüp onaylaması ve makineye bağlanıp düzeltmesi ortalama 3 ila 7 gün sürer. Bu süre, saldırganın yanal hareketle etki alanını ele geçirmesi için gereken sürenin (ortalama 84 dakika) onlarca katıdır!

Bu nedenle ESPM motorumuz, teşhis koyduğu an uygun **PowerShell veya Bash düzeltme bloklarını** (`generate_prioritized_remediation_script`) hazırlar.

**Karşılaşılan Operasyonel Engeller:**
1. **İş Kesintisi Korkusu (Fear of Business Disruption):** Sistem yöneticileri otomatik betiklerin meşru servisleri durdurmasından veya sistemi yeniden başlatmaya zorlamasından korkar.
2. **Bağlantı ve Yetki Kısıtları:** Uzaktan çalışan veya VPN'e bağlı olmayan cihazlara `Invoke-Command` (WinRM) veya SSH ile erişmek her zaman mümkün olmayabilir.
3. **Idempotency (Eşgüçlülük) Eksikliği:** Düzeltme betiği zaten açık olan bir servisi yeniden başlatırsa veri tabanı bağlantıları kopabilir.

**Güvenli ve Modern Orkestrasyon Mimarisi:**
Güvenli bir kendi kendini onarma ekosistemi 3 kademeli çalışmalıdır:
* **Kademe 1 (Zero-Impact Auto-Fix):** Sıfır kesinti riski taşıyan ayarlar doğrudan yerel ajan tarafından anında düzeltilir: EDR servisini başlatma (`Start-Service Sense`), kurcalama korumasını açma, imza güncelleme.
* **Kademe 2 (Automated with Notification):** Kullanıcı deneyimini etkileyebilecek ama acil olan ayarlar (BitLocker arka planda başlatma, yetkisiz yerel admin hesabını gruptan çıkarma) otomatik yapılır ve kullanıcıya/yöneticiye bilgilendirme bildirimi gönderilir.
* **Kademe 3 (Reboot Required / Sensitive Assets):** Yeniden başlatma gerektiren (çekirdek yamaları, Credential Guard aktivasyonu) veya kritik üretim veritabanlarında yapılacak müdahaleler için SOAR sistemi otomatik onay talebi oluşturur (Slack/Teams/Jira) ve bakım penceresinde uygulanır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat! Sadece alarm üreten bir sistem, yangını haber verip eline kova almayan itfaiyeciye benzer. Teşhis koyduğun an elinde ilacı hazır olmalıdır. Ürettiğin iyileştirme kodları cerrah neşteri gibi hassas ve idempotent olmalıdır. Bir satır kodla EDR servisini ayağa kaldıramıyorsan, yazdığın raporlar arşivde tozlanmaktan başka işe yaramaz!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2023 yılında uluslararası bir perakende zincirinde siber tehdit aktörleri gece yarısı 02:00'de çalışan bir bakım betiğinin güvenlik açığından yararlanarak 200 mağaza sunucusunda Windows Defender servisini kapattı ve UAC'yi devre dışı bıraktı. Olay esnasında SOC nöbetçisi uyuyordu. Ancak kurumun 15 dakikada bir çalışan otomatik uç nokta duruş denetleyicisi (ESPM motoru), 200 sunucuda birden EDR ve UAC sapması algıladı. Sistem insan onayını beklemeden hazırladığı otomatik iyileştirme modülünü tetikledi: EDR servislerini yeniden başlattı, UAC'yi `EnableLUA=1` yaptı ve bu komutları yürüten şüpheli sürecin PID'sini sonlandırıp ağ arabirimini geçici karantinaya aldı. Sabah 08:00'de işe gelen güvenlik ekibi, gece büyük bir fidye saldırısının kendi kendini onaran sistem tarafından sıfır insan müdahalesiyle tamamen bertaraf edildiğini loglardan hayretle okudu.
