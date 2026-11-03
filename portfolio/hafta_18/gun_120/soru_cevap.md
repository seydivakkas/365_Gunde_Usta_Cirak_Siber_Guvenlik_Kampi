# GÜN 120: STRIDE Tehdit Modellemesi Soru - Cevap Dokümanı

## SORU 1: STRIDE Metodolojisinde Güven Sınırları (Trust Boundaries) Neden Tehdit Analizinin En Kritik Odak Noktasıdır?

### 1. Soru Başlığı ve Tanımı
Bir Veri Akış Diyagramında (DFD) iki bileşen arasındaki güven sınırı geçişi (Trust Boundary Crossing) neden tehdit modellemesinin birincil analiz noktasıdır ve bu sınırın ihlali hangi güvenlik açıklarını tetikler?

### 2. Derinlemesine Teknik Analiz
Güven sınırı (Trust Boundary), bir sistem içerisindeki farklı yetki, ayrıcalık ve güvenlik seviyelerine sahip bölgeleri (zones) birbirinden ayıran mantıksal veya fiziksel sınırdır. Örneğin, genel internet ile DMZ (Demilitarized Zone), veya DMZ'deki bir API Gateway ile arka uçtaki çekirdek veri tabanı bölgesi (Internal Secure Subnet) arasında farklı güven seviyeleri bulunur.

Bir veri akışı (Data Flow) bu sınırı aştığında şu temel riskler doğar:
1. **Güven Varsayımının Çöküşü (Implicit Trust Breakdown):** Düşük güven bölgesinden (Untrusted Zone) yüksek güven bölgesine (Trusted Zone) giren her veri potansiyel olarak zehirlidir (CWE-20: Improper Input Validation).
2. **Kimlik Doğrulama ve Yetkilendirme Ayrışması:** Sınırı geçen aktörün gerçekten iddia ettiği kişi olup olmadığı (Spoofing) ve o bölgedeki kaynaklara erişim yetkisinin bulunup bulunmadığı (Elevation of Privilege) sınırda doğrulanmalıdır.
3. **Kanal Güvenliği İhlali:** Güven sınırı üzerinden akan verinin şifrelenmemesi durumunda ortadaki adam (MitM) saldırıları ile veri dinlenebilir (Information Disclosure - CWE-319) veya manipüle edilebilir (Tampering - CWE-353).

DFD analizinde sınır geçişi tespit edildiğinde; veri akışına otomatik olarak mTLS (mutual TLS), HMAC bütünlük kontrolü ve sınırda giriş doğrulaması zorunluluğu atanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret platformunda, DMZ'de bulunan Frontend Web Sunucusu, dahili ağda bulunan Ödeme İşleme Servisine HTTP REST üzerinden çağrı yapmaktadır. Geliştiriciler "DMZ ve iç ağ zaten şirket içinde, güvenlidir" varsayımıyla mTLS kullanmamış ve token doğrulaması koymamıştır. Bir saldırgan web sunucusundaki SSRF (Server-Side Request Forgery) zafiyetini sömürerek doğrudan ödeme servisine sahte para transferi istekleri göndermiş ve güven sınırını aşmıştır.

**Pratik Çözüm:**
1. **Mimari Düzenleme:** DMZ ile Core Payment Zone arasına açık bir Trust Boundary tanımlanır.
2. **mTLS Zorunluluğu:** Servisler arası iletişimde karşılıklı sertifika doğrulaması (mTLS - x509) devreye alınır; harici ve sahte süreçlerin doğrudan porta istek atması engellenir.
3. **Sıkı Giriş Şeması Doğrulaması:** Ödeme servisi, gelen JSON yükünü JSON Schema ile katı doğrulamadan geçirir ve istek başlığındaki kısa ömürlü imzalı JWT'yi doğrular.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, asla 'iç ağ güvenlidir' yalanına inanma! Zero Trust çağında her bileşen potansiyel olarak ele geçirilmiş kabul edilir. Mimari diyagram çizerken güven sınırlarını kalın kırmızı kalemle çiz. Bir çizgi bir kutudan diğerine geçerken kırmızı çizgiyi kesiyorsa, o çizginin üzerine hemen şu üçlüyü yaz: 'Kimlik Doğrulaması Yapıldı mı?', 'Veri Şifrelendi mi?', 'Girdi Sanitizasyonu Var mı?' Bu üç soru seni kariyerin boyunca yüzlerce felaketten kurtarır."

---

## SORU 2: STRIDE Eşleme Matrisinde Neden External Entity Bileşenine Yalnızca 'Spoofing' ve 'Repudiation' Tehditleri Uygulanır?

### 1. Soru Başlığı ve Tanımı
Veri Akış Diyagramı (DFD) standartlarında, bir Dış Varlık (External Entity) neden Tampering (Tahrifat), Information Disclosure (Bilgi İfşası), Denial of Service (Hizmet Engelleme) veya Elevation of Privilege (Yetki Yükseltme) tehditlerine doğrudan hedef olamaz; yalnızca Spoofing ve Repudiation kapsamında değerlendirilir?

### 2. Derinlemesine Teknik Analiz
Tehdit modellemenin temel prensiplerinden biri **Sistem Kapsamı ve Kontrol Edilebilirlik (Scope of Control)** ilkesidir:
1. **Dış Varlıkların Doğası:** Dış varlıklar (kullanıcılar, tarayıcılar, harici partner API'leri), tasarladığımız ve kontrol ettiğimiz sistem sınırlarının dışındadır. Biz onların bellek alanını, yerel veri tabanını veya sunucu kaynaklarını yönetemeyiz.
2. **Tehditlerin Hedefi vs. Kaynağı:**
   - Bir kullanıcı kendi bilgisayarındaki veriyi değiştirebilir (Tampering), ancak bu bizim sistemimizin tahrif edildiği anlamına gelmez; bizim açımızdan o kullanıcı sisteme sahte kimlikle veri gönderiyorsa bu **Spoofing**, veri akışı üzerinde değişiklik oluyorsa akış üzerinde **Tampering**'dir.
   - Dış varlığın sistem kaynakları tükense bile (örneğin kullanıcının bilgisayarı kilitlense), bu bizim sistemimiz için bir **Denial of Service** değildir; bizim sistemimiz ayaktadır.
   - Dış varlık kendi yerelinde yetki yükseltemez; sistemimize yetkisiz sızmaya çalıştığında yetki yükseltme tehdidi sisteme hizmet veren **Process (Süreç)** bileşeninde gerçekleşir (CWE-250 / CWE-285).
3. **Geçerli İki Tehdit:**
   - **Spoofing (Kimlik Sahteciliği):** Dış varlık sisteme bağlanırken başka bir kullanıcının kimliğini taklit edebilir.
   - **Repudiation (İnkar Edilebilirlik):** Dış varlık bir emir, para transferi veya işlem talimatı gönderdikten sonra "Bu işlemi ben yapmadım" diyerek inkar edebilir.

Dolayısıyla DFD-STRIDE matrisinde harici varlıklar için yalnızca Kimlik Doğrulama (Authentication) ve İnkar Edilemezlik (Non-Repudiation) odaklı kontroller modellenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir banka mobil şube uygulamasında, bir müşteri EFT işlemi yaptıktan sonra hesabından çekilen paranın kendisi tarafından gönderilmediğini, telefonunun çalındığını ve bankanın parayı iade etmesi gerektiğini iddia eder (Repudiation). Banka loglarında sadece IP adresi tutulmuş, SMS doğrulama kodu ise zaman damgasıyla kriptografik olarak imzalanmamıştır. Banka hukuki süreçte işlemi müşterinin yaptığını ispatlayamaz.

**Pratik Çözüm:**
1. **Dijital İmza ve Cihaz Eşleme:** Müşteri cihazındaki güvenli alanda (Secure Enclave / TPM) üretilen asimetrik anahtar çifti ile kritik işlemler imzalanır.
2. **Kriptografik İnkar Edilemezlik (Non-Repudiation):** İşlem özeti (transaction payload hash), istemci özel anahtarı ve sunucu zaman damgasıyla birleştirilerek WORM (Write Once Read Many) uyumlu denetim kütüğüne kaydedilir.
3. **Müşteri Uyuşmazlık Çözümü:** İmzalı işlem kaydı bağımsız denetçilere sunularak Repudiation riski kesin olarak bertaraf edilir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, tehdit modellerken sınırlarını bilmek zafiyeti bilmek kadar kıymetlidir. Kontrol edemediğin alanın güvenliğini vaat edemezsin. Bir kullanıcının makinesine sızılmasını engelleyemezsin ama o kullanıcının senin sistemine bağlanırken kimliğini ispatlamasını ve yaptığı işlemi inkar edememesini garanti altına alabilirsin. Tehdit modelleme yaparken hedefin dünyayı kurtarmak değil, kendi sistem sınırlarını zırhla kaplamaktır."

---

## SORU 3: Tehditleri DREAD Yöntemiyle Puanlarken 'Discoverability' (Keşfedilebilirlik) Kriteri Güvenlikte Neden Tartışmalıdır ve Modern Uygulamalarda Nasıl Ele Alınır?

### 1. Soru Başlığı ve Tanımı
DREAD risk derecelendirme metodolojisinde yer alan "Discoverability" (Keşfedilebilirlik) puanı neden "Security through Obscurity" (Gizlilik yoluyla güvenlik) yanılgısına yol açabilir ve modern güvenlik ekipleri bu metriği nasıl yorumlamalıdır?

### 2. Derinlemesine Teknik Analiz
DREAD skorunda Discoverability parametresi, bir saldırganın ilgili güvenlik açığını keşfetmesinin ne kadar kolay olduğunu (1: Neredeyse imkansız, kaynak kodu ve tersine mühendislik gerektirir; 10: Kamuoyu tarafından bilinen açık bir URL veya arayüz) puanlar.

Bu parametrenin tartışmalı olmasının temel sebepleri:
1. **Kerckhoffs Prensibi ve Obscurity Yanılgısı:** Güvenlik bilimi der ki; bir sistemin güvenliği sistemin çalışma mantığının gizli kalmasına değil, anahtarın gizliliğine dayanmalıdır. Geliştiriciler "Bu API uç noktasını kimse bilemez, dokümante etmedik" diyerek Discoverability puanını 1 veya 2 verirler. Bu, yapay bir rehavet yaratır ve toplam DREAD skorunu aşağı çeker!
2. **Otomasyon ve Shodan/Fuzzing Gerçeği:** Günümüz tehdit aktörleri Shodan, Censys, nmap, ffuf ve yapay zeka destekli crawler'lar ile interneti saniyeler içinde taramaktadır. Gizli sanılan bir parametre dakikalar içinde ortaya çıkar.
3. **Modern Yaklaşım (Worst-Case Discovery):** Microsoft ve çağdaş tehdit modelleme uzmanları, çoğu senaryoda Discoverability puanını varsayılan olarak **10 (En yüksek)** kabul etmeyi önerir. Çünkü zafiyet varsa, eninde sonunda bulunacaktır. Risk puanı keşfedilme zorluğuna değil; hasarın büyüklüğüne (Damage) ve istismar kolaylığına (Exploitability) odaklanmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kurum, yönetim paneline erişim sağlayan `/internal-admin-debug-panel/` yolunu internete açık bırakmış ancak ana sayfada link vermemiştir. Tehdit modelleme ekibi Discoverability'yi 2 olarak puanlamış, DREAD skoru 5.2 (Orta risk) çıktığı için düzeltme sprintini 6 ay sonraya atmıştır. İki gün sonra bir saldırgan brute-force dizin taraması (directory fuzzing) ile bu yolu 45 saniyede tespit etmiş ve admin paneline erişerek verileri sızdırmıştır.

**Pratik Çözüm:**
1. **Varsayılan Yüksek Keşfedilebilirlik Kuralı:** Tehdit modelleme motorumuzda harici internete maruz kalan veri akışlarında `Discoverability` varsayılan olarak en az 8-10 kabul edilir.
2. **Kritik Eşik Kontrolü:** Sadece "gizli" olduğu için skoru düşürülen tehditlerin üretime çıkışı engellenir (CWE-1025).
3. **Mimari Sertleştirme:** Yönetim paneli internete tamamen kapatılır, yalnızca kurumsal VPN ve Zero Trust Network Access (ZTNA) arkasından erişilebilir hale getirilir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kapının anahtarını paspasın altına saklayıp 'kimse paspasın altına bakmayı akıl edemez' diyemezsin! Hırsızın ilk baktığı yer paspasın altıdır. Siber güvenlikte gizliliğe güvenmek en büyük ahmaklıktır. Bir açığın keşfedilmesinin zor olduğunu düşünüyorsan, bil ki henüz yeterince meraklı bir hacker ile karşılaşmamışsındır. Discoverability puanını her zaman yüksek tut; böylece sistemini lafla değil, çelikten zırhla korursun."
