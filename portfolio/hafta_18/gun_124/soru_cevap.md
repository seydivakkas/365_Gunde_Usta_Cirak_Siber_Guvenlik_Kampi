# GÜN 124: Secrets Yönetimi ve Çevre Değişkenleri Soru - Cevap Dokümanı

## SORU 1: 12-Faktör Uygulama (The Twelve-Factor App) İlkelerinde Çevre Değişkenleri (.env) Önerilmesine Rağmen, Modern Kurumsal Mimarilerde Neden Yetersiz Kalır ve Secret Vault İhtiyacı Doğar?

### 1. Soru Başlığı ve Tanımı
Geliştiricilerin sıkça başvurduğu çevre değişkenleri (`os.environ` / `.env` dosyaları) neden büyük ölçekli ve yüksek güvenlikli sistemlerde kritik riskler barındırır; HashiCorp Vault veya Cloud Secret Manager gibi kasalara neden geçilmelidir?

### 2. Derinlemesine Teknik Analiz
12-Faktör metodolojisi konfigürasyonun koddan ayrılmasını (III. Config) önerir ve çevre değişkenlerini adresler. Bu pratik koda hardcoded yazmaktan çok daha iyidir ancak şu ciddi güvenlik zaafiyetlerini beraberinde getirir:
1. **İşletim Sistemi Seviyesinde Sızıntı (Procfs Exposure):** Linux çekirdeğinde her sürecin çevre değişkenleri `/proc/<PID>/environ` altında düz metin olarak tutulur. Aynı sunucuda yerel yetki yükselten (LPE) bir saldırgan veya yan süreç bu dosyayı okuyarak tüm veritabanı şifrelerini çalar.
2. **Konteyner ve CI/CD İzolasyon Eksikliği:** Kubernetes veya Docker ortamlarında `docker inspect <container_id>` veya `kubectl describe pod` komutları çalışan bir konteynerin tüm çevre değişkenlerini konsola döker.
3. **Alt Süreç Kalıtımı (Child Process Inheritance):** Uygulama `subprocess.Popen` veya `os.system` ile bir harici betik çalıştırdığında, ana sürecin tüm çevre değişkenleri istemeden bu alt sürece miras kalır.
4. **Çökme ve Hata Kayıtları (CWE-532):** Uygulama hata verdiğinde stack trace dökümünde veya bellek dump'ında çevre değişkenleri doğrudan günlüklere sızar.
5. **Dinamik Rotasyon Eksikliği:** Çevre değişkenini değiştirdiğinizde süreci yeniden başlatmanız (restart) gerekir; bu da üretim ortamında kesinti riski yaratır.

**Secret Vault Çözümü:**
Kasa mimarisinde anahtarlar ortamda açık durmaz; uygulama açıldığında mTLS veya AppRole ile kasaya bağlanır, kısa ömürlü (ephemeral) ve dinamik olarak kiralanmış (leased) anahtarı belleğe çeker. Süresi dolunca otomatik yenilenir; diskte veya `environ` içinde hiçbir kalıntı bırakmaz.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir SaaS firması, AWS RDS PostgreSQL şifresini Dockerfile içerisine `ENV DB_PASSWORD=my_prod_secret` olarak tanımlamıştır. Docker imajı şirket içi açık Docker Registry'ye yüklenmiştir. Şirketten ayrılan bir stajyer, imajı indirip `docker history` ve `docker inspect` komutlarıyla ana veritabanı şifresini elde etmiş ve müşteri veritabanını dışarı sızdırmıştır.

**Pratik Çözüm:**
1. **İmaj Temizliği:** Dockerfile ve imaj katmanlarındaki tüm `ENV` ve `ARG` secret tanımları kaldırılır.
2. **Vault Entegrasyonu:** Uygulama `SecretVaultManager` motoruna entegre edilir. Uygulama ayağa kalkarken `vault.get_secret("SEC-PROD-DB-01", requester_role="backend_prod_service")` çağrısıyla şifreyi geçici olarak belleğe alır.
3. **Log Sanitizasyonu:** Kasa motorunun `mask_log_message` filtresi log çıktısına eklenerek olası hata anlarında şifrenin maskelenmesi garanti edilir (CWE-532).

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, çevre değişkenleri bir evin kapı anahtarını paspasın altına koymak gibidir; kodun içine koymaktan iyidir ama hırsızın ilk baktığı yer yine orasıdır! Gerçek bir mühendis anahtarı kapının arkasında bırakmaz; onu banka kasasında (Vault) saklar, ihtiyacı olduğunda kasadan alır, işi bitince geri bırakır."

---

## SORU 2: CI/CD Boru Hatlarında Sabit Kodlanmış Gizli Anahtarları (CWE-798) Tespit Ederken Neden Yalnızca Regex Yetersizdir ve Shannon Entropisi Nasıl Çalışır?

### 1. Soru Başlığı ve Tanımı
Statik kod analizi (SAST) ve git commit taramalarında yalnızca düzenli ifadeler (Regex) kullanmanın kısıtları nelerdir; Shannon Entropisi formülü bilinmeyen veya özel üretim anahtarları nasıl başarıyla yakalar?

### 2. Derinlemesine Teknik Analiz
Statik secret tespitinde iki temel okul vardır:
1. **İmza / Regex Tabanlı Tarama:**
   - AWS (`AKIA...`), GitHub (`ghp_...`), Stripe (`sk_live_...`), Slack (`xoxb-...`) gibi standart öneklere sahip anahtarları %100 doğrulukla yakalar.
   - *Dezavantajı:* Özel bir HMAC anahtarını, şirket içi JWT imza sırrını veya rasgele üretilmiş 32 byte'lık bir veritabanı parolasını (`a8f9c2d1e0b3...`) regex ile yakalayamazsınız; çünkü bilinen bir öneki yoktur!
2. **Shannon Entropisi (Bilgi Yoğunluğu Analizi):**
   1948 yılında Claude Shannon tarafından geliştirilen bu formül, bir metindeki karakterlerin rastgelelik ve belirsizlik derecesini ölçer:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   - Doğal dillerde (İngilizce/Türkçe kod yorumları, değişken isimleri örn: `user_authentication_handler`), karakterler belirli sıklıklarla tekrarlanır; entropi genellikle **2.5 ile 3.5** arasındadır.
   - Ancak kriptografik olarak üretilmiş bir parola veya base64/hex token'da (`k9#vL2$mP8@zX4!qN7%yR1^wT5*`), her karakter neredeyse eşit olasılıkla yer alır ve bilgi yoğunluğu tavan yapar; entropi **4.2 - 5.5** aralığına fırlar!
3. **Bileşik Tarayıcı Mimarisi:**
   Motorumuz `SecretScanner`:
   - Önce bilinen imzaları regex ile arar (hızlı ve sıfır yanlış pozitif).
   - Ardından tırnak içindeki tüm 16+ karakterlik dizgilerin Shannon entropisini hesaplar. Eşik değeri (4.2) aşan dizgileri "Yüksek Entropili Şüpheli Anahtar" olarak işaretler ve derlemeyi durdurur (CWE-798 koruması).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir geliştirici, özel bir ödeme entegrasyonu için kendi ürettiği 64 karakterlik rastgele hex anahtarını kodun içine `ENC_KEY = "3a7b9c1d8e4f5a2b6c0d1e3f5a7b9c1d8e4f5a2b6c0d1e3f5a7b9c1d8e4f5a2b"` olarak yazmıştır. Şirketin kullandığı geleneksel regex tarayıcısı hiçbir bilinen önek (AWS/GitHub) görmediği için testi geçirmiştir. Kod açık kaynak repoya atılınca saldırganlar anahtarı çözüp ödeme verilerini tahrif etmiştir.

**Pratik Çözüm:**
1. **Entropi Motorunun Entegrasyonu:** Pre-commit hook ve CI/CD pipeline'ına `secrets_cli.py scan --entropy 4.2 --enforce` adımı eklenir.
2. **Otomatik Bloklama:** Bu dizginin Shannon entropisi 4.38 çıktığı için tarayıcı commit işlemini anında reddeder ve geliştiriciyi uyarır.
3. **Kasa Taşınması:** Anahtar repodan silinir (git history rebase edilir) ve merkezi kasaya `SEC-PAY-ENC` adıyla kaydedilir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kalabalık bir caddede hırsızı sadece üzerinde 'Ben Hırsızım' yazan bir tişört arayarak bulamazsın! Bu regex'tir. Gerçek güvenlik uzmanı, kalabalığın yürüyüş temposuna, hareketlerinin doğallığına bakar. Yüksek entropi, kodun içindeki o olağandışı gerginliktir; normal bir kelime gibi görünmeyen her yüksek entropili dizgi potansiyel bir dinamit lokumudur!"

---

## SORU 3: Zarflı Şifreleme (Envelope Encryption) Nedir ve Kasa Depolamasında Neden Tek Bir Anahtara Güvenilmez?

### 1. Soru Başlığı ve Tanımı
Kurumsal Secrets kasalarında (AWS KMS, HashiCorp Vault) kullanılan "Zarflı Şifreleme" (Envelope Encryption) mimarisi nasıl çalışır ve Ana Şifreleme Anahtarı (Master Key / KEK) ile Veri Şifreleme Anahtarı (DEK) arasındaki iş bölümü neden hayati bir gerekliliktir?

### 2. Derinlemesine Teknik Analiz
Tek bir anahtarla tüm sistemi şifrelemek (Symmetric Single-Key) şu riskleri doğurur:
- Tek bir anahtar çalınırsa tüm şirketin geçmiş ve gelecek tüm verileri açılır.
- Anahtarı değiştirmek (rotation) istediğinizde, yüzbinlerce veritabanı kaydını ve dosyasını tek tek çözüp yeni anahtarla yeniden şifrelemeniz gerekir; bu işlem günlerce sürebilir ve sistemi kilitler!

**Zarflı Şifreleme Mekanizması:**
1. **İki Aşamalı Anahtar Hiyerarşisi:**
   - **Veri Şifreleme Anahtarı (Data Encryption Key - DEK):** Her bir secret veya veri kaydı için `secrets.token_bytes(32)` ile üretilen benzersiz tekil anahtardır. Asıl veri bu DEK ile şifrelenir.
   - **Ana Anahtar / Anahtar Şifreleme Anahtarı (Key Encryption Key - KEK / Master Key):** HSM (Hardware Security Module) veya güvenli kasa çekirdeğinde saklanan kök anahtardır. Asla kasadan dışarı çıkmaz.
2. **Şifreleme Süreci (Zarflama):**
   - Kasa, gizli veriyi DEK ile şifreler.
   - Ardından DEK'in kendisi Master Key ile şifrelenir.
   - Şifrelenmiş veri ve şifrelenmiş DEK yan yana aynı "zarf" (payload) içinde diske kaydedilir.
3. **Mükemmel Rotasyon Avantajı (Key Rotation Efficiency):**
   Master Key'in rotasyon zamanı geldiğinde devasa verileri yeniden şifrelemeye gerek yoktur! Yalnızca şifreli DEK'ler çözülüp yeni Master Key ile tekrar kilitlenir. Verilere dokunulmadığı için rotasyon milisaniyeler içinde tamamlanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** 50 milyon müşteri kaydı tutan bir bankacılık altyapısında, güvenlik standardı (PCI-DSS) gereği anahtarların her yıl yenilenmesi zorunludur. Eski mimaride tek anahtar kullanıldığı için rotasyon işlemi veri tabanını 36 saat boyunca kitlemekteydi.

**Pratik Çözüm:**
1. **Zarflı Şifreleme Entegrasyonu:** `CryptoVaultHelper` sınıfındaki `derive_key` ve tuz/nonce zarflama yapısı devreye alınır.
2. **Hızlı Rotasyon:** Master Key yenilendiğinde yalnızca zarfların mühürleri güncellenir; ana veritabanı kesintisiz hizmet vermeye devam eder.
3. **Bütünlük Koruması:** Her zarf HMAC-SHA256 ile imzalanarak tahrifat (tampering) saldırılarına karşı korunur.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, sarayın tüm hazine odalarını tek bir anahtarla kilitlersen, o anahtarı kaybeden vezir tüm krallığı batırır! Her odanın kendine ait küçük bir anahtarı olmalı, o küçük anahtarlar ise yalnızca padişahın belindeki anahtarla açılan altın bir çekmecede saklanmalıdır. Zarflı şifreleme işte bu krallık düzenidir."
