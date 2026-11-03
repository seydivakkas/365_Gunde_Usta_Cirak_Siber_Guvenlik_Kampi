# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 100: Soru-Cevap — Kriptografide Entropi ve Rastgelelik

---

## Soru 1: Python'ın yerleşik `random` modülü (Mersenne Twister MT19937) parola sıfırlama token'ı veya kriptografik anahtar üretiminde neden kesinlikle kullanılamaz?

### 1. Soru Başlığı ve Tanımı
Mersenne Twister PRNG algoritmasının dahili durum yapısı (internal state), doğrusal tersine mühendislik (linear state recovery) ve CWE-338 zafiyeti.

### 2. Derinlemesine Teknik Analiz
Mersenne Twister (MT19937), simülasyon ve oyunlar için tasarlanmış yüksek performanslı bir Sözde Rastgele Sayı Üretecidir (PRNG). $2^{19937}-1$ periyoda sahip olmasına rağmen kriptografik bir algoritma değildir.

MT19937, 624 adet 32-bitlik tamsayıdan oluşan bir durum dizisi (state array) tutar:
$$\mathbf{S} = [s_0, s_1, \dots, s_{623}]$$
Üretilen her rastgele sayı, bu durum dizisindeki bir elemanın "tempering" (bit kaydırma ve XOR) işlemlerinden geçirilmesiyle elde edilir. Bu tempering fonksiyonu birebir ve tersine çevrilebilir (bijective) bir doğrusal işlemdir.

Bir saldırgan sistemden ardışık olarak **624 adet çıktı** topladığında (örneğin art arda 624 kez parola sıfırlama talebinde bulunarak üretilen token'ları gözlemlediğinde), her bir çıktıyı ters tempering matrisiyle işleyerek MT19937'nin 624 durum elemanının tamamını elde eder. Dahili durum ele geçirildikten sonra, saldırgan gelecekte herhangi bir kullanıcı için üretilecek tüm parola sıfırlama token'larını, oturum kimliklerini veya doğrulama kodlarını %100 kesinlikle önceden hesaplar!

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesi, kullanıcıların e-postalarına giden şifre sıfırlama linklerini `hex(random.getrandbits(128))` ile oluşturmaktadır. Bir saldırgan 624 adet sahte hesap açarak şifre sıfırlama token'ı talep etmiş, gelen değerlerden sunucunun `random` durumunu kopyalamış ve hemen ardından hedeflediği şirket yöneticisinin e-postasına şifre sıfırlama isteği göndermiştir. Saldırgan, yöneticiye giden token'ı sunucuya gitmeden kendi bilgisayarında üretip hesabı ele geçirmiştir.

**Çözüm:** Parola, token ve anahtar üretiminde `random` tamamen yasaklanır. Yalnızca işletim sisteminin kriptografik entropi havuzunu kullanan `secrets` modülü (`secrets.token_hex(32)`) veya `os.urandom(32)` kullanılmalıdır. `CSPRNGGenerator.inspect_generator()` motoru zayıf PRNG kullanımını AST seviyesinde yakalar.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, `random` modülü kumarhane zarı gibidir; hilesini bilen için geleceği görmek çocuk oyuncağıdır. Kriptografide asla zar atılmaz; işletim sisteminin kaosundan, kuantum seviyesindeki donanım gürültüsünden beslenen `secrets` kullanılır!

---

## Soru 2: Bir şifreleme anahtarının veya parolanın Shannon Entropisinin yüksek olması tek başına kırılması imkansız olduğu anlamına gelir mi?

### 1. Soru Başlığı ve Tanımı
Shannon Entropisi ($H$) ile Arama Uzayı (Search Space / Key Space - CWE-334) arasındaki fark, Min-Entropi ($H_\infty$) ve sözlük saldırısı direnci.

### 2. Derinlemesine Teknik Analiz
Shannon Entropisi, bir dizideki baytların dağılımının ne kadar tekdüze (uniform) olduğunu ölçer; dizinin uzunluğunu veya anahtar uzayının büyüklüğünü tek başına garanti etmez!

Örneğin:
1. **Küçük Uzay Zafiyeti (CWE-334):** 2 baytlık (16-bit) tamamen rastgele üretilmiş bir anahtar ele alalım. Bu iki baytın Shannon entropisi mükemmel şekilde $8.0 \text{ bit/bayt}$ çıkabilir. Ancak toplam arama uzayı yalnızca $2^{16} = 65.536$ olasılıktır! Modern bir GPU bu arama uzayını 1 milisaniyede tüketir.
2. **Min-Entropi Farkı (Worst-Case):** Eğer bir parola formatında ilk 8 karakter rastgele ama son 8 karakter her zaman sabit bir kalıp içeriyorsa, Shannon entropisi ortalamada yüksek görünebilir. Ancak saldırgan sabit kısımları bildiği için etkin arama uzayını dramatik şekilde daraltır.
3. **Kombinatoryal Entropi (Parolalar İçin):** Parolalarda bayt entropisi yerine kombinatoryal entropi hesabı yapılır:
   $$E = L \times \log_2(R)$$
   Burada $L$ parolanın uzunluğu, $R$ ise karakter havuzunun büyüklüğüdür (örneğin küçük, büyük harf, rakam ve sembol için $R=94$).

Dolayısıyla yüksek güvenlik için iki koşul birlikte sağlanmalıdır:
- Yüksek bayt entropisi ($H(X) \ge 7.5 \text{ bit/bayt}$)
- Yeterli anahtar uzayı (En az 128 bit, tavsiye edilen 256 bit / 32 bayt).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finansal yazılım, API anahtarlarını üretirken `os.urandom(4)` kullanarak 32-bitlik anahtarlar üretmiştir. Yapılan testlerde bayt başına Shannon entropisi 7.8 bit çıkmış ve raporlar "Yüksek Entropi" demiştir. Ancak sistem canlıya çıktığında saldırganlar 4 milyar olasılığı ($2^{32}$) 10 dakikada tarayarak (brute-force) şirket API anahtarını kırmıştır.

**Çözüm:** `CSPRNGGenerator.generate_key(bits=256)` fonksiyonunda katı minimum sınır (`MIN_KEY_BITS = 64`) konulmuştur. 64-bitin altında anahtar talep edildiğinde sistem `SmallEntropySpaceError` (CWE-334) fırlatarak işlemi engeller.

### 4. Ustanın Çırağa Tavsiyesi
Çırağım, küçük bir odadaki hava ne kadar türbülanslı olursa olsun, oda küçüktür! Entropi havanın karışıklığıdır, anahtar uzunluğu ise odanın büyüklüğüdür. Güvenlik için hem fırtına gibi rastgelelik, hem de uçsuz bucaksız bir evren büyüklüğünde anahtar uzayı gerekir!

---

## Soru 3: Debian OpenSSL Zafiyeti (CVE-2008-0166) siber güvenlik tarihine neden en büyük rastgelelik felaketi olarak geçmiştir ve tohumlama (seeding) mimarisi nasıl kurulmalıdır?

### 1. Soru Başlığı ve Tanımı
Tohumlama (seeding) kaynaklarının çöküşü (CWE-337 / CWE-331), deterministik anahtar havuzu ve CSPRNG tohumlama standartları (NIST SP 800-90A).

### 2. Derinlemesine Teknik Analiz
Kriptografik bir PRNG (CSPRNG), bir tohum (seed) değeri ile başlar ve ardından kriptografik olarak güvenli sözde rastgele sayılar üretir. Eğer tohum yeterli entropiye sahipse ve gizliyse, üretilen sayılar tahmin edilemez.

2008 yılındaki Debian OpenSSL krizinde:
1. Geliştirici, OpenSSL'in entropi ekleyen `MD_Update` fonksiyonunu kaldırdı.
2. OpenSSL'in entropi havuzu boş kaldı ve tohum olarak geriye **yalnızca işletim sisteminin o anki Süreç Kimliği (PID)** kaldı.
3. Linux'ta `pid_max` varsayılan olarak $32.768$'dir.
4. Sonuç olarak, Debian ve Ubuntu sistemlerde üretilen tüm SSH sunucu anahtarları, SSL sertifikaları ve VPN anahtarları **yalnızca 32.768 farklı olasılıktan biri** haline geldi!
5. Saldırganlar tüm anahtarları önceden hesaplayıp bir gökkuşağı tablosu (rainbow table) oluşturdular. Bir Debian sunucusuna SSH bağlantısı açıldığında, sunucunun sunduğu genel anahtarın hangi PID ile üretildiği 1 saniyede bulundu ve eşleşen özel anahtarla parola girmeden sunucuya root olundu.

**Doğru Tohumlama İlkeleri:**
- Tohum ASLA `time.time()`, `PID`, `MAC adresi` gibi tahmin edilebilir kaynaklardan tek başına alınamaz (CWE-337).
- Tohumlama doğrudan donanım gürültüsü (`/dev/urandom`, `RDRAND`, TPM, jitter) içeren işletim sistemi entropi havuzundan çekilmelidir.
- NIST SP 800-90A uyarınca, CSPRNG periyodik olarak yeniden tohumlanmalı (reseeding) ve geçmiş/gelecek gizliliği (forward/backward secrecy) korunmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir IoT cihazı, fabrika çıkışında ilk kez açıldığında donanımsal saat pili olmadığı için her zaman `1970-01-01 00:00:00` zamanıyla başlamaktadır. Cihaz ilk açılışta cihaz özel anahtarını üretirken sistem zamanını tohum olarak kullanmıştır. Sonuç olarak aynı fabrikadan çıkan 500.000 akıllı kameranın tamamı aynı özel anahtarla üretilmiştir.

**Çözüm:** `CSPRNGGenerator.inspect_generator()` motoru `seed_type == "SYSTEM_TIMESTAMP"` durumunu tespit ettiği an `PredictableSeedError` fırlatır. Cihazlar internete çıkmadan veya donanımsal ADC/termal gürültü toplamadan anahtar üretemez.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, tohum zehirliyse meyve de zehirlidir. Tohumun ne kadar tahmin edilebilirse, anahtarın o kadar kırılgandır. Asla saatin tik taklarına güvenip kriptografik tohum atma; doğanın kontrol edilemeyen gürültüsüne sığın!
