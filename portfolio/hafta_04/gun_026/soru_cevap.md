# GÜN 026: Soru Bankası ve Çözüm Rehberi (PATH ve Ortam Değişkenleri)

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## SENARYO 1 (G026-SC1): PATH ve Ortam Değişkenleri Temel Mekanizması ve Güvenlik Önemi

### 1. Soru Metni ve Açıklaması
**Soru:** PATH ve ortam değişkenleri: Temel mekanizmayı ve güvenlik önemini açıkla. (PATH, çalıştırılabilir komutların nerede arandığını etkiler; güvenilmeyen dizinlerin önceliği risk doğurabilir.)

**Açıklama:** İşletim sisteminde bir komut mutlak yolu belirtilmeden çağrıldığında kabuk, komutu bulmak için `$PATH` ortam değişkenindeki dizinleri sırayla tarar. Bu soruda arama sırasının mekaniği, güvenilmeyen dizinlerin (`.`, `/tmp`) listenin başında veya içinde bulunmasının doğurduğu ikili gölgeleme (Binary Hijacking) ve yetki yükseltme tehditleri incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap

1. **Arama ve Çözümleme Mekanizması:**
   - `$PATH`, iki nokta üst üste (`:`) veya Windows ortamında noktalı virgül (`;`) ile ayrılmış bir dizin listesidir.
   - Kullanıcı `cat dosya.txt` yazdığında kabuk bu komutu sırasıyla dizinlerde arar:
     `Dizin 1` -> `Dizin 2` -> `Dizin 3` ...
   - İlk eşleşen çalıştırılabilir dosya çekirdeğe gönderilir ve arama durur.
   - Çözümleme sırası her zaman **soldan sağa (left-to-right)** işler.

2. **Güvenilmeyen Dizinlerin Önceliği ve Güvenlik Riski:**
   - **Mevcut Dizin (Current Working Directory - `.`):** Eğer `PATH` dizesinde `.` veya boş bir ayraç (`::`) yer alıyorsa, kabuk komutu ilk olarak kullanıcının o an bulunduğu dizinde arar.
   - **İkili Gölgeleme (Binary Hijacking / Trojan):** Saldırgan, sistem yöneticisinin sıkça girdiği bir klasöre (örn: `/tmp`, paylaşımlı ağ dizini veya ortak Git deposu) `ls`, `grep` veya `sudo` adında zararlı bir betik bırakır. Yönetici bu dizine girip `ls` çalıştırdığında gerçek `/usr/bin/ls` yerine saldırganın betiği çalışır.
   - **Yetki Yükseltme (Privilege Escalation):** Eğer bu komutu çalıştıran kişi `root` veya ayrıcalıklı bir kullanıcıysa, saldırganın zararlı kodu süper kullanıcı haklarıyla yürütülmüş olur.

3. **Diğer Kritik Ortam Değişkenleri:**
   - `LD_PRELOAD`: Dinamik bağlayıcıya standart kütüphanelerden önce belirtilen paylaşımlı kütüphaneyi yükletir. Kod enjeksiyonu ve fonksiyon kancalama (API hooking) riski taşır (CWE-114).
   - `IFS` (Internal Field Separator): Kabuğun komut satırındaki parametreleri nasıl ayıracağını belirler; manipüle edilirse betiklerin çalışma mantığı bozulabilir.
   - Hassas Veri İfşası (CWE-526): `DB_PASSWORD`, `API_TOKEN` gibi gizli anahtarların ortam değişkenlerinde düz metin olarak tutulması durumunda, aynı kullanıcının çalıştırdığı herhangi bir alt süreç `/proc/$PID/environ` dosyasından bu sırları sızdırabilir.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Mülakatlarda sıkça sorulur: *"Bir Linux yöneticisinin `$PATH` değişkeninde `.` bulunması neden CIS Benchmark kurallarında kesinlikle yasaklanmıştır?"*  
**Usta Yanıtı:** *"Çünkü `.` göreceli bir yoldur ve anlamı yöneticinin o an bulunduğu dizine göre dinamik olarak değişir. Yönetici `/tmp` dizinine `cd /tmp` yapıp `ls` yazdığında, eğer `.` PATH'in başındaysa sistem `/usr/bin/ls` yerine `/tmp/ls` dosyasını çalıştırır. Bir saldırganın tek yapması gereken `/tmp` altına kötü niyetli bir `ls` betiği bırakıp yöneticinin oraya girmesini beklemektir. Bu nedenle CIS Benchmark 5.4.4, root ve normal kullanıcıların PATH listesinde hiçbir zaman `.` veya boş ayraç (`::`) bulunmamasını şart koşar."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir telekomünikasyon şirketinde çalışan sistem mühendisi, her gece çalışmak üzere bir crontab görevi tanımlar:
`0 2 * * * cd /var/log/app && clean_logs.sh && tar -czf backup.tar.gz *`
Ancak mühendis betikte `tar` komutunu mutlak yoluyla (`/bin/tar`) yazmamıştır ve sunucudaki global PATH'e geliştirici ortamı için `.` eklenmiştir. Uygulama üzerindeki bir zafiyetten içeri sızan düşük yetkili saldırgan, `/var/log/app/` dizinine kendi yazdığı zararlı bir `tar` betiği koyar. Gece saat 02:00'de cron işi çalıştığında cron süreci `/bin/tar` yerine saldırganın sahte `tar` dosyasını `root` yetkileriyle çalıştırır ve saldırgan sunucuda tam yetkili root kabuğuna ulaşır.

---

## SENARYO 2 (G026-SC2): Bağımsız Laboratuvar: PATH Değerini Salt-Okunur İnceleme ve Güvenlik Notu Yazma

### 1. Soru Metni ve Açıklaması
**Soru:** PATH ve ortam değişkenleri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir? (Örnek uygulama: PATH değerini salt-okunur inceleyip güvenlik notu yaz. Doğrulama: kontrollü girdi, gözlenebilir çıktı, olumlu/olumsuz test ve etik sınır. Önceki günün dosyası gerekmez.)

**Açıklama:** Güvenlik sıkılaştırma ve denetim süreçlerinde analist, sisteme hiçbir kalıcı zarar vermeden mevcut durumu salt-okunur (read-only) biçimde inceleyebilmeli ve bulguları kurumsal standartlara göre raporlayabilmelidir. Bu soruda bağımsız bir laboratuvar metodolojisiyle yerel `$PATH` değişkeninin analizi incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap

1. **Kontrollü Girdi (Controlled Input):**
   - Çalışma ortamındaki mevcut işletim sisteminin `PATH` ortam değişkeni (`os.environ.get("PATH")`).
   - Önceden tanımlanmış kural şablonu (`path_security_baseline_rules.json`).
   - Deney tamamen bağımsızdır; önceki günlerin hiçbir dosyasına bağımlılık gerektirmez.

2. **İşlem Adımları (Operation):**
   - **Adım 1:** `path_environment_security_auditor.py --live-path` komutu çalıştırılır.
   - **Adım 2:** Program `PATH` dizesini platform ayrıştırıcısına (Windows `;`, POSIX `:`) göre böler.
   - **Adım 3:** Her bir dizin için:
     - Diskte fiziksel olarak mevcut olup olmadığı (`os.path.exists`),
     - Bağıl bir yol (`.`, `..`, sürücüsüz yol) olup olmadığı (`os.path.isabs`),
     - Boş ayraç (`::`) kaynaklı boş string içerip içermediği kontrol edilir.
   - **Adım 4:** Sistem yöneticisi ve denetim ekipleri için didaktik bir "Güvenlik Değerlendirme Notu" metni üretilir.
   - **Adım 5:** Çıktılar `kanit/gercek/yerel_path_guvenlik_incelemesi.txt` dosyasına kaydedilir.

3. **Beklenen Sonuç (Observable Output):**
   - Taranan toplam dizin sayısı, her dizinin sırası, varlık durumu (`[MEVCUT]` / `[BULUNAMADI]`), bağıl yol bayrakları ve özet güvenlik notu (`[GÜVENLİ]` / `[KRİTİK RİSK]`) konsolda ve dosyada açıkça listelenir.

4. **Negatif Kontrol ve İstisna Yönetimi (Negative Control):**
   - **Test 03 / Test 04:** PATH içinde yapay olarak `.` veya `::` enjekte edildiğinde sistemin bunu derhal yakalayarak `CWE-426` kritik ihlali üretmesi doğrulanmıştır.
   - **Test 12:** CLI arayüzüne var olmayan bir profil dosyası verildiğinde sistemin kontrollü olarak hata üretmesi (`proc.returncode != 0`).
   - **Test 13:** Bozuk JSON kural dosyasında `json.JSONDecodeError` fırlatılarak güvenli hata yönetimi sağlanması.

5. **Etik Sınır (Ethical Boundary):**
   - İnceleme tamamen salt-okunur (read-only) yapılmıştır. Sistemin kayıt defterine (registry), `/etc/environment` veya `.bashrc` dosyalarına hiçbir kalıcı değişiklik yazılmamıştır.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Teknik denetçi mülakatlarında şu soru yöneltilir: *"Bir denetim sırasında işletim sisteminin PATH dizesinde `/opt/custom_app/bin::/usr/bin` gördünüz. Buradaki güvenlik zafiyeti nedir?"*  
**Usta Yanıtı:** *"Aradaki çift iki nokta üst üste (`::`), boş bir eleman üretir (`split(':') -> ''`). POSIX kabukları boş bir PATH girişini geçerli çalışma dizini (`.`) olarak yorumlar. Dolayısıyla kullanıcı `/opt/custom_app/bin` altında bulunmayan bir komut çalıştırdığında, kabuk hemen aradaki boş girişi yani o an bulunduğu mevcut dizini kontrol eder. Bu durum örtülü (implicit) bir CWE-426 Untrusted Search Path zafiyetidir ve derhal aradaki fazladan `:` kaldırılarak düzeltilmelidir."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir siber güvenlik danışmanı, bir holdingin veri merkezindeki yüzlerce Linux sunucusunda uyumluluk denetimi yaparken geliştirdiği salt-okunur denetim aracını koşturur. 12 adet kritik muhasebe sunucusunda, geçmişte bir yazılım kurulumu sırasında `/etc/environment` dosyasına `PATH=/usr/local/bin:/usr/bin:/bin:/tmp` yazıldığını keşfeder (`yerel_path_guvenlik_incelemesi.txt`). Danışman hazırladığı güvenlik notunda, herhangi bir yerel kullanıcının `/tmp` içine sahte sistem komutları koyarak sunucuları rehin alabileceğini kanıtlar ve altyapı ekibi acil bakım penceresi açarak tüm sunuculardaki `/tmp` girdisini temizler.

---

## SENARYO 3 (G026-SC3): PATH ve Ortam Değişkenleri Risk Analizi, Tespiti ve Savunma Kontrolleri

### 1. Soru Metni ve Açıklaması
**Soru:** 'PATH ve ortam değişkenleri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir? (Risk: Gereksiz izin, yanlış servis ve yapılandırma. Konuya uyarlama: PATH ve ortam değişkenleri. Tespit: Kullanıcı/izin/servis envanteri ve fark raporu. Savunma: En az ayrıcalık ve geri alınabilir yapılandırma.)

**Açıklama:** Ortam değişkenleri süreçlerin belleğinde dinamik olarak taşınır ve yapılandırma hataları sonucunda saldırganlara yetki yükseltme ve veri sızdırma kapıları açar. Bu soruda riskin kaynakları, otomatik fark raporlamasıyla tespiti ve çok katmanlı savunma kontrolleri incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap

1. **Riskin Doğuşu (Threat & Root Cause):**
   - **Gereksiz İzinler ve Güvensiz Dizinler:** `$PATH` içinde yer alan bir dizinin yazma izninin dünya çapında açık olması (`chmod 777` verilmiş `/opt/scripts` gibi) veya doğrudan `/tmp` eklenmesi (CWE-427).
   - **Öncelik Sırasının İhlali:** Kullanıcıya ait `~/bin` veya `/usr/local/bin` dizinlerinin sistem dizinlerinin (`/usr/bin`, `/bin`) önüne geçmesi.
   - **Dinamik Bağlayıcı Kötüye Kullanımı (CWE-114):** `LD_PRELOAD` veya `LD_LIBRARY_PATH` değişkenlerinin yetkisiz tanımlanması.
   - **Açık Parola Sızıntıları (CWE-526):** Veritabanı ve bulut API anahtarlarının `.bashrc` veya konteyner ortam değişkenlerinde açık metin saklanması.

2. **Riskin Tespiti (Detection via Inventory & Difference Reporting):**
   - **Otomatik Denetim:** `path_environment_security_auditor.py --audit` aracı ile sistem ortamı ve kullanıcı profilleri taranır.
   - **Kural Seti Karşılaştırması:** Taranan veriler `path_security_baseline_rules.json` güvenlik kurallarıyla kıyaslanır.
   - **Fark Raporu (Difference Report):**
     - *Kritik:* PATH içinde `.` veya `::` tespiti (CWE-426).
     - *Kritik:* PATH içinde `/tmp` veya `/dev/shm` gibi yazılabilir dizin tespiti (CWE-427).
     - *Kritik:* `LD_PRELOAD` değişkeninin aktif olması (CWE-114).
     - *Yüksek:* `DB_PASSWORD` veya `AWS_SECRET_KEY` gibi açık sırların tespiti (CWE-526).

3. **Savunma ve Önleme Kontrolleri (Remediation & Defense Controls):**
   - **En Az Ayrıcalık (PoLP):** PATH yalnızca `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` dizinlerini içerecek şekilde kilitlenir.
   - **Mutlak Yol Kullanımı:** Sistem yöneticisi betiklerinde ve sistem servislerinde (systemd unit dosyaları) çağrılan tüm komutlar mutlak yol ile (`/usr/bin/rsync`, `/usr/bin/systemctl`) yazılır.
   - **SUID/SGID Koruması:** Linux çekirdeğinin SUID süreçlerde `LD_PRELOAD` ve `LD_LIBRARY_PATH` değişkenlerini temizlemesi özelliği (`secure_getenv`) zorunlu kılınır.
   - **Güvenli Sır Yönetimi:** Ortam değişkenleri yerine HashiCorp Vault, Kubernetes Secrets veya dosya tabanlı parola enjeksiyonu kullanılır; `/proc` dosya sistemine erişim `hidepid=2` bağlama seçeneğiyle kısıtlanarak diğer süreçlerin ortam değişkenlerini okuması engellenir.

### 3. Mülakat / Sınav İpucu (Usta Notu)
DevSecOps ve Konteyner Güvenliği mülakatlarında şu soru sorulur: *"Docker konteynerlerinde `ENV DB_PASSWORD=secret` kullanmak neden bir güvenlik ihlalidir ve bunun yerine ne kullanılmalıdır?"*  
**Cevap:** *"1. `docker inspect` komutu çalıştıran herkes imajın veya konteynerin tüm ortam değişkenlerini görebilir. 2. İmaj Docker Hub veya özel bir registry'ye yüklendiğinde parola imaj katmanlarında kalıcı olarak mühürlenir (leak). 3. Konteyner içinde çalışan herhangi bir süreç veya web açığı `/proc/1/environ` dosyasını okuyarak parolayı çalabilir. Bunun yerine Docker Secrets, Kubernetes Secrets veya HashiCorp Vault gibi sır yönetim araçları kullanılmalı; sırlar belleğe salt-okunur ramfs (tmpfs) bağlama noktasıyla dinamik olarak verilmelidir."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir finansal yazılım şirketinin CI/CD sunucusunda derleme işlemi sırasında birim testlerin hata verdiği görülür. Yazılımcı sorunu gidermek amacıyla CI/CD derleme ajanı (runner) ortam değişkenlerine `LD_PRELOAD=/tmp/libmock.so` tanımlar. Ancak derleme tamamlandıktan sonra bu değişken silinmez. Sunucuya giren bir saldırgan, runner ortamındaki `LD_PRELOAD` değişkenini fark eder ve `/tmp/libmock.so` dosyasının üzerine kendi zararlı kütüphanesini yazar. Bir sonraki derlemede bankacılık uygulamasının kaynak koduna gizlice arka kapı (backdoor) enjekte edilir (SolarWinds tarzı tedarik zinciri saldırısı). Düzenli ortam denetleyicisi çalıştırılsaydı, `LD_PRELOAD` tespiti ilk dakikada alarm üretecek ve tedarik zinciri saldırısı engellenecekti.
