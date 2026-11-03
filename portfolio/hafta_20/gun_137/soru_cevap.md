# Gün 137: Linux SSH Anahtar Güvenliği — Soru & Cevap

---

## SORU 1

### 1. Soru Başlığı ve Tanımı
**Asimetrik Kriptografi ve Anahtar Algoritması Seçimi: Ed25519 vs RSA ve DSA'nın Kırılması (CWE-327 / CWE-326)**  
SSH altyapılarında kullanılan kriptografik anahtar algoritmaları arasındaki matematiksel ve güvenlik farkları nelerdir? Neden 1024-bit DSA ve 2048-bit altı RSA anahtarları derhal tedavülden kaldırılmalıdır? Modern Ed25519 (Curve25519) standardı sistem yöneticilerine hangi kriptografik, performans ve yan kanal (side-channel) korumalarını sunar?

### 2. Derinlemesine Teknik Analiz
SSH protokolünde kimlik doğrulama asimetrik anahtar çiftleri üzerinden yürütülür. Zaman içerisinde artan işlemci gücü ve kriptanaliz teknikleri eski algoritmaları savunmasız bırakmıştır:

1. **DSA (Digital Signature Algorithm - 1024 bit):**
   - DSA, FIPS 186 standardında 1024-bit asal sayılar ve 160-bit alt grup kullanılarak tanımlanmıştır.
   - 1024-bit anahtar boyutu, Discrete Logarithm Problem (DLP) çözümleri için günümüz donanımları karşısında yetersizdir.
   - En büyük kusuru, her imza üretiminde kullanılan rastgele geçici değerin (`k` nonce) mükemmel rastgele olmasını şart koşmasıdır. Eğer rastgele sayı üretecinde (RNG) milyonda birlik bir sapma (bias) dahi olursa, saldırgan ardışık birkaç imzayı inceleyerek özel anahtarı (`x`) matematiksel olarak türetebilir.
   - Bu nedenle OpenSSH 7.0 sürümünden itibaren DSA varsayılan olarak devre dışı bırakılmıştır.

2. **RSA (Rivest–Shamir–Adleman):**
   - RSA'nın güvenliği büyük iki asal sayının çarpımının çarpanlarına ayrılmasının (Integer Factorization Problem - IFP) zorluğuna dayanır.
   - Genel Sayı Alanı Eleği (GNFS) algoritmalarındaki gelişmeler nedeniyle 1024-bit RSA tamamen güvensizdir; 2048-bit RSA ise NIST ve BSI tarafından 2030 yılına kadar geçiş süresi tanınmış asgari sınırdır.
   - Kurumsal sistemlerde RSA kullanılacaksa minimum 3072 veya 4096 bit tercih edilmelidir. Ancak anahtar boyutu büyüdükçe matematiksel işlem süresi ve CPU yükü katlanarak artar.

3. **Ed25519 (Edwards-curve Digital Signature Algorithm):**
   - Daniel J. Bernstein (djb) tarafından tasarlanan Curve25519 eliptik eğrisi (Twisted Edwards curve) üzerinde çalışır.
   - **Kriptografik Güç:** 256-bit anahtar uzunluğuyla ~128-bit güvenlik seviyesi sunar (bu da yaklaşık 3072-bit RSA gücüne denktir).
   - **Yan Kanal (Side-Channel) Koruması:** Ed25519 hesaplamaları sabit zamanda (constant-time) yürütülür. Bu sayede işlemci önbellek zamanlamasını veya güç tüketimini izleyen saldırganlar gizli anahtarı sızdıramaz.
   - **Deterministik İmzalama:** İmza üretilirken harici bir RNG'ye ihtiyaç duyulmaz; nonce değeri özel anahtar ve mesajın kriptografik özetinden (SHA-512) türetilir. Bu sayede DSA/ECDSA'daki felaket RNG zaafları tamamen bertaraf edilir.
   - **Boyut ve Hız:** Açık anahtar 32 bayt, imza 64 bayttır. Ağ üzerinden çok hızlı aktarılır ve CPU'yu neredeyse hiç yormaz.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekomünikasyon şirketi, 2012 yılında kurulmuş eski sunucularında hala 1024-bit DSA anahtarlarıyla çalışan otomatik yedekleme cron görevleri kullanmaktadır. Ağ trafiğini kaydeden bir tehdit aktörü, DSA noncelerindeki zayıflığı istismar ederek yedekleme servisinin özel anahtarını elde etmiş ve tüm veri tabanı sunucularına sızmıştır.

**Pratik Çözüm:**
1. Altyapıdaki tüm DSA anahtarları taranır ve derhal iptal edilir.
2. Yerine kurumsal standart olan Ed25519 anahtarı üretilir:
   ```bash
   ssh-keygen -t ed25519 -a 100 -C "prod-backup-2026" -f ~/.ssh/id_ed25519
   ```
   *Not: `-a 100` parametresi, anahtar parola ile şifrelenirken 100 tur KDF (Key Derivation Function - bcrypt) uygulatarak kaba kuvvet saldırılarına karşı anahtarın kırılmasını imkansız hale getirir.*
3. Üretilen açık anahtar sunucuya aktarılır:
   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519.pub backup_user@prod-server
   ```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! DSA artık bir güvenlik aracı değil, kapıya asılmış açık bir davetiyedir. Eğer bir sunucuda `ssh-dss` veya 1024-bit RSA anahtarı görürsen hiç düşünme; derhal yerine Ed25519 koy. Küçük, zarif, roket gibi hızlı ve matematiksel olarak kaya gibi sağlamdır. Anahtar üretirken `-t ed25519 -a 100` senin ezberin olsun.

---

## SORU 2

### 1. Soru Başlığı ve Tanımı
**Özel Anahtar ve `authorized_keys` Dosya İzinleri İhlali (CWE-732 / MITRE ATT&CK T1552.004 / T1098.004)**  
Linux üzerinde SSH özel anahtarlarının (`id_rsa`, `id_ed25519`) veya yetkilendirme dosyalarının (`authorized_keys`) dosya izinlerinin gevşek (`0644`, `0666`, `0777`) bırakılması durumunda oluşabilecek yetki yükseltme ve kalıcılık (persistence) saldırıları nasıl gerçekleşir? OpenSSH istemcisinin ve sunucusunun izin doğrulama mantığı nedir?

### 2. Derinlemesine Teknik Analiz
SSH mimarisinde güvenlik yalnızca kriptografik algoritmaya değil, anahtarların saklandığı yerel dosya sisteminin erişim denetimine (Discretionary Access Control - DAC) doğrudan bağlıdır:

1. **Özel Anahtarın İfşa Olması (CWE-732 / T1552.004):**
   - Özel anahtar (`id_ed25519`), sahibinin dijital parmak izidir.
   - Eğer bu dosyanın izinleri `0644` (diğerleri okuyabilir) veya `0666` (herkes yazabilir/okuyabilir) yapılırsa, sunucudaki herhangi bir yetkisiz süreç (örneğin Apache/Nginx web kullanıcısı `www-data` ya da sınırlı stajyer hesabı) dosyayı doğrudan okur.
   - Anahtar parola ile korunmamışsa, saldırgan anahtarı kopyalayarak sunucuya veya o anahtarın yetkili olduğu diğer tüm iç ağ sunucularına (lateral movement) parola sorulmaksızın giriş yapar.
   - OpenSSH istemcisi bu tehlikeden korunmak için özel anahtar dosyasının izinlerinin `0600` (`-rw-------`) veya daha katı (`0400`) olduğunu doğrular. Eğer dosya `group` veya `others` tarafından okunabilir durumdaysa, istemci `WARNING: UNPROTECTED PRIVATE KEY FILE!` hatası vererek bağlantıyı açmayı reddeder.

2. **`authorized_keys` Tahrifatı ve Kalıcılık (CWE-732 / T1098.004):**
   - `~/.ssh/authorized_keys` dosyası, o hesaba hangi açık anahtarların şifresiz giriş yapabileceğini belirler.
   - Eğer bu dosya `0666` veya `0777` yapılırsa, saldırgan tek bir komutla kendi oluşturduğu açık anahtarı bu dosyanın sonuna ekler:
     ```bash
     echo "ssh-ed25519 AAAAC3NzaC1l... attacker@kali" >> /home/deploy/.ssh/authorized_keys
     ```
   - Bu işlem tamamlandığı andan itibaren saldırgan artık o sunucuda meşru bir kullanıcı gibi SSH oturumu açabilir. Bu teknik, saldırganın sistemde kalıcı olmasını sağlayan klasik bir **SSH Authorized Keys Persistence (T1098.004)** saldırısıdır.
   - Ayrıca `StrictModes yes` direktifi aktif olan bir OpenSSH sunucusu, kullanıcının ev dizini (`~`), `~/.ssh/` dizini veya `authorized_keys` dosyası başkaları tarafından yazılabilir durumdaysa girişi güvenlik gerekçesiyle engeller (`Authentication refused: bad ownership or modes for file`).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yazılım şirketinde bir geliştirici SSH bağlantısı kurarken "Permission denied (publickey)" hatası almış; forumlardan bulduğu hatalı tavsiyeyle `chmod -R 777 ~/.ssh` komutunu çalıştırmıştır. Şirketin paylaşımlı sunucusuna sızan bir saldırgan, geliştiricinin `id_ed25519` dosyasını çalmış ve şirketin üretim AWS ortamlarına doğrudan geliştirici kimliğiyle erişmiştir.

**Pratik Çözüm:**
1. Dosya ve dizin izinleri derhal standart sıkılaştırma seviyesine çekilmelidir:
   ```bash
   chmod 0700 ~/.ssh
   chmod 0600 ~/.ssh/id_ed25519
   chmod 0644 ~/.ssh/id_ed25519.pub
   chmod 0600 ~/.ssh/authorized_keys
   chown -R $USER:$USER ~/.ssh
   ```
2. Geliştirdiğimiz denetim motoru (`LinuxSshSecurityEngine`), tüm kullanıcı ev dizinlerini tarayarak izinleri `0600` dışına çıkmış özel anahtarları ve `0666` olmuş `authorized_keys` dosyalarını anında tespit edip `otomatik_sikilastirma.sh` betiği ile kilitler.

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Unix dünyasında bir kural vardır: `chmod 777` diyen adam ya ne yaptığını bilmiyordur ya da sunucunu yakmaya çalışıyordur. `.ssh` dizini bir kullanıcının yatak odası gibidir; kapısı kilitli (`0700`), kasası kilitli (`0600`) olmalıdır. İzinleri gevşeterek problem çözülmez, yalnızca güvenlik felaketine davetiye çıkarılır.

---

## SORU 3

### 1. Soru Başlığı ve Tanımı
**OpenSSH Sunucu Sertleştirmesi (`sshd_config`): `PermitRootLogin no`, `PasswordAuthentication no` ve Kriptografik Şifre Setleri**  
Kurumsal bir Linux sunucusunda `/etc/ssh/sshd_config` dosyası sertleştirilirken parola tabanlı kimlik doğrulamanın kapatılması ve doğrudan `root` oturumunun engellenmesi hangi tehdit vektörlerini (Brute-Force, Credential Stuffing) tamamen nötralize eder? Zayıf CBC şifreleri ve SHA-1 yerine modern AEAD şifrelerinin (`chacha20-poly1305`, `aes256-gcm`) seçilmesi neden hayati önem taşır?

### 2. Derinlemesine Teknik Analiz
İnternete açık veya kurumsal DMZ bölgesindeki bir SSH sunucusuna günde on binlerce otomatik bot saldırısı yöneltilir:

1. **Parola Doğrulamasını Kapatmanın Etkisi (`PasswordAuthentication no` - CIS 5.2.9):**
   - Parola kimlik doğrulaması açıkken saldırganlar devasa sözlükler ve sızdırılmış kimlik listeleri (RockYou, breach-compilations) kullanarak **Credential Stuffing** ve **Brute-Force** saldırıları düzenler.
   - `PasswordAuthentication no` yapıldığında OpenSSH sunucusu parola sorgulama aşamasını protokol seviyesinde tamamen kapatır (`AuthenticationMethods publickey`).
   - Saldırgan milyonlarca şifre denese bile sunucu hiçbir parolayı kabul etmez; geçerli bir özel anahtar imzası sunulmadığı sürece oturum açılması matematiksel olarak imkansızdır.

2. **Root Girişini Engellemenin Etkisi (`PermitRootLogin no` - CIS 5.2.5):**
   - Bütün Linux sistemlerinde varsayılan ve en yetkili kullanıcının adı `root`'tur. Saldırgan için kullanıcı adı zaten bellidir; iş yalnızca parolayı veya anahtarı tahmin etmeye kalır.
   - `PermitRootLogin no` yapıldığında doğrudan root girişi yasaklanır. Saldırgan önce sistemdeki benzersiz kullanıcı adını (örneğin `m_yilmaz`) bulmak, onun anahtarıyla girmek ve ardından `sudo` parolasını aşmak zorundadır (Çift katmanlı savunma).
   - Ayrıca sistem denetiminde (auditd) root olarak kimin işlem yaptığı belirsizleşmez; oturumu açan kullanıcının kimliği her log satırında görünür.

3. **Modern Şifre Setleri ve KexAlgorithms:**
   - Eski SSH yapılandırmalarında `3des-cbc`, `blowfish-cbc`, `arcfour` (RC4) ve `hmac-sha1` gibi zayıf algoritmalar bulunur.
   - CBC (Cipher Block Chaining) modundaki şifreler, SSH protokolünde düz metin sızıntısına yol açan **Padding Oracle (Plaintext Recovery)** saldırılarına (CVE-2008-5161) açıktır.
   - Modern sertleştirmede Authenticated Encryption with Associated Data (AEAD) mimarisine sahip şifreler zorunlu kılınır:
     - `chacha20-poly1305@openssh.com` (Yüksek hız, donanım bağımsız)
     - `aes256-gcm@openssh.com` (Donanım AES-NI hızlandırmalı tam kimlik doğrulamalı şifreleme)
   - Anahtar değişiminde (Key Exchange) ise logjam ve discrete log açıklarına karşı `curve25519-sha256` ve `diffie-hellman-group16-sha512` zorunlu tutulur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kamu kurumunun dışa açık web sunucusuna her saniye yüzlerce SSH brute-force denemesi yapılmakta, log dosyaları şişmekte ve sunucu CPU tüketimi tavan yapmaktadır. Güvenlik ekibi fail2ban kurmuş olsa da dağıtık botnet IP'leri ban listelerini aşmaktadır.

**Pratik Çözüm:**
`/etc/ssh/sshd_config` dosyasında şu sertleştirme uygulanır:
```ini
# Temel Kimlik Doğrulama Sıkılaştırması
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AuthenticationMethods publickey
MaxAuthTries 3

# Kriptografik Şifre Setleri
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```
Yapılandırma doğrulandıktan sonra servis yeniden yüklenir:
```bash
sudo sshd -t && sudo systemctl reload sshd
```
Sonuç olarak sunucuya gelen tüm parola denemeleri anında kapıda reddedilir; brute-force fırtınası sıfır maliyetle tamamen etkisiz hale gelir.

### 4. Ustanın Çırağa Tavsiyesi
Çırak! İnternete açık bir sunucuda parola ile SSH girişi bırakmak, evinin kapısını açık bırakıp "Nasılsa hırsız kapı kolunu çevirmeyi akıl edemez" demek gibidir. Parola kimlik doğrulamasını kapatacaksın; sadece güçlü anahtarlara izin vereceksin. Bu basit ama hayati adımı attığın an, sunucuna yönelik saldırıların %99'u kapıda buharlaşır.
