# GÜN 135: Linux PAM ve Oturum Politikası Soru-Cevap ve Derinlemesine Analiz

## Soru 1: Linux PAM Modül Yürütme Zincirinde `required`, `requisite` ve `sufficient` Kontrol Bayrakları (Control Flags) Arasındaki Mantıksal Farklar Nelerdir ve Yanlış Bir `sufficient` Bayrağı Kimlik Doğrulamayı Nasıl Bypass Eder?

### 1. Soru Başlığı ve Tanımı
Pluggable Authentication Modules (PAM) mimarisi, kimlik doğrulama adımlarını bir zincir (stack) halinde sırayla yürütür. Her bir kuralın sonucunun genel doğrulama kararını nasıl etkileyeceğini `required`, `requisite`, `sufficient` ve `optional` kontrol bayrakları belirler. Bu bayrakların hatalı sıralanması veya `sufficient` bayrağının gevşek bir kurala verilmesi, saldırganların kimlik denetimlerini tamamen atlatmasına (Authentication Bypass) yol açar.

### 2. Derinlemesine Teknik Analiz
PAM zincirinde her bir modül `PAM_SUCCESS`, `PAM_AUTH_ERR`, `PAM_USER_UNKNOWN` gibi bir durum kodu döner. Karar motorunun mantığı:

1. **`required` (Zorunlu ama Tamamlayıcı):**
   - Modül başarılı olursa zincir devam eder.
   - Modül başarısız olursa, PAM bu başarısızlığı dahili hafızasına not eder ancak **zinciri kesmez**. Saldırgana parolanın mı, kullanıcının mı yoksa 2FA'nın mı yanlış olduğunu belli etmemek (timing attack / kullanıcı keşfi önleme) için zincirdeki sonraki modülleri de çalıştırır. Nihai karar zincir bittiğinde mutlaka **BAŞARISIZDIR**.
2. **`requisite` (Zorunlu ve Kesici):**
   - Modül başarılı olursa zincir devam eder.
   - Modül başarısız olduğu anda **zincir derhal sonlandırılır** ve anında hata döner. Sistem kaynaklarını korumak veya kritik bir ön koşul (örneğin hesap kilidi) sağlanmadığında diğer kontrolleri çalıştırmamak için kullanılır.
3. **`sufficient` (Yeterli ve Erken Başarı):**
   - Eğer bu modülden önceki hiçbir `required` modül başarısız olmamışsa ve bu modül `PAM_SUCCESS` dönerse, **PAM zinciri o anda keser ve kullanıcıyı BAŞARIYLA sisteme kabul eder!** Zincirin altındaki diğer kurallar (örneğin ikinci faktör doğrulama veya hesap kilit kontrolleri) hiç çalıştırılmaz!
   - Eğer modül başarısız olursa, başarısızlık yok sayılır ve zincir alttaki kurallara devam eder.

**Ölümcül Hata Örneği (Bypass Senaryosu):**
```text
auth sufficient pam_permit.so
auth required   pam_unix.so
auth required   pam_faillock.so
```
Burada `pam_permit.so` her zaman başarı döner. `sufficient` olduğu için ilk satırda PAM zinciri anında bitirir ve kullanıcı ne şifre girerse girsin (isterse yanlış girsin) sisteme kabul edilir!

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sistem yöneticisi, ofis içi yerel ağdan gelen yöneticilerin şifresiz girebilmesi için `/etc/pam.d/sshd` dosyasına özel bir modül eklemek istemiş ve şu yapılandırmayı yapmıştır:
```text
auth sufficient pam_env.so
auth required   pam_unix.so
```
`pam_env.so` modülü sadece çevre değişkenlerini yüklemek için tasarlanmıştır ve ortam yüklendiğinde her zaman `PAM_SUCCESS` döner. Yönetici farkında olmadan `sufficient` bayrağı kullandığı için, SSH üzerinden bağlanan herhangi bir kullanıcı şifre ekranında Enter'a bastığı anda sunucuya root olarak giriş yapabilmiştir.

**Pratik Çözüm:**
1. `pam_env.so` gibi durum kontrolü yapmayan modüllere asla `sufficient` verilmemeli, `required` veya `optional` olarak tanımlanmalıdır.
2. Kimlik doğrulama zincirlerinde modern standart sözdizimi veya `authselect` profilleri kullanılmalıdır:
```text
# Güvenli RHEL/Ubuntu auth zinciri:
auth required   pam_faillock.so preauth silent
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail
auth optional   pam_faildelay.so delay=2000000
auth required   pam_faillock.so authsucc
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, `sufficient` bayrağı PAM'ın çift namlulu tüfeğidir; yanlış yere koyarsan kendini vurursun. Bir kurala `sufficient` diyorsan, "Bu kural geçtiyse benim için güvenlik bitmiştir, içeri al" demiş olursun. Arkasındaki hiçbir kural (şifre, 2FA, faillock) çalışmaz. Elle PAM yazarken `sufficient` kullanmaktan kaçın; `authselect` veya `pam-auth-update` gibi test edilmiş profil araçlarına sadık kal!

---

## Soru 2: `pam_faillock` Modülü ile Kaba Kuvvet (Brute-Force) Koruması Nasıl Yapılandırılır ve Neden `even_deny_root` Parametresi Hayatidir?

### 1. Soru Başlığı ve Tanımı
Linux sunucularında SSH ve yerel konsollar, otomatik botlar ve saldırganlar tarafından sürekli sözlük (dictionary) ve kaba kuvvet parola tahmin saldırılarına maruz kalır. `pam_faillock` modülü, belirlenen başarısız deneme eşiği aşıldığında hesabı geçici olarak kilitleyerek bu saldırıları imkansız hale getirir. `even_deny_root` direktifi ise en büyük hedef olan `root` kullanıcısının da bu kalkan altına alınmasını sağlar.

### 2. Derinlemesine Teknik Analiz
`pam_faillock` modülü, başarısız oturum açma denemelerini `/run/faillock/` (veya `/var/run/faillock/`) dizininde her kullanıcı için ayrı bir ikili dosyada tutar. Bu sayede bellek tabanlı, son derece hızlı ve disk I/O yükü getirmeyen bir sayım yürütür.

**Kritik Yapılandırma Parametreleri (`/etc/security/faillock.conf`):**
1. **`deny = 5`:** Kullanıcı 5 kez üst üste yanlış şifre girerse hesap kilitlenir.
2. **`fail_interval = 900`:** Başarısız denemeler 900 saniye (15 dakika) boyunca hafızada tutulur. Kullanıcı 14. dakikada 5. hatayı yaparsa hesap kilitlenir.
3. **`unlock_time = 900`:** Kilitlenen hesap 900 saniye sonra otomatik olarak açılır (DoS saldırısı riskini hafifletmek için). Eğer bu değer `0` yapılırsa hesap ancak bir sistem yöneticisi `faillock --reset` komutunu çalıştırana kadar kilitli kalır.
4. **`even_deny_root`:** Varsayılan olarak Linux sistemleri yöneticinin dışarıda kalmaması (lockout) için `root` kullanıcısını kilitlemez. Ancak saldırganların en birincil hedefi root hesabıdır. Bu parametre aktif edilmediğinde, saldırgan root hesabına milyonlarca şifre deneyebilirken normal kullanıcılar 5 denemede kilitlenir.

**Root Kilitlenme Emniyeti (`root_unlock_time`):**
Root kullanıcısının hizmet reddi (DoS) ile sistemi tamamen kilitlemesini engellemek için `even_deny_root` ile birlikte `root_unlock_time = 300` (5 dakika) gibi daha kısa bir otomatik kilit açma süresi tanımlanabilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** İnternete açık bir Linux sunucusuna Hydra ve Medusa araçlarıyla SSH üzerinden root parolası denenmektedir. Sistemde `pam_faillock` açıktır ancak `even_deny_root` unutulmuştur. Saldırgan 6 saatlik kaba kuvvet denemesi sonucunda sunucunun root şifresini kırar ve içeri sızar.

**Pratik Çözüm:**
`/etc/security/faillock.conf` dosyası standartlara uygun yapılandırılır:
```ini
# /etc/security/faillock.conf
dir = /run/faillock
audit
silent
deny = 5
fail_interval = 900
unlock_time = 900
even_deny_root
root_unlock_time = 300
```
Yönetici kilit durumunu şu komutla izler:
```bash
# Tüm kilitli kullanıcıları listeleme
faillock
# Spesifik bir kullanıcının kilidini açma
faillock --user root --reset
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, kapına vuran her tokmağa kapıyı sonsuza kadar açmaya çalışırsan, elbet bir gün anahtarı tuttururlar. Beş tokmağı yanlış vuranın elini 15 dakika bağla (`faillock`). Ve sakın "root kilitlenirse ne yaparız" diye korkup root'u savunmasız bırakma; `even_deny_root` koy, yanına konsol erişimi için `root_unlock_time` ekle!

---

## Soru 3: Parola Karmaşıklığı (`pam_pwquality`) ve Oturum Zaman Aşımı (`TMOUT`) İlkeleri Neden Birlikte Uygulanmalıdır ve Parola Kredileri (Credits) Mantığı Nasıl Çalışır?

### 1. Soru Başlığı ve Tanımı
Güçlü bir kimlik güvenliği; sadece parolanın ne kadar karmaşık olduğuyla değil, oluşturulan aktif oturumun nasıl terk edildiğiyle de doğrudan ilişkilidir. `pam_pwquality`, kaba kuvvet ve tahmin saldırılarına karşı güçlü parola seçilmesini zorunlu kılarken; `TMOUT` değişkeni, açık unutulan terminallere fiziksel veya yetkisiz erişimlerin önüne geçerek oturum yaşam döngüsünü kapatır.

### 2. Derinlemesine Teknik Analiz
`pam_pwquality` modülünde yer alan **Kredi (Credits)** sistemi, Linux güvenlik yöneticilerinin en sık karıştırdığı parametre grubudur:

Parametreler: `dcredit` (digit/rakam), `ucredit` (uppercase/büyük harf), `lcredit` (lowercase/küçük harf), `ocredit` (other/özel karakter).

**Pozitif Değerler (Uzunluk İndirimi):**
Örneğin `minlen = 14` ve `dcredit = 2` olarak ayarlanmışsa: Bu durum parola içinde rakam bulunmasını **zorunlu kılmaz**. Eğer kullanıcı parolasında en az bir rakam kullanırsa, sistem ona 2 karakter "bonus" verir ve minimum uzunluk 14'ten 12'ye düşer! Bu durum güvenliği gevşetir.

**Negatif Değerler (Zorunlu Asgari Adet):**
Değer negatif yapıldığında (`dcredit = -1`, `ucredit = -1`, `lcredit = -1`, `ocredit = -1`), sistem artık bonus vermez; kullanıcının parolasında **en az 1 adet rakam, 1 adet büyük harf, 1 adet küçük harf ve 1 adet özel karakter** bulunmasını MUTLAK ZORUNLULUK haline getirir. Biri bile eksik olursa `passwd` komutu `BAD PASSWORD: The password fails the dictionary check / complexity check` hatasıyla işlemi iptal eder.

**Oturum Boşta Kalma (Inactivity) Güvenliği (CWE-613):**
Kullanıcı 16 karakterlik aşırı güçlü bir parola seçse bile, oturumu açıp masadan ayrıldığında oturum süresiz açık kalırsa parolanın hiçbir koruyuculuğu kalmaz.
Linux kabukları (Bash/Zsh), `TMOUT` çevre değişkeniyle yönetilir:
- `TMOUT=900`: 15 dakika boyunca terminalden girdi gelmezse kabuk otomatik olarak `exit` yapar ve oturumu kapatır.
- `readonly TMOUT`: Kullanıcının kabuk içinde `unset TMOUT` veya `TMOUT=0` yazarak bu korumayı aşmasını engeller.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir AR-GE şirketinde kıdemli sistem yöneticisi veri merkezindeki konsoldan sunucuya root girişi yapmış, acil bir toplantı için ekranı kilitlemeden ayrılmıştır. Ofisi temizleyen temizlik personeli veya meraklı bir stajyer, klavyeden Enter'a basarak root kabuğuna erişmiş ve yanlış bir komutla üretim veri tabanını silmiştir.

**Pratik Çözüm:**
1. Parola karmaşıklığı `/etc/security/pwquality.conf` ile kilitlenir:
```ini
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
enforce_for_root
```
2. Oturum zaman aşımı `/etc/profile.d/timeout.sh` dosyasına yazılır:
```bash
# /etc/profile.d/timeout.sh
readonly TMOUT=900
export TMOUT
```
3. Dosya izinleri kilitlenir: `chmod 0644 /etc/profile.d/timeout.sh`.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, dünyanın en kırılmaz çelik kapısını taktırsan ama kapıyı ardına kadar açık bırakıp gitsen, o kapının çeliği kimi korur? `pam_pwquality` ile kapıyı çelik yap, `TMOUT` ile de açık kalan kapıyı arkasından otomatik kapat! Pozitif kredilere kanma, kredileri daima eksi (`-1`) tut!
