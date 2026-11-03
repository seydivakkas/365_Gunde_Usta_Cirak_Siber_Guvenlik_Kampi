# GÜN 134: Linux Sudo, Ayrıcalık Devri ve Yetki Yükseltme Savunması

## Usta-Çırak / Hoca Dersi: Linux'ta Root Tacının Korunması

Hoş geldin evlat. Hafta 20 ile birlikte siber güvenliğin en kritik ve en güçlü dünyasına adım atıyoruz: **Linux Sistem Güvenliği**. 

Windows'un karmaşık API'lerinden sonra Linux sana ilk başta sade görünecektir; ancak bu sadelik yanıltıcıdır. Linux'ta tek bir komut, tek bir yapılandırma satırı seni vezir de eder, rezil de. İşte o satırların en tehlikelisi ve en kudretlisi `/etc/sudoers` dosyasıdır.

Bir Linux sisteminde saldırgan düşük yetkili bir kullanıcı (`www-data`, `nobody` veya standart kullanıcı) olarak kabuk (shell) elde ettiğinde ilk çalıştırdığı komut şudur:
```bash
sudo -l
```
Saldırgan bu komutla sistem yöneticisinin tembellik yapıp yapmadığını anlar. Eğer bir sistem yöneticisi düşüncesizce bir izin vermişse, saldırgan 5 saniye içinde makinenin mutlak tanrısı olan `root` kullanıcısına dönüşür.

Bugün seninle Linux ayrıcalık devrini (Privilege Delegation), sudo mimarisini, GTFOBins kabuk kaçışlarını ve kurumsal sudoers sıkılaştırmasını santim santim öğreneceğiz.

---

### 1. Linux Ayrıcalık Devri ve Sudo Mimarisi

Geleneksel Unix felsefesinde iki tür kullanıcı vardı: `root` (UID 0 - her şeye kadir) ve diğerleri (UID > 0). Bir kullanıcının yönetimsel bir iş yapabilmesi için doğrudan `root` şifresini bilmesi veya `su -` çekmesi gerekiyordu. Ancak bu modelde:
- `root` şifresi herkese dağıtılır,
- Kimin ne yaptığı denetlenemez (non-repudiation yoktur),
- En az ayrıcalık (Least Privilege) prensibi uygulanamazdı.

**Sudo (Superuser Do)** bu kaosu çözmek için doğdu. Sudo; kullanıcının kendi şifresini girerek (veya belirli durumlarda şifresiz) yalnızca izin verilen komutları `root` yetkisiyle yürütmesini sağlayan bir SUID (`/usr/bin/sudo`) ikilisidir.

Sudo'nun çalışma mantığı:
1. Kullanıcı `sudo <komut>` yazar.
2. Sudo, `/etc/pam.d/sudo` üzerinden kullanıcının kimliğini doğrular (Authentication).
3. Sudo, `/etc/sudoers` ve `/etc/sudoers.d/` dizinini tarayarak yetkilendirme (Authorization) kurallarını kontrol eder.
4. Kural geçerliyse `setuid(0)` ve `setgid(0)` sistem çağrılarıyla sürecin UID'sini 0 yaparak komutu icra eder.

---

### 2. Sudoers Sözdizimi (Syntax) ve Anatomi

Sudo kuralları şu genel şablonu takip eder:
```text
Kullanıcı/Grup   Host=(RunAs_Kullanıcı:RunAs_Grup) [ETİKETLER] Komutlar
```

Örnekler:
```text
root             ALL=(ALL:ALL) ALL
%wheel           ALL=(ALL:ALL) ALL
devops           ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
```

**Kritik Sözdizimi Kuralları:**
- `%` işareti kuralın bir kullanıcıya değil, bir Linux grubuna (`group`) ait olduğunu belirtir (Örn: `%wheel`, `%sudo`).
- `ALL=(ALL:ALL)` ifadesi: Herhangi bir sunucuda, herhangi bir kullanıcının ve herhangi bir grubun kimliğine bürünebileceğini gösterir.
- `NOPASSWD:` etiketi: Kullanıcının bu komutu çalıştırırken kendi şifresini dahi girmesine gerek olmadığını belirtir (**Saldırganların en sevdiği bayrak!**).

---

### 3. Ölümcül Hata 1: `NOPASSWD: ALL` (CWE-250 / MITRE ATT&CK T1548.003)

Evlat, tembel sistem yöneticileri genellikle şöyle bir satır yazar:
```text
developer ALL=(ALL) NOPASSWD: ALL
```
Bu satır ne anlama gelir? "Bu kullanıcının şifresini bilmene gerek yok. `sudo su -` veya `sudo /bin/bash` yazdığın anda doğrudan root olursun."

Eğer bu kullanıcının SSH anahtarı çalınırsa veya makinedeki bir web servisi bu kullanıcı altında koşarken RCE zafiyeti verirse, saldırgan parola engeline takılmadan tek saniyede makineyi ele geçirir. Kurumsal ortamlarda `NOPASSWD: ALL` kabul edilemez bir güvenlik ihlalidir.

---

### 4. Ölümcül Hata 2: GTFOBins ve Masum Görünen İkili Dosyalar

Sistem yöneticisi der ki: *"Ben geliştiriciye ALL vermedim, sadece logları okusun diye `cat`, `less` verdim; dosyaları düzenlesin diye `vim` verdim; dosya arasın diye `find` verdim."*

İşte buna siber güvenlikte **GTFOBins** deriz evlat! Birçok standart Unix aracı içerisinde kabuk çağırma (shell escape) mekanizmaları barındırır:

1. **Vim / Vi Editörü:**
   Kullanıcı `sudo vim` çalıştırdığında editör içerisinden şunu yazar:
   ```text
   :!/bin/sh
   ```
   Vim editörü root yetkisiyle çalıştığı için çağırdığı alt kabuk doğrudan **root kabuğu** olur!
2. **Find Komutu:**
   ```bash
   sudo find . -exec /bin/sh \; -quit
   ```
   Find komutu bulunan her dosya için `-exec` parametresini root haklarıyla yürütür.
3. **AWK / GAWK Betiği:**
   ```bash
   sudo awk 'BEGIN {system("/bin/sh")}'
   ```
4. **Less / More Sayfalayıcısı:**
   `sudo less /var/log/syslog` açıldığında klavyeden `!/bin/sh` yazmak anında root kabuğu verir.
5. **Python / Perl / Ruby Yorumlayıcıları:**
   ```bash
   sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
   ```

**Kural:** Sudoers içerisine interaktif editörler, sayfalayıcılar veya yorumlayıcı diller (`vim`, `find`, `python`, `less`) doğrudan eklenemez! Eğer belirli bir dosyayı düzenletmek gerekiyorsa `sudoedit` kullanılmalıdır.

---

### 5. Ölümcül Hata 3: `env_keep` ve `LD_PRELOAD` Kütüphane Enjeksiyonu (CWE-426 / MITRE ATT&CK T1574.006)

Eski veya hatalı yapılandırılmış sudoers dosyalarında şu satıra rastlarsın:
```text
Defaults env_keep += "LD_PRELOAD"
```
Bu satır Linux'un kalbine sıkılmış bir kurşundur! 

Linux'ta dinamik bağlayıcı (`ld.so`), `LD_PRELOAD` çevre değişkeninde belirtilen paylaşımlı kütüphaneyi (`.so`) program başlamadan önce belleğe ilk kütüphane olarak yükler. Normalde SUID ikililerinde ve sudo çağrılarında güvenlik nedeniyle `LD_PRELOAD` otomatik olarak sıfırlanır (`env_reset`).

Ancak sistem yöneticisi `env_keep += "LD_PRELOAD"` demişse:
Saldırgan basit bir C kodu yazar:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
Bunu derler: `gcc -fPIC -shared -nostartfiles -o /tmp/evil.so evil.c`  
Ve çalıştırır:
```bash
sudo LD_PRELOAD=/tmp/evil.so <herhangi_bir_izinli_komut>
```
Komut ne olursa olsun (isterse sadece `ls` olsun), `evil.so` ilk çalışan kod olur ve anında root kabuğu açılır!

---

### 6. Sudoers Dosya İzinleri ve `visudo` Zorunluluğu (CWE-732)

`/etc/sudoers` ve `/etc/sudoers.d/` altındaki dosyaların izinleri:
- Sahip ve Grup: `root:root`
- İzin Modu: `0440` (Sadece root okuyabilir, kimse yazamaz!).

Eğer bir yönetici bu dosyaya `chmod 0666` veya `0777` verirse, makinedeki herhangi bir kullanıcı dosyayı açıp kendi adını `ALL=(ALL) ALL` olarak ekler.

Ayrıca `/etc/sudoers` dosyası **asla standart metin editörleriyle (nano, vim doğrudan) düzenlenmemelidir!** Daima:
```bash
visudo
```
komutu kullanılmalıdır. `visudo` dosyayı geçici bir alanda açar, sözdizimi hatası (syntax error) varsa dosyayı kaydetmeyi reddeder ve iki yöneticinin aynı anda düzenleme yaparak dosyayı bozmasını (race condition / locking) engeller.

---

### 7. Kurumsal Sudo Sıkılaştırma (Hardening) Direktifleri

Bir kurumda standart bir `/etc/sudoers` dosyasının başında mutlaka bulunması gereken sıkılaştırma direktifleri:
1. `Defaults env_reset` : Kullanıcının çağıran ortamındaki değişkenleri siler.
2. `Defaults mail_badpass` : Hatalı parola denemelerini günlüğe ve e-postaya bildirir.
3. `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"` : Güvenli arama yolu uygular, `.` veya `/tmp` çalışmasını önler.
4. `Defaults use_pty` : Sudo'yu sahte bir terminalde çalıştırarak terminal girdi enjeksiyonlarını (TIOCSTI) engeller.
5. `Defaults logfile="/var/log/sudo.log"` : Tüm sudo işlemlerini merkezi denetim günlüğüne yazar.
6. `Defaults timestamp_timeout=15` : Şifre önbellek süresini 15 dakika ile sınırlar.

---

### Ustanın Çırağa Öğüdü
> *"Evlat, Linux'ta root olmak kolaydır; ama bir sisteme root kaptırmamak ustalık ister. `sudo -l` dediğinde önüne çıkan liste, sistem yöneticisinin zeka testidir. NOPASSWD verme, GTFOBins araçlarını kısıtla, `env_reset`'i asla kapatma ve sudoers dosyasına gözün gibi bak!"*
