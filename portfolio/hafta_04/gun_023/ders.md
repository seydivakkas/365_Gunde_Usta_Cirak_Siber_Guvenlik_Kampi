# GÜN 023: Linux Terminali, Kabuk (Shell) Yorumlayıcısı ve Yol Güvenliği

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu eğitim materyali Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır. İzinsiz kopyalanamaz, çoğaltılamaz ve ticari amaçla kullanılamaz.*

---

## 1. Derse Giriş ve Kavramsal Çerçeve: Terminal, Kabuk ve Çekirdek Ayrımı

Sevgili öğrencim, dünkü dersimizde Windows dünyasında PowerShell'in nesne tabanlı boru hattı mimarisini ve güvenlik katmanlarını incelemiştik. Bugün ise internet sunucularının, ağ cihazlarının ve güvenlik savunma araçlarının büyük çoğunluğuna hayat veren **Linux Terminal ve Kabuk (Shell)** mimarisine adım atıyoruz.

Siber güvenliğe yeni başlayanların sıklıkla birbirine karıştırdığı üç temel kavramı netleştirelim:
1. **Terminal (TTY / PTY):** Kullanıcı ile sistem arasındaki girdi/çıktı (I/O) arabirimidir. Fiziksel klavyeden basılan tuşları alır ve ekrana karakterleri yansıtır (xterm, GNOME Terminal, Windows Terminal, SSH oturumu birer sözde terminal - PTY'dir).
2. **Kabuk (Shell):** Kullanıcıdan gelen komut satırını sözcüklerine ayıran (tokenization), değişkenleri genişleten (expansion), sözdizimini yorumlayan ve işletim sistemi çekirdeğine çalıştırılacak sistem çağrılarını (`fork`, `execve`) ileten bir **komut yorumlayıcısıdır** (Bash, Sh, Zsh).
3. **Çekirdek (Kernel):** Donanım kaynaklarını, süreçleri ve dosya sistemini doğrudan yöneten çekirdek yazılımdır.

Siber güvenlik analisti için kabuk, hem olay anında delil topladığı (adli bilişim) hem de saldırganın bir web zafiyeti (Command Injection, RCE) üzerinden elde etmeye çalıştığı birincil kontrol merkezidir ("Reverse Shell" kavramı buradan gelir).

---

## 2. Standart G/Ç Akışları ve Dosya Tanımlayıcıları (File Descriptors)

Linux'ta "Her şey bir dosyadır" ilkesi gereğince, her çalışan sürecin açtığı 3 varsayılan akış (stream) vardır:
- **FD 0 (`stdin`):** Standart Girdi (varsayılan klavye).
- **FD 1 (`stdout`):** Standart Çıktı (varsayılan terminal ekranı).
- **FD 2 (`stderr`):** Standart Hata Çıktısı (hata mesajlarının ayrıştırıldığı ekran).

### Yönlendirme ve Boru Hattı Operatörleri:
- `>` : Standart çıktıyı bir dosyaya yazar (dosyayı ezer / overwrite).
- `>>` : Standart çıktıyı dosyanın sonuna ekler (append).
- `<` : Dosya içeriğini standart girdi olarak aktarır.
- `2>&1` : Standart hata akışını (FD 2) standart çıktıya (FD 1) yönlendirir.
- `|` (Boru Hattı / Pipe): Birinci sürecin standart çıktısını (`stdout`), ikinci sürecin standart girdisine (`stdin`) bağlar.

---

## 3. Temel Kabuk Komutları ve İç Mekanizmaları (G023-SC2)

Soru bankamızdaki `G023-SC2` laboratuvarında ele aldığımız 5 temel komutun perde arkası:

### A. `pwd` (Print Working Directory)
- **Rolü:** Sürecin o anda bulunduğu mevcut çalışma dizinini (Current Working Directory - `cwd`) ekrana basar.
- **İç Mekanizma:** Çoğu modern kabukta `pwd` bir kabuk yerleşiğidir (builtin); çekirdeğin süreç kontrol bloğundaki (PCB / `task_struct`) geçerli dizin göstergesini okur.

### B. `cd` (Change Directory)
- **Rolü:** Çalışma dizinini değiştirir.
- **Güvenlik Notu:** `cd` asla harici bir program (`/bin/cd`) olamaz! Bir alt süreç (child process) üst sürecin (parent shell) çalışma dizinini değiştiremez (`fork-exec` kuralı). Bu nedenle `cd` zorunlu olarak kabuk yerleşiğidir (builtin).

### C. `ls` (List)
- **Rolü:** Hedef dizindeki dosya ve alt klasörleri, izinleri, dosya boyutlarını ve sahiplikleri listeler.
- **Adli Önemi:** Dosya değiştirilme zaman damgaları (mtime/atime/ctime) ve yetkisiz gizli dosyalar (`ls -la`) keşif için hayati önemdedir.

### D. `cat` (Concatenate)
- **Rolü:** Dosyaları sırayla okuyup standart çıktıya (`stdout`) basar.
- **Güvenlik Uyarısı:** Büyük log dosyalarını `cat` ile açmak terminal tamponunu kilitler ve bellek tüketebilir; analizlerde sınırlandırılmış araçlar tercih edilmelidir.

### E. `head`
- **Rolü:** Bir dosyanın başından itibaren ilk `N` satırını (varsayılan 10) ekrana basar.
- **Güvenlik Önemi:** Log dosyalarının başlıklarını, konfigürasyon dosyalarının meta verilerini tüm dosyayı belleğe yüklemeden hızlıca denetlemeyi sağlar.

---

## 4. Göreceli Yol (Relative Path) vs Mutlak Yol (Absolute Path) ve Güvenlik Tuzakları (G023-SC1)

Kabuk güvenliğinin en kritik dersi şudur: **"Bir dosyanın nerede olduğu, senin nerede durduğuna bağlı olmamalıdır."**

### A. Göreli Yol (Relative Path):
- Kök (`/`) ile başlamaz; sürecin o anki çalışma dizinine (`pwd`) göre hesaplanır (`cat config.txt`, `./backup.sh`, `../../etc/shadow`).
- **Büyük Güvenlik Tehlikesi (G023-SC1):**  
  Bir sistem yöneticisi veya otomatik zamanlanmış görev (cron job) `/tmp` dizininde iken `cat config.txt` komutu çalıştırılırsa, sistem `/etc/config.txt` yerine saldırganın `/tmp/config.txt` içine yerleştirdiği sahte dosyayı okur!
  Aynı şekilde `../../` kullanımıyla dizin aşımı (CWE-22 Path Traversal) gerçekleşebilir.

### B. Mutlak Yol (Absolute Path):
- Her zaman en üst kök dizinden (`/`) başlar (`/etc/config.txt`, `/var/log/auth.log`).
- Sürecin hangi dizinde çalıştığından tamamen bağımsızdır ve deterministiktir.
- **Altın Savunma Kuralı:** Tüm kurumsal betiklerde, cronjob tanımlarında ve servis birimlerinde (systemd) **istisnasız mutlak yol** kullanılmalıdır.

---

## 5. Saldırı Vektörleri ve Kötüye Kullanım Senaryoları

Saldırganlar kabuk mekanizmalarını nasıl istismar eder?
1. **Güvensiz PATH İstismarı (CWE-426 Untrusted Search Path):**  
   Eğer kullanıcının veya root'un `PATH` ortam değişkeninde `.` (mevcut dizin) veya `/tmp` yer alıyorsa (`PATH=.:/usr/bin:/bin`):
   Saldırgan `/tmp` içine zararlı bir `ls` ikilisi bırakır (`chmod +x /tmp/ls`). Root kullanıcısı `/tmp` dizinindeyken `ls` yazdığında, sistem gerçek `/bin/ls` yerine saldırganın sahte dosyasını çalıştırır ve saldırgan tam root yetkisi kazanır!
2. **Cronjob Göreceli Yol Zaafiyeti:**  
   Root kullanıcısının crontab'ında `cd /var/www && ./sync.sh` satırı varsa ve `/var/www` web kullanıcısına (www-data) yazılabilirse; saldırgan `sync.sh` dosyasını değiştirerek root yetkisinde kod yürütür.
3. **Wildcard Injection (Joker Karakter İstismarı):**  
   Bir dizinde `rm *` veya `tar cf archive.tar *` çalıştırıldığında, saldırgan adı `--checkpoint-action=exec=sh shell.sh` olan bir dosya oluşturursa, `tar` bu dosya adını bir parametre olarak yorumlar ve yetki yükseltir.

---

## 6. Savunma, Denetim ve Güvenli Betik Yazımı

Kurumsal savunmada uygulanması zorunlu standartlar:
1. **Katı Kabuk Betiği Başlığı (Strict Mode):**  
   Yazılan her Bash betiğinin başına şu satır konulmalıdır:
   ```bash
   set -euo pipefail
   IFS=$'\n\t'
   ```
   - `-e`: Bir komut hata verirse betik anında durur (sessizce devam etmez).
   - `-u`: Tanımlanmamış bir değişken çağrılırsa hata verir.
   - `-o pipefail`: Boru hattındaki ara komutlardan biri çökerse boru hattı başarısız sayılır.
2. **Güvenli PATH Tanımı:** Betiklerin başında PATH açıkça ve mutlak yollarla sabitlenmelidir:
   `export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`
3. **Statik Analiz:** Betikler üretime alınmadan önce `shellcheck` aracıyla otomatik taranmalıdır.

---

## 7. Usta Notu, Özet ve Çıkarımlar

> **Usta Diyor ki:**  
> "Evlat, kabuk bir büyüteç gibidir; doğru kullanırsan sisteme dair her ayrıntıyı berrakça görürsün, dikkatsizce güneşe tutarsan koca bir ormanı ateşe verirsin. Asla bir betiğe güvenip göreli yolla (`./`) komut çalıştırma. `PATH` değişkeninin başında asla nokta (`.`) bırakma. Unutma; tecrübeli bir savunmacı, komutun nereden yüklendiğini (`which komut` / `type komut`) ve parametrelerin nasıl genişletildiğini her zaman bilen kişidir."

Yarın **Gün 024** dersimizde, bu kabuk komutlarının üzerinde çalıştığı **Linux Dosya ve Dizin İzinleri, Sayısal (Oktal) ve Simgesel İzinler, Umask ve Erişim Denetimi** konularını derinleştireceğiz.
