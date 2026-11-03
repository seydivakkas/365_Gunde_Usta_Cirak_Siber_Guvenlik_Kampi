# GÜN 026: PATH ve Ortam Değişkenleri Güvenlik Mimarisi

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## 1. GİRİŞ VE PEDAGOJİK ÇERÇEVE (USTA-ÇIRAK VİZYONU)

Evlat, işletim sistemlerinde kabuğa (shell) bir komut yazdığında—örneğin sadece `ls`, `grep` veya `python`—arka planda devasa bir arama ve çözümleme mekanizması devreye girer. İşletim sistemi bu programın diskteki tam adresini nereden bilir? Çekirdek diski rastgele mi tarar? Tabii ki hayır! Çekirdek, sürecin bellek alanında tutulan ve **`PATH`** adı verilen özel bir ortam değişkenine bakar.

İşte bu basit arama listesi, bilgisayar korsanlarının ve sistem sızma testi uzmanlarının en çok istismar ettiği alanlardan biridir. Eğer bir yönetici kolaylık olsun diye `PATH` değişkeninin en başına `.` (mevcut dizin) koyarsa veya `/tmp` gibi herkesin yazabildiği bir klasörü listeye eklerse, tüm işletim sisteminin egemenliğini farkında olmadan saldırgana teslim etmiş olur.

Bugünkü dersimizde `$PATH` arama sırasını, ikili gölgeleme (Binary Hijacking / Trojan) saldırılarını, `LD_PRELOAD` gibi tehlikeli dinamik bağlayıcı manipülasyonlarını, CWE-426, CWE-427 ve CWE-526 zafiyetlerini ve yerel `$PATH` değişkenini salt-okunur analiz ederek kurumsal bir güvenlik değerlendirme notunun nasıl yazılacağını öğreneceğiz.

---

## 2. $PATH ÇÖZÜMLEME MEKANİZMASI VE ARAMA SIRASI

### 2.1 Soldan Sağa Arama Mantığı
Bir kullanıcı veya betik mutlak yol (`/bin/ls`) yerine çıplak komut adı (`ls`) yazdığında kabuk:
1. Komutun bir yerleşik kabuk komutu (shell builtin - `cd`, `echo`, `type`) olup olmadığını kontrol eder.
2. Bir takma ad (alias) olup olmadığına bakar.
3. Bunlar değilse `$PATH` ortam değişkenini iki nokta (`:`) veya Windows'ta noktalı virgül (`;`) karakterlerine göre **soldan sağa (left-to-right)** sırayla tarar.
4. Karşılaştığı ilk çalıştırılabilir dosyayı çalıştırır ve **aramayı derhal sonlandırır**!

### 2.2 Öncelik Sıralamasının Önemi
Standart ve güvenli bir Linux dağıtımında `$PATH` sırası şöyledir:
```bash
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
- `/usr/local/bin`: Sistem yöneticisinin yerel derlediği özel araçlar.
- `/usr/bin`: Paket yöneticisiyle (APT/YUM) kurulan genel sistem araçları.
- `/bin`: Çekirdek seviyesindeki temel sistem komutları.

Eğer bu sırada bir kullanıcının kendi dizini (örn: `/home/analist/bin`) sistem dizinlerinin önüne yazılırsa, o kullanıcının dizinine yerleştirilecek sahte bir `grep` veya `sudo` programı, gerçek sistem aracını gölgeler (shadowing/hijacking)!

---

## 3. CWE-426 VE CWE-427: BAĞIL YOL VE GÜVENİLMEYEN DİZİN GASPI

### 3.1 "." (Current Working Directory) ve Boş Ayraç Riski (CWE-426)
Bazı yazılımcılar mevcut dizindeki betikleri `./program` yazmadan doğrudan `program` diye çalıştırabilmek için `PATH` değişkenine `.` ekler:
```bash
export PATH=.:$PATH
```
Bu hareket kurumsal siber güvenlikte intihardır!
- POSIX kabuklarında iki nokta üst üste (`::`) veya başta/sonda unutulan tek bir `:` karakteri de çekirdek tarafından **örtülü bir `.`** olarak kabul edilir!
- **Saldırı Senaryosu (Trojan Binary Hijacking):**
  1. Saldırgan `/tmp/proje/` veya paylaşımlı bir Git reposu klasörüne kötü amaçlı bir `ls` dosyası koyar ve `chmod +x ls` yapar.
  2. Sistem yöneticisi veya root kullanıcısı bu dizine girer ve masumca `ls` yazar.
  3. Çekirdek `PATH`'in ilk elemanı olan `.` (geçerli dizin) içinde `ls` arar, saldırganın sahte dosyasını bulur ve yönetici haklarıyla çalıştırır!
  4. Saldırgan anında sisteme kalıcı arka kapı veya ters kabuk (reverse shell) yerleştirir.

### 3.2 Dünyaya Yazılabilir Dizinler (CWE-427)
Eğer `$PATH` değişkeninde `/tmp`, `/var/tmp` veya `/dev/shm` gibi sistemdeki herkesin dosya yazabildiği (world-writable) bir dizin bulunuyorsa, herhangi bir düşük yetkili kullanıcı veya kısıtlı web servisi (`www-data`) bu dizine `cat`, `ps`, `netstat` isimli sahte ikililer koyarak yetki yükseltme (Privilege Escalation) gerçekleştirebilir.

---

## 4. DİNAMİK BAĞLAYICI MANİPÜLASYONU: LD_PRELOAD VE LD_LIBRARY_PATH (CWE-114)

Linux sistemlerinde dinamik olarak bağlanan ELF ikilileri çalışırken paylaşımlı kütüphaneleri (`.so`) yükler. Ancak ortam değişkenleri bu süreci saptırabilir:

### 4.1 LD_PRELOAD
- İşletim sistemine şu emri verir: *"Hangi program çalışırsa çalışsın, standart kütüphanelerden (libc.so) önce BENİM belirttiğim kütüphaneyi yükle!"*
- Bir saldırgan `geteuid()` veya `strcmp()` gibi fonksiyonları hook eden özel bir `.so` dosyası yazıp `export LD_PRELOAD=/tmp/evil.so` tanımlarsa, çalışan her süreç saldırganın istediği mantıkla hareket eder.
- **Savunma:** Modern Linux çekirdeği SUID programlar çalışırken `LD_PRELOAD` değişkenini güvenlik gereği otomatik olarak yok sayar (strip eder). Ancak normal kullanıcı süreçleri veya cron betikleri hala bu tehdide açıktır.

### 4.2 LD_LIBRARY_PATH
- Kütüphanelerin aranacağı dizin sırasını belirler. Güvenilmeyen bir dizin (örn: `/tmp`) bu değişkene eklenirse, program meşru kütüphane yerine saldırganın sahte kütüphanesini yükler (Shared Library Hijacking).

---

## 5. ORTAMDA AÇIKTA KALAN PAROLA VE SIRLAR (CWE-526)

Geliştiricilerin modern konteyner (Docker) ve bulut ortamlarında en sık yaptığı hata, veritabanı parolalarını ve API anahtarlarını ortam değişkeni olarak tanımlamaktır:
```bash
export DB_PASSWORD="MegaSecretPassword123!"
export AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
```

### 5.1 Neden Tehlikelidir?
1. **Alt Süreçlere Miras Kalır:** Ortam değişkenleri oluşturulan her alt sürece (child process) otomatik kopyalanır. Çalıştırılan basit bir curl veya loglama aracı bile bu sırları görebilir.
2. **`/proc/PID/environ` İfşası:** Linux sisteminde aynı kullanıcı yetkisindeki herhangi bir süreç `/proc/<PID>/environ` dosyasını okuyarak çalışan diğer programın tüm ortam değişkenlerini düz metin (cleartext) olarak çekebilir.
3. **Hata ve Log Sızıntıları:** Çöken bir uygulamanın stack trace dökümünde veya debug loglarında tüm ortam değişkenleri ekrana basılabilir.

---

## 6. GÜVENLİK ANALİSTİNİN KONTROL LİSTESİ VE SAVUNMA STRATEJİSİ

Bir siber güvenlik uzmanı sistemleri sertleştirirken şu prensipleri uygular:

1. **Temiz ve Sabit PATH:**
   - `/etc/environment` veya `/etc/profile` dosyalarında PATH mutlak sistem dizinleriyle sınırlandırılmalıdır:
     ```bash
     export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
     ```
2. **Betiklerde ve Cron İşlerinde Mutlak Yol (Absolute Paths):**
   - Güvenli yazılım geliştirme kuralı: Betiklerde asla çıplak `tar -czf ...` yazılmaz; her zaman `/bin/tar -czf ...` şeklinde mutlak yol kullanılır.
3. **Bağıl Yol Yasaklaması:**
   - PATH içinde `.` veya çift iki nokta (`::`) kesinlikle engellenmelidir (CIS Benchmark 5.4.4).
4. **Sırların Güvenli Saklanması:**
   - Parolalar ortam değişkeni yerine HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets veya Linux Keyring aracılığıyla bellek içi güvenli kanallardan çekilmelidir.

---

## 7. ÖZET VE BÖLÜM KONTROL LİSTESİ

- [x] `$PATH` değişkeninin soldan sağa arama mantığı ve komut çözümleme sırası anlaşıldı.
- [x] Bağıl yol (`.`) ve boş ayraç (`::`) kullanımının neden olduğu CWE-426 zafiyeti ve sahte ikili (Trojan) yerleştirme riski kavrandı.
- [x] Dünyaya yazılabilir dizinlerin (`/tmp`) PATH içerisine eklenmesinin tehlikeleri (CWE-427) incelendi.
- [x] `LD_PRELOAD` ve `LD_LIBRARY_PATH` değişkenlerinin dinamik bağlayıcı üzerindeki manipülasyon etkisi analiz edildi.
- [x] Ortam değişkenlerinde açık saklanan parolaların (CWE-526) yarattığı veri sızıntısı riskleri değerlendirildi.
- [x] Canlı yerel işletim sistemi `$PATH` değeri salt-okunur incelenerek profesyonel güvenlik notu üretildi (G026-SC2).
