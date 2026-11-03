# GÜN 089: Argparse ve CLI Tasarımı — Usta-Çırak Siber Güvenlik Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz çoğaltılamaz, dağıtılamaz veya ticari projelerde kullanılamaz.*

---

## 1. Ustanın Giriş Dersi: Neden "Sadece Bir Betik" Değil, Güvenli Bir CLI?

Evlat, siber güvenlik dünyasında ister bir Kırmızı Takım (Red Team) sızma testi uzmanı, ister bir Mavi Takım (Blue Team) SOC analisti ol; yazdığın araçların güvenilirliği, onların komut satırı arayüzü (CLI - Command Line Interface) kalitesiyle ölçülür. 

Pek çok toy geliştirici veya güvenlik heveslisi, Python ile bir exploit ya da tarayıcı yazdığında parametreleri `sys.argv[1]`, `sys.argv[2]` gibi ilkel indislerle almaya kalkışır. Ya da kullanıcı hatalı bir argüman girdiğinde betik Python'un çirkin stack trace çıktısını ekrana kusar, yarım kalmış dosya tutamaçları (file handles) açık kalır veya en kötüsü kullanıcıdan gelen filtrelenmemiş komut satırı argümanı bir alt kabuk (subshell) çağrısına doğrudan sızarak **Argüman Enjeksiyonu (CWE-88)** ya da **Dizin Atlama (Path Traversal - CWE-22)** felaketine yol açar.

Usta der ki: **"Bir CLI aracı, hem son derece sezgisel ve standartlara uygun (POSIX/GNU uyumlu) olmalı, hem de kendisine beslenen her baytı düşmanca bir girdi kabul ederek kapıda doğrulamalıdır."**

Bu derste; Python standart kütüphanesinin güçlü modülü `argparse`'i sadece basit bayraklar eklemek için değil; alt komutlar (subparsers), karşılıklı dışlayan gruplar (mutually exclusive groups), ortak miras ayrıştırıcıları (parent parsers) ve kurşun geçirmez girdi doğrulama kalkanlarıyla donatılmış endüstriyel bir güvenlik aracına dönüştürmeyi öğreneceksin.

---

## 2. CLI Tasarımının Temel İlkeleri ve POSIX/GNU Standartları

Profesyonel bir komut satırı aracı, Unix/POSIX felsefesine ve GNU CLI standartlarına sadık kalmalıdır:

1. **Kısa ve Uzun Bayrak Ayrımı:**
   - Kısa bayraklar tek tire ile (`-v`, `-h`, `-o`, `-p`), uzun bayraklar çift tire ile (`--verbose`, `--help`, `--output`, `--port`) verilmelidir.
   - Kısa bayraklar gerektiğinde birleştirilebilmelidir (`-vh` gibi, gerçi güvenlik araçlarında açık ve belirgin olmak her zaman yeğdir).
2. **Alt Komutlar (Subcommands / Subparsers):**
   - Tıpkı `git commit`, `docker run` veya `kubectl get` mimarisinde olduğu gibi, kompleks araçlar işlevlerine göre alt komutlara ayrılmalıdır (`scan`, `audit`, `hash` vb.).
   - Her alt komut yalnızca kendi bağlamına ait parametreleri kabul etmeli; böylece parametre kirliliği ve mantıksal çakışmalar engellenmelidir.
3. **Karşılıklı Dışlayan Seçenekler (Mutually Exclusive Options):**
   - Bir aracın aynı anda hem `--fast` (hızlı/yüzeysel) hem de `--deep` (tam kapsamlı/derin) modda çalışması mantıksal bir tezat oluşturur. Bu durum kod içerisinde karmaşık `if-else` kontrolleriyle değil, ayrıştırıcı seviyesinde (`add_mutually_exclusive_group`) çözülmelidir.
4. **Tutarlı Çıkış Kodları (Exit Codes):**
   - POSIX standartlarına göre:
     - `0`: Başarılı tamamlanma (Success).
     - `1`: Genel işlem/uygulama hatası (Runtime/Operational failure).
     - `2`: Komut satırı sözdizimi, eksik veya geçersiz argüman hatası (CLI syntax/argument error).

---

## 3. Siber Güvenlik Odaklı CLI Zafiyetleri ve Savunma Stratejileri

Komut satırı araçları doğrudan yetkili kullanıcılar veya CI/CD boru hatları tarafından çağrıldığı için girdi doğrulaması yapılmadığında kritik zafiyetlere gebedir:

### A. Dizin Atlama (Path Traversal - CWE-22)
Kullanıcı `--target /etc/shadow` veya `--config ../../../root/.ssh/id_rsa` girdiğinde, CLI ayrıştırıcısı dosyayı açmaya kalkışmadan önce yolun meşru ve izin verilen sınırlar içerisinde olduğunu kontrol etmelidir.
- **Çözüm:** `os.path.abspath` ve `os.path.realpath` kontrolleriyle izin verilen kök dizin sınırları denetlenmeli, `..` dizin üstüne çıkma girişimleri anında reddedilmelidir.

### B. Argüman Enjeksiyonu (Argument Injection - CWE-88)
CLI aracın arka planda `curl`, `nmap` veya `tar` gibi başka bir ikili programı çağırıyorsa, kullanıcıdan gelen `--target` parametresi aslında `--help` veya `--output=/tmp/pwned` gibi parametreler içerebilir.
- **Çözüm:** Argümanların başında kontrolsüz tire (`-`) bulunmamalı, regex ile hedef formatı (RFC-1123 uyumlu alan adı veya geçerli IPv4/IPv6 adresi) sıkı bir şekilde onaylanmalıdır.

### C. Sayısal Sınır ve Port Doğrulaması (CWE-20)
Bir ağ tarayıcısı CLI'ı için port parametresi rastgele bir tamsayı olamaz.
- **Kural:** Port değeri kesinlikle `$1 \le port \le 65535$` kapalı aralığında olmalıdır. Bu aralık dışındaki değerler derhal 2 çıkış koduyla reddedilmelidir.

### D. Hizmet Reddi (Denial of Service - DoS) Saldırıları
Saldırganlar otomasyon boru hatlarını çökertmek veya tampon bellek taşması simülasyonu yapmak için komut satırına megabaytlarca uzunlukta argümanlar gönderebilir.
- **Kural:** Girdi komut dizgisi makul bir üst sınırla (örneğin 8192 bayt) ve argüman adedi en fazla 64 ile sınırlandırılmalıdır.

---

## 4. `argparse` ile İleri Düzey Mimari Tasarım: Kod İncelemesi

Aşağıdaki mimari, geliştirdiğimiz `SecurityArgumentParser` sınıfının kalbini oluşturur:

```python
# Ortak parametreleri (help, json-output, verbose) miras almak için add_help=False parent parser
common_parent = argparse.ArgumentParser(add_help=False)
common_parent.add_argument(
    "--json-output", 
    action="store_true", 
    help="Çıktıyı yapısal JSON formatında döndürür"
)
common_parent.add_argument(
    "-v", "--verbose", 
    action="store_true", 
    help="Ayrıntılı hata ayıklama günlüklerini etkinleştirir"
)

# Ana ayrıştırıcı
root_parser = SecurityArgumentParser(
    prog="sec-cli",
    description="Kurumsal Güvenlik Denetim ve Analiz CLI Motoru",
    parents=[common_parent]
)

# Alt komutlar boru hattı
subparsers = root_parser.add_subparsers(
    dest="subcommand",
    title="Kullanılabilir Güvenlik Alt Komutları",
    required=True
)

# 'audit' alt komutunda karşılıklı dışlayan grup
audit_parser = subparsers.add_parser("audit", parents=[common_parent])
audit_group = audit_parser.add_mutually_exclusive_group()
audit_group.add_argument("--fast", action="store_true", help="Hızlı yüzeysel denetim")
audit_group.add_argument("--deep", action="store_true", help="Derinlemesine tam denetim")
```

Bu tasarım sayesinde:
1. `--json-output` ve `-v` gibi bayraklar hem alt komuttan önce (`sec-cli --json-output scan ...`) hem de sonra (`sec-cli scan --json-output ...`) verilebilir; `argparse` şaşırmaz.
2. Kullanıcı hem `--fast` hem de `--deep` vermeye kalktığında ayrıştırıcı doğrudan `error()` metodunu tetikleyerek kullanıcıyı uyarır.
3. Hata mesajları stack trace üretmez; temiz, açıklayıcı ve POSIX çıkış kodu `2` ile sonlanır.

---

## 5. Çırağa Öğütler ve Altın Kurallar

1. **Hiçbir Zaman `exit_on_error=True` ile Gözü Kapalı Kalma:** Birim testler yazarken `argparse` varsayılan olarak `sys.exit()` çağırır ve test sürecini patlatır. Kendi `SecurityArgumentParser` sınıfını türeterek `error()` metodunu override et ve kontrollü bir istisna (`CLIArgumentError`) fırlat.
2. **Kullanıcı Dostu Yardım Metinleri Sun:** `--help` çağrıldığında parametrelerin ne işe yaradığı, varsayılan değerleri (`default=...`) ve kabul edilen değer aralıkları (`choices=...`) net bir şekilde listelenmelidir.
3. **JSON ve Otomasyon Uyumluluğu:** Modern güvenlik araçları insanlar kadar CI/CD boru hatları ve SIEM sistemleri tarafından da tüketilir. `--json-output` desteğini baştan tasarla.
