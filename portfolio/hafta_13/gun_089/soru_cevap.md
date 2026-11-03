# GÜN 089: Argparse ve CLI Tasarımı — Mülakat ve Saha Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap seti yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz paylaşılamaz veya çoğaltılamaz.*

---

## SORU 1: Alt Komutlar (Subparsers) ile Ortak Bayrakların (Common Flags) Çakışması Nasıl Önlenir?

### 1. Soru Başlığı ve Tanımı
Python `argparse` kütüphanesinde karmaşık bir CLI aracı geliştirirken; ana araç seviyesinde tanımlanan ortak bayraklar (örneğin `--json-output` veya `--verbose`) alt komutlar (`scan`, `audit`) eklendiğinde neden kaybolur veya alt komuttan sonra yazıldığında neden `unrecognized arguments` hatası verir? Bu mimari sorun nasıl çözülür?

### 2. Derinlemesine Teknik Analiz
`argparse`, argümanları soldan sağa doğru durum makinesi (state machine) mantığıyla ayrıştırır. Eğer ana ayrıştırıcıya (`ArgumentParser`) bir alt komut grubu (`add_subparsers`) eklenirse, ayrıştırıcı bir alt komut adıyla karşılaştığı anda denetimi o alt komutun ayrıştırıcısına devreder. 

Eğer `--json-output` bayrağı yalnızca ana ayrıştırıcıda tanımlanmışsa ve kullanıcı komutu:
```bash
sec-cli scan 192.168.1.1 --json-output
```
şeklinde çalıştırırsa; denetim `scan` alt ayrıştırıcısındadır ve `scan` bu bayrağı tanımadığı için `argparse.ArgumentError: unrecognized arguments: --json-output` hatası fırlatır. 

Tersine, bu bayrak hem ana ayrıştırıcıda hem de her alt ayrıştırıcıda el yordamıyla tekrar tekrar eklenirse; kod tekrarı oluşur, bakım zorlaşır ve yardım metinlerinde (`--help`) çelişkiler ortaya çıkar.

Doğru mimari yaklaşım: `add_help=False` parametresiyle oluşturulan bağımsız bir `common_parent` (ebeveyn ayrıştırıcı) tanımlamak ve bunu hem ana ayrıştırıcıya hem de tüm alt ayrıştırıcılara `parents=[common_parent]` şeklinde miras vermektir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir DevSecOps boru hattında çalışan güvenlik tarama aracında kullanıcıların ve CI/CD betiklerinin esnek bayrak yerleşimine izin vermemiz gerekir.

```python
import argparse

# 1. Ortak bayrakları tutan ve çakışmayı önlemek için yardım bayrağını kapatan ebeveyn ayrıştırıcı
common_parent = argparse.ArgumentParser(add_help=False)
common_parent.add_argument(
    "--json-output",
    action="store_true",
    help="Yapısal JSON çıktısı üretir"
)
common_parent.add_argument(
    "-v", "--verbose",
    action="store_true",
    help="Ayrıntılı hata ayıklama günlüklerini açar"
)

# 2. Ana ayrıştırıcıya ebeveyni miras veriyoruz
root_parser = argparse.ArgumentParser(
    prog="sec-cli",
    parents=[common_parent],
    description="Kurumsal Güvenlik Aracı"
)

# 3. Alt komut yöneticisi
subparsers = root_parser.add_subparsers(dest="subcommand", required=True)

# 4. Alt ayrıştırıcıya da ebeveyni miras veriyoruz
scan_parser = subparsers.add_parser("scan", parents=[common_parent])
scan_parser.add_argument("target", help="Hedef IP veya alan adı")
```

Bu çözüm sayesinde kullanıcı ister `sec-cli --json-output scan 10.0.0.1`, ister `sec-cli scan 10.0.0.1 --json-output` yazsın, her iki kullanım da sorunsuz bir şekilde ayrıştırılır.

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, CLI araçlarında kullanıcıyı belirli bir bayrak sırasına zorlamak zayıf bir kullanıcı deneyimidir. `parents=[common_parent]` kalıbını kullanırken `add_help=False` vermeyi asla unutma; aksi takdirde `-h/--help` bayrağı çakışacak ve Python `argparse.ArgumentError: conflicting option string: -h` hatası fırlatacaktır."

---

## SORU 2: Argüman Seviyesinde Girdi Doğrulama ve CWE-88 / CWE-22 Tehditleri Nasıl Bertaraf Edilir?

### 1. Soru Başlığı ve Tanımı
Bir CLI aracında kullanıcı tarafından girilen parametrelerin (`--target`, `--file`, `--port`) `argparse` seviyesinde veya hemen sonrasında sıkı doğrulamadan geçirilmemesi ne gibi siber güvenlik zafiyetlerine (CWE-88, CWE-22, CWE-20) yol açar ve savunma katmanı nasıl kurulur?

### 2. Derinlemesine Teknik Analiz
`argparse`'in varsayılan `type=str` veya `type=int` doğrulaması yalnızca temel tip dönüşümünü kontrol eder, anlamsal güvenlik sınırlarını denetlemez:
- **Port Doğrulaması (CWE-20):** `type=int` kullanıldığında kullanıcı `-500` veya `99999` girebilir. TCP/UDP portları matematiksel olarak 16-bit işaretsiz tamsayıdır ($1 \le p \le 65535$).
- **Argüman Enjeksiyonu (CWE-88):** Bir araç girilen hedefi arka planda bir sistem komutuna (örn. `ssh target` veya `nmap target`) aktarıyorsa, saldırgan `--target "-oProxyCommand=calc.exe"` vererek hedef parametresini yeni bir komut satırı bayrağına dönüştürebilir.
- **Dizin Atlama (CWE-22):** Bir denetim aracı dosya yolu aldığında kullanıcı `--file ../../../etc/shadow` girerek yetkisiz dizinlere erişebilir.

Savunma katmanı; özel tip doğrulama fonksiyonları (`custom type callables`) veya ayrıştırma sonrası sıkı doğrulamacılar (strict validators) ile regex, aralık kontrolü ve kök dizin hapsetme (`chroot/base-dir containment`) mantığıyla kurulmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Aşağıdaki Python kodu, hem port aralığını doğrular hem de hedef dizin atlamasını engeller:

```python
import os
import re
import argparse

def validate_port_number(val: str) -> int:
    """Port numarasını 1-65535 aralığında doğrular."""
    try:
        port = int(val)
        if not (1 <= port <= 65535):
            raise argparse.ArgumentTypeError(f"Geçersiz port: {port}. Port 1-65535 arasında olmalıdır.")
        return port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port bir tamsayı olmalıdır, girilen: {val}")

def validate_safe_file_path(path_str: str, allowed_base_dir: str = ".") -> str:
    """Path traversal (CWE-22) saldırılarını engeller."""
    if ".." in path_str:
        raise ValueError("Dizin atlama ('..') girişimleri güvenlik sebebiyle reddedildi.")
    
    # Mutlak yolları normalize et
    base_abs = os.path.abspath(allowed_base_dir)
    target_abs = os.path.abspath(os.path.join(allowed_base_dir, path_str))
    
    if not target_abs.startswith(base_abs):
        raise ValueError("Erişilmek istenen dosya izin verilen kök dizin sınırları dışındadır.")
        
    return target_abs
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, bir komut satırı aracında 'kullanıcı nasıl olsa sistemi kullanan kişi, kötü niyetli olamaz' varsayımına asla kapılma. Güvenlik araçları çoğunlukla `sudo` yetkisiyle veya CI/CD boru hatlarında servis hesaplarıyla çalıştırılır. O araca iletilen parametreler dışarıdan (bir webhook, bir git commit mesajı, bir ortam değişkeni) besleniyor olabilir. Girişte doğrulanmayan her parametre, sisteme açılan bir arka kapıdır."

---

## SORU 3: Komut Satırında Karşılıklı Dışlayan Seçenekler (Mutually Exclusive Groups) ve Çıkış Kodları Standartları

### 1. Soru Başlığı ve Tanımı
Bir güvenlik tarayıcısında kullanıcıların hem `--fast` hem de `--deep` gibi birbiriyle çelişen çalışma modlarını aynı anda girmesi nasıl engellenir? Hatalı kullanım durumunda hangi POSIX çıkış kodu döndürülmeli ve neden standart çıkış kodlarına uyulmalıdır?

### 2. Derinlemesine Teknik Analiz
Komut satırı araçlarında karşılıklı dışlayan seçeneklerin yönetimi yazılım mimarisi açısından kritiktir. Eğer geliştirici bu mantığı manuel `if args.fast and args.deep:` şeklinde çözmeye kalkarsa:
1. `--help` çıktısında bu iki seçeneğin birbiriyle çeliştiği kullanıcılara gösterilemez.
2. Kod büyüdükçe kombinatorik patlama yaşanır.

`argparse` kütüphanesinin `add_mutually_exclusive_group(required=False)` fonksiyonu, bu kuralı ayrıştırma ağacına gömer. Eğer her iki seçenek de verilirse, ayrıştırıcı anında hata üretir ve yardım sözdiziminde bunu `[--fast | --deep]` paranteziyle modeller.

Çıkış kodları (Exit Codes) açısından POSIX standardı ve GNU Coding Standards şu ayrımı yapar:
- **0:** Başarılı yürütme.
- **1:** Çalışma zamanı/mantıksal hata (örn. taranan sunucuya ulaşılamadı).
- **2:** CLI sözdizimi, hatalı bayrak veya karşılıklı dışlayan seçenek ihlali (CLI argument parse error).

CI/CD araçları (Jenkins, GitLab CI, GitHub Actions) 2 döndüğünde yapılandırma hatası olduğunu, 1 döndüğünde ise uygulamanın çalıştığını ancak testin başarısız olduğunu ayırt edebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
```python
import sys
import argparse

parser = argparse.ArgumentParser(prog="sec-audit")
# Karşılıklı dışlayan grup tanımı
mode_group = parser.add_mutually_exclusive_group(required=False)
mode_group.add_argument("--fast", action="store_true", help="Yüzeysel ve hızlı denetim")
mode_group.add_argument("--deep", action="store_true", help="Kapsamlı ve derin denetim")

try:
    args = parser.parse_args()
    print(f"[+] Denetim başlatılıyor... Hızlı: {args.fast}, Derin: {args.deep}")
    sys.exit(0)
except SystemExit as e:
    # argparse varsayılan olarak sözdizimi hatasında exit code 2 döndürür
    sys.exit(e.code)
```

Terminalde test edildiğinde:
```bash
$ python sec_audit.py --fast --deep
usage: sec-audit [-h] [--fast | --deep]
sec-audit: error: argument --deep: not allowed with argument --fast
$ echo $?
2
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, komut satırı aracı geliştiren mühendisin imzası çıkış kodlarıdır. Hata olduğunda her şeye `sys.exit(1)` dönmek acemiliktir. Sözdizimi hatasında 2 dön ki, aracını bir orkestrasyon betiğine bağlayan DevOps mühendisi parametre hatası mı yaptı yoksa sistem mi çöktü tek bir çıkış koduna bakarak anında anlasın."
