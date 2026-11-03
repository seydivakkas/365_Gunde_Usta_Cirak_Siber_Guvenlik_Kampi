# GÜN 078: DOSYA OKUMA VE PATHLIB (SECURE FILE I/O & PATHLIB IN CYBER SECURITY)
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞ DERSİ: DOSYA SİSTEMİ BİR DEPO DEĞİL, BİR MUHAREBE MEYDANIDIR

Evlat, siber güvenlik yazılımlarında dosya okuma ve yazma işlemleri (`File I/O`), acemi yazılımcıların en çok hata yaptığı ve saldırganların en çok istismar ettiği alandır. Birçok kişi `open("dosya.txt", "r")` yazmanın basit ve masum olduğunu düşünür. Oysa dosya sistemi yaşayan, sürekli durum değiştiren, sembolik bağlarla yanıltılabilen ve dizin atlama karakterleriyle sınırları aşılabilen dinamik bir yapıdır.

Eğer kullanıcının veya bir ağ paketinin sağladığı bir dosya adını doğrudan dosya açma fonksiyonuna iletirsen, saldırgan tek bir `../../../../etc/passwd` dizesiyle senin sunucunun en mahrem sırlarını çalar. Eğer gelen bir kural dosyasını yazarken elektrik kesilirse veya süreç öldürülürse, güvenlik duvarın yarım yazılmış bozuk bir konfigürasyonla baş başa kalır ve tüm kapılarını açık (fail-open) bırakabilir.

İşte bu yüzden modern siber güvenlik otomasyonunda eski `os.path` fonksiyonları yerine nesne yönelimli, sembolik bağları fiziksel tabanına kadar kanonik olarak çözen `pathlib.Path` standardını ve atomik yazma (`Atomic Write`) mimarisini kullanmak bir tercih değil, mutlak bir savunma zorunluluğudur!

---

## 2. DİZİN AŞIMI (PATH TRAVERSAL / CWE-22) VE `os.path.join` ÖLÜMCÜL TUZAĞI

Çırakların en sık düştüğü yanılgı, `os.path.join()` fonksiyonunun dizin aşımını engellediğini sanmaktır:

```python
# ❌ ÇOK TEHLİKELİ VE YAYGIN BİR YANILGI (CWE-22):
sandbox = "/var/log/app"
user_input = "/etc/passwd"

guya_guvenli_yol = os.path.join(sandbox, user_input)
# Sonuç: "/etc/passwd" !
```
**Neden Oldu?** POSIX standartlarına göre `os.path.join()` fonksiyonuna gelen ikinci parametre mutlak bir yol (`/` ile başlayan) ise, fonksiyon önceki tüm parametreleri atar ve doğrudan ikinci yolu kök kabul eder! Yazılımcı `sandbox` içinde kaldığını sanırken, saldırgan doğrudan işletim sisteminin köküne atlamıştır!

### Savunmacı Çözüm: `pathlib.Path.resolve()` ve `is_relative_to()`
Python 3.4 ile gelen ve 3.9'da `is_relative_to` ile taçlanan `pathlib` kütüphanesi bu sorunu kökten çözer:

```python
from pathlib import Path

# 1. Sandbox dizini kesinlikle kanonik ve mutlak yapılır
sandbox_dir = Path("/var/log/app").resolve()

# 2. Mutlak yol enjeksiyonu önceden engellenir
req = Path(user_input)
if req.is_absolute():
    raise PermissionError("Mutlak yol enjeksiyonu engellendi!")

# 3. Yol birleştirilir ve tüm göreceli noktalar (../../) çözümlenir
candidate = (sandbox_dir / req).resolve()

# 4. Kanonik adayın gerçekten sandbox altında olup olmadığı matematiksel olarak sınanır
if not candidate.is_relative_to(sandbox_dir):
    raise PermissionError("Dizin aşımı (Path Traversal) tespit edildi ve engellendi!")
```
Bu 4 adımlı kalkan sayesinde saldırgan kaç kat `../` koyarsa koysun, `resolve()` onu fiziksel yoluna indirger ve `is_relative_to` sınır bekçisi kapıyı yüzüne kapatır!

---

## 3. SEMBOLİK BAĞLANTI (SYMLINK) VE KAVŞAK (JUNCTION) İSTİSMARI (CWE-59)

Bir saldırgan sandbox dizini içine meşru bir dosya yerine işletim sisteminin hassas bir bölgesini işaret eden bir sembolik bağlantı (`symlink`) yerleştirebilir:
- `sandbox/audit.log -> /etc/shadow`

Geleneksel kontroller dosyanın `sandbox/audit.log` yolunda olduğunu görür ve erişime izin verir. Ancak `.resolve()` çağrıldığında, `pathlib` bu sembolik bağı takip ederek gerçek hedefi olan `/etc/shadow` yoluna ulaşır. Ardından yapılan `is_relative_to(sandbox_dir)` kontrolü, hedefin sandbox sınırları dışında olduğunu anında yakalar ve operasyonu `PermissionError` ile durdurur.

---

## 4. ZAMAN KONTROLÜ / ZAMAN KULLANIMI YARIŞ DURUMLARI (TOCTOU - CWE-367)

Bir dosya üzerinde işlem yaparken kontrol zamanı (Time-of-Check) ile kullanım zamanı (Time-of-Use) arasında geçen mikrosaniyeler, çoklu iş parçacığı veya paylaşımlı ortamlarda saldırganın araya girmesine zemin hazırlar:

```python
# ❌ GÜVENSİZ YARIŞ DURUMU (TOCTOU):
if os.path.exists(filepath): # 1. Kontrol Zamanı
    # 💥 TAM BU ARADA saldırgan dosyayı silip yerine /etc/shadow sembolik bağını koyar!
    with open(filepath, "w") as f: # 2. Kullanım Zamanı -> /etc/shadow ezilir!
        f.write(data)
```

### Savunmacı Çözüm: EAFP (Easier to Ask for Forgiveness than Permission)
Siber güvenlikte "önce kontrol et sonra yap" yerine "doğrudan atomik bağlamda güvenle aç, hata olursa yakala" ilkesi uygulanır. Dosyayı kontrol etmek yerine bağlam yöneticisi (`with open`) ve `os.open` bayrakları (`O_CREAT | O_EXCL`) ile açıp hatayı istisna bloğunda yönetmek yarış durumunu imkansız kılar.

---

## 5. ATOMİK DOSYA YAZMA (ATOMIC WRITE) VE POLİTİKA BÜTÜNLÜĞÜ

Bir siber güvenlik sisteminde güvenlik duvarı kuralları, erişim kontrol listeleri (ACL) veya tehdit istihbaratı veritabanı doğrudan hedef dosya üzerine `open(file, "w")` ile yazılmamalıdır. Eğer yazma işlemi sırasında elektrik kesilirse, bellek taşarsa veya süreç öldürülürse dosya 0 bayt kalır veya yarım yazılır. Bu durum güvenlik sisteminin kör kalmasına yol açar.

### Dört Aşamalı Atomik Yazma Protokolü:
1. **Aynı Dizinde Geçici Dosya Oluştur:** Hedef dosyanın bulunduğu aynı disk bölümünde benzersiz bir geçici dosya (`.tmp_PID_TIMESTAMP`) açılır. (Aynı dosya sisteminde olması atomik takas için zorunludur).
2. **Tamponu Boşalt (`flush`):** Python'ın iç bellek tamponundaki veriler işletim sistemine aktarılır.
3. **Diske Senkronize Et (`os.fsync`):** İşletim sisteminin disk önbelleğinde bekleyen veriler fiziksel diske zorla yazdırılır (Veri Dayanıklılığı - Data Durability).
4. **Atomik Takas (`os.replace`):** Geçici dosya tek bir çekirdek çağrısıyla hedef dosyanın üzerine taşınır. Çekirdek bu işlemi atomik olarak gerçekleştirir; sistem çökse dahi dosya ya eski sağlam halinde kalır ya da yeni tam halinde kalır, asla yarım veya bozuk olamaz!

---

## 6. BÜYÜK DOSYALARDA BELLEK TÜKENMESİ (CWE-400 / OOM-KILLER) SAVUNMASI

Bir saldırgan sisteme 50 GB boyutunda devasa bir log dosyası veya Zip-Bomb ile şişirilmiş bir metin dosyası sağlayabilir. Eğer yazılımınız `file.read()` veya `file.readlines()` çağırırsa:
- Sunucunun tüm RAM'i tükenir.
- İşletim sisteminin OOM-Killer mekanizması devreye girer ve güvenlik yazılımını zorla kapatır.

### İkili Savunma Bariyeri:
1. **Statik Boyut Denetimi:** Dosya açılmadan önce `path.stat().st_size` ile boyutu kontrol edilir. Güvenlik tavanını (`max_file_size_bytes`, örn. 1 MB) aşıyorsa işlem hiç başlatılmaz.
2. **Akış Üreteçleri (Generators):** Büyük log dosyaları okunurken satırlar `yield` ile akıtılır (`safe_stream_lines`). Bellekte aynı anda sadece tek bir satır tutulur.

---

## 7. USTANIN ÇIRAĞA ÖĞÜTLERİ VE ALTIN KURALLAR

1. **`os.path`'i Unut, `pathlib.Path`'e Sarıl:** 2026 yılı siber güvenlik standartlarında `os.path` kullanmak tarihi eser tüfekle savaşa gitmeye benzer. `Path.resolve()` ve `is_relative_to()` senin sarsılmaz kalendir.
2. **Kullanıcı Girdisini Asla Doğrudan `Path()` İle Açma:** Önce Null-Byte kontrolü yap, mutlak yol olup olmadığını denetle, sandbox'a ekleyip resolve et ve sınırda kalıp kalmadığını test et.
3. **Uzantı Beyaz Listesi (Whitelist) Koy:** Sandbox dizinine sadece izin verdiğin uzantılardaki (`.json`, `.log`, `.yaml`, `.txt`) dosyaların girmesine ve çıkmasına izin ver. `.exe`, `.sh`, `.php` dosyalarını sınırda reddet.
4. **Güvenlik Politikalarını Asla Doğrudan Dosyaya Yazma:** Her zaman atomik yaz (`.tmp` -> `flush` -> `fsync` -> `os.replace`). Sistemin fişi çekilse dahi politikan bozulmamalıdır.
5. **Daima `with open()` Kullan:** Açılan her dosya tanımlayıcısını bağlam yöneticisine emanet et. Bir gün bile kaynak sızıntısı (FD leak) yüzünden sisteminin kilitlenmesine izin verme!
