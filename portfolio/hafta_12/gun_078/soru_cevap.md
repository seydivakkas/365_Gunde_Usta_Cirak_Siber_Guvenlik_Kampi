# GÜN 078: DOSYA OKUMA VE PATHLIB — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G078-SC1: Dizin Aşımı (Path Traversal / CWE-22), `os.path.join` Fonksiyonunun Gizli Zaafı ve `Pathlib` ile Sandbox İzolasyonu

#### Soru Başlığı ve Tanımı
Geleneksel Python kodlarında dosya yollarını birleştirmek için `os.path.join(base_dir, user_filename)` sıkça kullanılır. Bu fonksiyonun mutlak yol parametreleri karşısındaki çalışma mantığı nasıl kritik bir dizin aşımı (Path Traversal / CWE-22) ve yetkisiz dosya okuma açığı doğurur? Modern Python'da `pathlib.Path.resolve()` ve `is_relative_to()` yöntemleri kullanılarak sarsılmaz bir sandbox kalkanı nasıl inşa edilir?

#### Derinlemesine Teknik Analiz
`os.path.join()` fonksiyonunun POSIX ve Windows spesifikasyonunda gizli ve ölümcül bir davranış kuralı vardır:
*Eğer birleştirilen yollardan biri mutlak bir yol (POSIX'te `/` ile, Windows'ta `C:\` ile başlayan) ise, `os.path.join()` o noktadan önceki tüm argümanları tamamen yok sayar ve birleştirmeyi o mutlak yoldan itibaren başlatır.*

```python
# GÜVENSİZ KOD:
base_directory = "/opt/security_app/storage"
untrusted_file = "/etc/shadow"

result_path = os.path.join(base_directory, untrusted_file)
# result_path DEĞERİ: "/etc/shadow" !
```
Yazılımcı dosyanın `/opt/security_app/storage` içinde açılacağını varsayarken, Python işletim sisteminin kök dizinine atlamış ve saldırganın talep ettiği sistem parolasını okuyup ifşa etmiştir.

Benzer şekilde göreceli dizin atlama karakterleri (`../../`) kullanıldığında:
`os.path.join("/opt/app/storage", "../../etc/passwd")` -> `"/opt/app/storage/../../etc/passwd"` dizesini üretir. Bu dize doğrudan `open()` fonksiyonuna iletildiğinde çekirdek (kernel) seviyesinde göreceli noktalar işletilerek `/etc/passwd` okunur.

**Savunmacı Pathlib Mimarisi (Kanonik Sınır Koruması):**
1. **Kanonikleştirme (`Path.resolve()`):** Dosya yolundaki tüm göreceli referansları (`.` ve `..`) ve sembolik bağları (symlink) çözerek fiziksel disk üzerindeki gerçek mutlak hedefe indirger.
2. **Kapsama Denetimi (`is_relative_to()`):** Çözümlenen kanonik yolun gerçekten yetkilendirilmiş sandbox dizininin bir alt dalı olup olmadığını matematiksel olarak doğrular.

```python
from pathlib import Path

def get_safe_sandbox_file(base_dir: Path, requested_file: str) -> Path:
    # 1. Null-byte kontrolü
    if "\x00" in requested_file:
        raise ValueError("Null-byte enjeksiyonu!")
        
    # 2. Mutlak yol enjeksiyonu kontrolü
    req = Path(requested_file)
    if req.is_absolute():
        raise PermissionError(f"Mutlak yol ile sandbox dışına çıkış engellendi: {requested_file}")
        
    # 3. Kanonikleştirme
    canonical_target = (base_dir / req).resolve()
    
    # 4. Sandbox sınır denetimi
    if not canonical_target.is_relative_to(base_dir):
        raise PermissionError(f"Dizin aşımı (Path Traversal) tespit edildi: {requested_file}")
        
    return canonical_target
```

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurum içi güvenlik portalı, personelin log dosyalarını indirmesi için bir API sunmaktadır. API `os.path.join("/var/log/audit", filename)` ile dosyayı diskten okumaktadır. Saldırgan parametre olarak `../../../../etc/kubernetes/admin.conf` göndermiş; sunucu kural dışına çıkarak Kubernetes kümesinin yönetici anahtarlarını saldırgana teslim etmiş ve tüm bulut altyapısı ele geçirilmiştir.

`pathlib` tabanlı `resolve()` ve `is_relative_to()` koruması devreye alındığında, `admin.conf` yolunun `/var/log/audit` hiyerarşisinde olmadığı anında saptanarak işlem `PermissionError` ile durdurulur ve güvenlik alarmı üretilir.

#### Ustanın Çırağa Tavsiyesi
> "Evlat, `os.path.join` bir emniyet kilidi değildir; sadece bir metin yapıştırıcısıdır! Kullanıcıdan dosya adı alıyorsan, 'bu dosya benim dizinimde mi?' diye sormanın tek yasal yolu `candidate.is_relative_to(sandbox_dir)` kontrolüdür. Bu kontrolü yapmadan dosya açan yazılımcı, kapının anahtarını sokaktaki paspasın altına bırakan adama benzer!"

---

### G078-SC2: Zaman Kontrolü / Zaman Kullanımı (TOCTOU - CWE-367) Yarış Durumları, Sembolik Bağlantı İstismarı ve EAFP Yaklaşımı

#### Soru Başlığı ve Tanımı
Bir dosya açılmadan önce `if os.path.exists(filepath):` veya `if os.path.isfile(filepath):` şeklinde yapılan kontroller, çoklu iş parçacığı (multi-threading) veya paylaşımlı dizinlerde nasıl bir TOCTOU (Time-of-Check to Time-of-Use / CWE-367) yarış durumu yaratır? Saldırganlar aradaki mikrosaniyeleri sembolik bağlar (symlink) ile istismar ederek sistem dosyalarını nasıl ezebilir ve savunmacı Python kodunda EAFP ilkesi bu zaafı nasıl kapatır?

#### Derinlemesine Teknik Analiz
TOCTOU açığı, bir kaynağın durumunun denetlendiği an (Time-of-Check) ile o kaynağın fiilen kullanıldığı an (Time-of-Use) arasında geçen işlemci döngülerinde kaynağın durumunun üçüncü bir tarafça değiştirilmesidir.

**Saldırı Senaryosu (Symlink Race Condition):**
1. **0. Mikrosaniye (Kontrol):** Güvenlik yazılımı geçici bir dosyanın durumunu kontrol eder:
   `if not os.path.exists("/tmp/temp_policy.txt"):` -> Sonuç `True` (Dosya henüz yok, güvenli).
2. **5. Mikrosaniye (Saldırgan Araya Girer):** Saldırgan tam bu kontrolün hemen ardından işletim sisteminde aynı yola bir sembolik bağ oluşturur:
   `ln -s /etc/passwd /tmp/temp_policy.txt`
3. **10. Mikrosaniye (Kullanım):** Güvenlik yazılımı dosyayı yazmak üzere açar:
   `with open("/tmp/temp_policy.txt", "w") as f: f.write(new_policy)`
4. **Sonuç:** Güvenlik yazılımı masum bir geçici dosya yazdığını sanırken, sembolik bağı takip eden çekirdek `/etc/passwd` dosyasını ezer ve sistem çöker!

**Savunmacı Programlama Çözümü: EAFP İlkesi:**
Python felsefesinin temel taşlarından biri olan **EAFP (Easier to Ask for Forgiveness than Permission - İzin İstemektense Özür Dilemek Daha Kolaydır)** ilkesi uygulanır.
- Dosyanın var olup olmadığını önceden kontrol etmek (`LBYL - Look Before You Leap`) yerine, işlem doğrudan güvenli ve atomik işletim sistemi bayraklarıyla başlatılır.
- Düşük seviyeli `os.open` çağrısında `os.O_CREAT | os.O_EXCL` bayrakları kullanılır. Bu bayraklar çekirdek seviyesinde garanti eder: *Eğer dosya veya sembolik bağ zaten varsa, dosya açılmaz ve derhal `FileExistsError` fırlatılır.* Araya saldırganın girmesi donanımsal düzeyde imkansız hale gelir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir antivirüs tarayıcısı, şüpheli dosyaları karantina dizinine taşımadan önce `if os.path.exists(target_path):` kontrolü yapmaktadır. Yerel yetki yükseltme (LPE) peşinde koşan bir saldırgan, tarayıcının karantina işlemi sırasında hızlı bir C betiğiyle araya girerek karantina yolunu `C:\Windows\System32\drivers\etc\hosts` dosyasına bağlamış ve sistem dosyalarını tahrif etmiştir.

**Savunmacı Çözüm:**
```python
import os

def create_quarantine_file_safe(target_path: str, data: bytes) -> None:
    # os.O_CREAT | os.O_EXCL çekirdek seviyesinde atomiktir (TOCTOU imkansız)
    # 0o600: Sadece dosya sahibine okuma/yazma izni verir
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600
    
    try:
        fd = os.open(target_path, flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except FileExistsError:
        raise PermissionError(f"Yarış durumu (TOCTOU) veya dosya çakışması engellendi: {target_path}")
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! Kapıyı çalmakla (check) kapıyı açmak (use) arasında geçen o bir mikrosaniyede saldırgan içeri girip bombayı bırakır. 'Dosya var mı yok mu?' diye kontrol edip sonra açmayacaksın. Kapıyı kilitli bayraklarla (`O_EXCL`) tek hamlede atomik olarak açacaksın; içeride biri varsa sistem kapıyı onun kafasına çarparak `FileExistsError` ile patlasın!"

---

### G078-SC3: Kritik Güvenlik Politikası Dosyalarında Atomik Yazma (Atomic Write) ve Veri Dayanıklılığı (`fsync` + `os.replace`)

#### Soru Başlığı ve Tanımı
Güvenlik duvarı kuralları, SIEM yapılandırmaları veya tehdit istihbaratı veritabanı gibi kritik dosyalar doğrudan hedef dosya üzerine `with open(filepath, "w") as f:` kalıbıyla yazıldığında ne gibi felaket riskleri (veri bozulması, yarım yazılma, fail-open durumu) ortaya çıkar? Atomik yazma (`Atomic Write`) protokolü, `flush()`, `os.fsync()` ve `os.replace()` adımları ile bu riskleri nasıl sıfırlar?

#### Derinlemesine Teknik Analiz
Standart bir `open(path, "w")` çağrısı yapıldığı anda işletim sistemi dosyanın boyutunu anında sıfırlar (truncate to 0 bytes). Ardından Python veriyi yazmaya başlar.

Bu süreçte şu üç senaryodan biri gerçekleşirse:
1. Sunucunun elektrik bağlantısı kesilirse veya güç kaynağı arızalanırsa.
2. İşletim sistemi çekirdeği bellek yetersizliği (OOM) sebebiyle süreci aniden öldürürse (`kill -9`).
3. Diskte yer kalmazsa (`No space left on device`).

**Sonuç:** Hedef güvenlik politikası dosyası ya 0 bayt kalır ya da ilk 50 satırı yazılmış, geri kalanı eksik bozuk bir dosya haline gelir. Güvenlik servisi yeniden başladığında bozuk politikayı ayrıştıramaz ve çöker; ya da kurallar eksik olduğu için tüm ağ trafiğini denetimsiz içeri alır (Fail-Open felaketi).

**Dört Aşamalı Atomik Yazma (Atomic Write Protocol):**

```
[ Bellek / RAM ]                 [ Geçici Dosya ]                  [ Hedef Dosya ]
Yeni Politika Metni ──write()──> .tmp_12345_999 
                                        │
                                   os.flush()
                                        │
                                   os.fsync() ──> [Fiziksel Manyetik/NVMe Disk]
                                        │
                                 os.replace() ────(Tek Çekirdek Adımı: ATOMIC)────> policy.yaml
```

1. **Aynı Dizin ve Dosya Sisteminde Geçici Dosya:** Geçici dosya (`.tmp_PID_TIME`) hedef dosya ile kesinlikle aynı dosya sistemi bölümünde açılmalıdır. Farklı disk bölümleri arasında atomik taşıma yapılamaz.
2. **Kullanıcı Alanından Çekirdeğe Boşaltma (`f.flush()`):** Python'ın C seviyesindeki I/O tamponunu işletim sistemi çekirdeğine aktarır.
3. **Fiziksel Diske Zorlama (`os.fsync(fd)`):** Çekirdeğin disk önbelleğindeki (page cache) veriyi fiziksel depolama plakalarına/chiplerine yazar. Elektrik anında kesilse dahi geçici dosyanın diske tam yazıldığı kesinleşir.
4. **Atomik Değiştirme (`os.replace(temp, target)`):** İşletim sisteminin VFS katmanındaki `rename` sistem çağrısı atomiktir. Dosya ya tamamen eski halinde kalır ya da tek bir mikrosaniyede tamamen yeni haliyle yer değiştirir. Asla yarım, bozuk veya 0 bayt kalamaz!

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir endüstriyel SCADA ağında güvenlik politikalarını güncelleyen Python servisi, doğrudan `firewall_rules.json` üzerine yazarken sunucu UPS devreye girmiş ve disk yazması yarıda kalmıştır. JSON dosyası kapanış parantezi eksik bozuk kaydedilmiş; güvenlik duvarı servisi JSON parse hatası vererek çökmüş ve fabrika otomasyon ağı 3 saat boyunca saldırıya açık kalmıştır.

**Savunmacı Atomik Yazma Metodu:**
```python
import os
import time
from pathlib import Path

def atomic_write_policy_safe(target_path: Path, content: str) -> None:
    temp_path = target_path.parent / f".tmp_{os.getpid()}_{time.time_ns()}"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
            
        os.replace(temp_path, target_path)
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise e
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, güvenlik yazılımında yarım iş olmaz! Kurallarının yarısı yazılmış bir güvenlik duvarı, kilidi sökülmüş bir çelik kapıdan farksızdır. Doğrudan kural dosyasına yazmak intihardır. Önce kenarda geçici dosyanı eksiksiz inşa edeceksin, `fsync` ile çivi gibi diske çakacaksın, sonra tek bir atomik hamleyle (`os.replace`) hedefi güncelleyeceksin. Fişi çekseler bile sistemin dimdik ayakta kalacak!"
