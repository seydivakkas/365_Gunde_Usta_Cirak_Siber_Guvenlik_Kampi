# Gün 105: Mini Proje 14 — Soru ve Cevaplar
## Usta-Çırak Kriptografik FIM ve Bütünlük Doğrulama Mülakatı

---

### Soru 1: FIM Sistemlerinde "Mühürsüz Manifest Zafiyeti" (CWE-353) Nedir ve Nasıl Savunulur?

#### 1. Soru Başlığı ve Tanımı
Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM) yazılımlarında sıkça yapılan kritik mimari hata; dosya adları, boyutları ve hash özetlerinin düz metin (veya ham JSON/YAML) olarak aynı sunucu veya dizin içinde mühürsüz saklanmasıdır. Bu durum neden kritik bir zafiyettir (CWE-353) ve kriptografik açıdan nasıl bertaraf edilir?

#### 2. Derinlemesine Teknik Analiz
Eğer bir saldırgan hedef sunucuda ayrıcalık yükselterek (veya dosya yazma yetkisi elde ederek) `/var/www/html/app.py` dosyasını arka kapılı (trojanized) bir sürümle değiştirirse, sistemde çalışan FIM aracının veri tabanını veya manifest dosyasını da inceleyebilir.
Manifest dosyası şifresiz ve imzasızsa:
1. Saldırgan değiştirdiği `app.py` dosyasının yeni SHA-256 özetini hesaplar:
   $$\text{Hash}_{\text{yeni}} = \text{SHA-256}(\text{app\_trojan.py})$$
2. `manifest.json` dosyasını açıp eski hash yerine bu yeni değeri yazar.
3. FIM doğrulama servisi çalıştığında diskteki dosyanın hash'i ile manifestodaki hash'i eşleştirir ve `PASS` (Bütünlük Bozulmamış) sonucunu üretir. Bu durum tam bir güvenlik kör noktasıdır.

Kriptografik savunma yöntemi: Manifest içeriğinin kanonik biçimde (sıralı anahtarlar, deterministik JSON) serileştirilmesi ve bağımsız bir gizli anahtar ($K_{\text{seal}}$) ile **HMAC-SHA256** özetinin hesaplanarak `integrity_seal` başlığı altında saklanmasıdır:
$$\text{Seal} = \text{HMAC-SHA256}(K_{\text{seal}}, \text{Canonical}(\text{Manifest}_{\text{body}}))$$
Saldırgan $K_{\text{seal}}$ değerine erişemediği sürece (anahtar HSM, Vault veya uzak izleme sunucusunda saklandığından), manifestoyu değiştirdiğinde mühür geçersiz kalacak ve FIM anında sabotaj alarmı üretecektir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret şirketinin ödeme işleme sunucusuna `admin` şifresinin sızdırılmasıyla erişen saldırgan, kredi kartı bilgilerini harici bir sunucuya kopyalayan zararlı kodu `checkout_engine.php` içine enjekte eder. Sunucuda yerel çalışan AIDE/Tripwire benzeri bir bash betiği vardır ancak hash listesi yerel disktedir. Saldırgan `aide.db` dosyasını güncelleyerek denetimden kaçar.

**Pratik Çözüm:**
1. Manifest üretim aşamasında `hash_manifest_engine.py` ile HMAC mührü üretilir:
   ```python
   # Manifest içeriği deterministik sıralanarak mühürlenir
   body_bytes = json.dumps(manifest_body, sort_keys=True).encode("utf-8")
   seal = hmac.new(seal_key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
   ```
2. Mühür anahtarı yerel diskte tutulmaz; yalnızca doğrulama yapan merkezi SIEM/SOC ajanına RAM üzerinden enjekte edilir.
3. Doğrulama sırasında `hmac.compare_digest` kullanılarak zamanlama analizi (CWE-208) engellenir.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, mühürsüz bir hash listesi, kilidi olmayan bir çelik kasaya benzer. Saldırgana 'seni izliyorum ama kontrol listeni senin değiştirmene izin veriyorum' demiş olursun. Bir dosyanın bütünlüğünü denetlerken, denetim listesinin kendi bütünlüğünü ve kaynağını kime emanet ettiğini asla aklından çıkarma!"

---

### Soru 2: Büyük Dosyalarda Akışlı Hashing (Streaming) Neden Zorunludur ve CWE-400 ile İlişkisi Nedir?

#### 1. Soru Başlığı ve Tanımı
Python'da dosya hash'i alırken `hashlib.sha256(open(dosya, "rb").read()).hexdigest()` yazmak neden büyük bir güvenlik ve performans hatasıdır? Bu yaklaşım CWE-400 (Resource Exhaustion / OOM DoS) zafiyetine nasıl yol açar?

#### 2. Derinlemesine Teknik Analiz
Python'da `read()` fonksiyonu argümansız çağrıldığında, dosyanın tamamını tek bir bayt dizisi (`bytes` nesnesi) olarak işletim sisteminden heap belleğe kopyalar.
- Eğer taranan dizin içinde bir veri tabanı yedeği (örn. `dump.sql` - 16 GB) veya büyük bir sanal makine imajı (`disk.qcow2` - 60 GB) varsa:
  1. Python işlemi 16-60 GB fiziksel bellek talep eder.
  2. Sistemde yeterli RAM yoksa `MemoryError` fırlatılır veya Linux çekirdeğinin OOM Killer servisi kritik güvenlik sürecini anında öldürür (`SIGKILL`).
  3. Bu durum saldırganın kasıtlı olarak büyük bir dosya bırakıp FIM aracını devre dışı bırakmasıyla (DoS - CWE-400) sonuçlanır.

Akışlı (streaming) blok hash yaklaşımında bellek karmaşıklığı $O(N)$ seviyesinden $O(1)$ seviyesine düşürülür:
```python
# Sabit 64 KB bellek tamponu (Sabit bellek alanı)
CHUNK_SIZE = 64 * 1024  # 65536 bayt
with open(filepath, "rb") as f:
    while chunk := f.read(CHUNK_SIZE):
        hasher.update(chunk)
```
Bu mimariyle dosya boyutu 1 TB dahi olsa, RAM tüketimi asla 64 KB'ı aşmaz.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir SOC analiz merkezinde şüpheli dosya yüklemelerini tarayan bir FIM/antivirüs ayrıştırıcı servisi çalışmaktadır. Saldırgan `sparse file` veya içi sıfırlarla dolu 10 GB'lık `log.txt` yükler. İlkel `f.read()` kullanan FIM servisi sunucunun tüm RAM'ini tüketerek SOC merkezinin analiz yeteneğini kilitler.

**Pratik Çözüm:**
1. `hash_manifest_engine.py` içinde dosya okumaları kesinlikle `BUFFER_SIZE_BYTES = 65536` ile sınırlandırılır.
2. Motor düzeyinde maksimum izin verilen dosya boyutu tavanı belirlenir (örneğin CLI parametresi `--max-file-mb 500`). Bu sınırı aşan anormal dosyalar karantinaya alınır ve `FileTooLargeError` fırlatılır.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, bellek bilgisayarın en kutsal ve pahalı kaynağıdır. Bir yazılımın zarafeti, gigabaytlarca veriyi avucundaki bir bardak su (64 KB) kadar bellek harcayarak sakin ve kararlı biçimde işleyebilmesinde yatar. Asla tembellik edip dosyanın tamamını tek nefeste belleğe çekme!"

---

### Soru 3: FIM Motorlarında Dizin Aşımı (Path Traversal) ve Sembolik Bağ (Symlink) Kaçışları Nasıl Gerçekleşir?

#### 1. Soru Başlığı ve Tanımı
Bir FIM aracı bağıl dosya yollarını (`relative paths`) işlerken saldırganlar sembolik bağlar (`symlinks`) veya `../` dizin manipülasyonları kullanarak kök dizinin dışındaki hassas dosyalara nasıl erişebilir (CWE-22 & CWE-59)? Bu atak vektörleri kriptografik manifestoları nasıl zehirler?

#### 2. Derinlemesine Teknik Analiz
Bir manifest dosyası tipik olarak projenin kök dizinine göre bağıl yolları listeler:
```json
{
  "files": {
    "src/app.py": { "sha256": "..." },
    "config/db.conf": { "sha256": "..." }
  }
}
```
Eğer doğrulama motoru hedef yolu birleştirirken yalnızca basit bir string birleştirme yaparsa (`os.path.join(root_dir, rel_path)`):
1. Saldırgan manifestoya `../../../../etc/shadow` veya `..\\..\\Windows\\System32\\config\\SAM` ekleyebilir (CWE-22).
2. Ya da proje dizini içine bir sembolik bağ oluşturur: `ln -s /etc/shadow ornek_veri/sample_project_tree/leak.txt` (CWE-59).
3. Motor `safe_resolve_path` kontrolü yapmıyorsa, yetkisiz dosyanın hash'ini hesaplayıp manifestoya yazar veya doğrulama sırasında dosyanın varlığını teyit ederek dışarıya adli bilgi sızdırır.

Kapsamlı Savunma:
```python
def safe_resolve_path(root_dir: str, rel_path: str) -> str:
    # 1. Ham yolda şüpheli symlink / traversal anahtar kelimeleri taranır
    raw_joined = os.path.join(root_dir, rel_path)
    if os.path.islink(raw_joined):
        raise SymlinkEscapeError("Sembolik bağ tespiti - Kök dışı kaçış engellendi.")
    
    # 2. Kanonik mutlak yol çözümlenir (symlink ve ../ çözülür)
    abs_root = os.path.abspath(root_dir)
    target_abs = os.path.abspath(raw_joined)
    
    # 3. Hedef yolun kesinlikle kök dizin altında kaldığı doğrulanır
    if not target_abs.startswith(abs_root + os.sep) and target_abs != abs_root:
        raise PathTraversalError("Dizin aşımı engellendi: Kök dizin sınırları ihlal edildi.")
    return target_abs
```

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir CI/CD pipeline'ında açık kaynaklı bir kütüphanenin derleme manifestosu otomatik taranmaktadır. Kötü niyetli bir geliştirici pull request içinde `tests/fixtures/sample_key -> /root/.ssh/id_rsa` sembolik bağını eklemiştir. FIM aracı bu bağı takip ederek özel SSH anahtarının hash'ini manifestoya döker ve derleme loglarında yayınlar.

**Pratik Çözüm:**
Motorumuz sembolik bağları (`os.path.islink`) doğrudan reddeder. Dosya sisteminde sembolik bağ tespit edildiğinde derleme boru hattı anında durdurulur ve güvenlik ekiplerine `SymlinkEscapeError (CWE-59)` alarmı iletilir.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, dosya yolları kullanıcının veya dosya sisteminin elinde birer silaha dönüşebilir. Sana sunulan yol ne kadar masum görünürse görünsün, onu kanonik gerçeğine (`os.path.abspath`) indirgemeden ve kendi belirlediğin kök hapishanesinin (chroot/sandbox) içinde kaldığını kanıtlamadan asla disk operasyonuna izin verme!"
