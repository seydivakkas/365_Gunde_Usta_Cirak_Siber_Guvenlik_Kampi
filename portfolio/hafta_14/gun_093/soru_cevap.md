# GÜN 093: Hashlib ile Dosya Doğrulama — Mülakat ve Saha Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap seti yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz paylaşılamaz veya çoğaltılamaz.*

---

## SORU 1: Akış Tabanlı (Chunk-based) Hash Hesaplama Neden DoS Zafiyetlerini (CWE-400) Engeller?

### 1. Soru Başlığı ve Tanımı
Büyük dosyaların (adli disk imajları, sanal makine diskleri, ISO dosyaları) kriptografik özetini hesaplarken `file.read()` ile tek seferde okumak yerine neden 64 KB'lık akış blokları (chunk streaming) kullanılmalıdır? Bellek yönetimi ile hizmet reddi (DoS - CWE-400) arasındaki ilişki nedir?

### 2. Derinlemesine Teknik Analiz
İşletim sistemlerinde süreçlerin (process) kullanabileceği sanal bellek fiziksel RAM ve takas (swap) alanı ile sınırlıdır.
- Bir Python sürecinde `f.read()` çağrıldığında, dosyanın tüm bayt dizisi (örneğin 20 GB'lık bir `evidence.raw` adli bilişim imajı) tek bir `bytes` nesnesi olarak RAM'e kopyalanmaya çalışılır.
- Bu durum belleğin ani tükenmesine (**Memory Exhaustion / CWE-400**) neden olur. İşletim sisteminin OOM Killer (Out-of-Memory Killer) mekanizması süreci derhal sonlandırır (`SIGKILL` / Exit Code 137).
- Saldırganlar, bir dosya yükleme veya denetim servisine gigabaytlarca büyüklükte yapay dosyalar yükleyerek güvenlik denetleyicisini çökertebilir.

Akış tabanlı (chunk-based streaming) yaklaşımda ise dosya diski bloke etmeden sabit boyutlu tamponlar (örneğin $64\text{ KB} = 65536\text{ bayt}$) halinde okunur ve doğrudan `hasher.update(tampon)` fonksiyonuna beslenir:
- Bellek karmaşıklığı dosya boyutundan ($N$) bağımsız olarak sabit kalır: $\mathcal{O}(1)$ RAM tüketimi.
- Dosya terabaytlarca büyüklükte olsa dahi işlemci ve bellek kaynakları dengeli kullanılır, DoS riski sıfırlanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Adli bilişim laboratuvarında 500 GB'lık disk imajının SHA-256 özetini bellek şişmesi yaşamadan hesaplayan fonksiyon:

```python
import hashlib

def compute_large_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Akış tabanlı güvenli SHA-256 hesaplayıcı."""
    hasher = hashlib.sha256()
    
    with open(file_path, "rb") as fp:
        while True:
            chunk = fp.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            
    return hasher.hexdigest()
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, kodunda `with open(...) as f: data = f.read()` yazıp ardından hash almaya kalktığın an, kendi ayağına DoS bombası bağlıyorsun demektir. Bellek sınırlıdır ama matematik sınırsızdır. 64 KB'lık küçük kaşıklarla koca okyanusu boşaltabilirsin; sakın tek lokmada yutmaya kalkma, boğulursun."

---

## SORU 2: MD5 ve SHA-1 Algoritmaları Neden Kriptografik Olarak Kırılmıştır ve Çarpışma Saldırısı (CWE-328) Nedir?

### 1. Soru Başlığı ve Tanımı
Güvenlik camiasında MD5 ve SHA-1 neden "kriptografik olarak kırılmış" (broken) kabul edilir? Çarpışma Saldırısı (Collision Attack - CWE-328) ile Ön-görüntü Direnci (Pre-image Resistance) arasındaki fark nedir ve bu zafiyet gerçek dünyada nasıl istismar edilmiştir?

### 2. Derinlemesine Teknik Analiz
Bir kriptografik özet fonksiyonunun güvenli sayılması için 3 matematiksel şartı sağlaması gerekir:
1. **Tek Yönlülük (Pre-image Resistance):** Verilen bir $H$ özetinden $M$ mesajını bulmak imkansız olmalıdır ($2^{256}$ karmaşıklık).
2. **İkinci Ön-görüntü Direnci (Second Pre-image Resistance):** Verilen bir $M_1$ için aynı özeti veren $M_2$ bulmak imkansız olmalıdır ($H(M_1) = H(M_2)$).
3. **Çarpışma Direnci (Collision Resistance):** Rastgele iki farklı mesajın ($M_1 \ne M_2$) aynı özeti üretmesi matematiksel olarak imkansız olmalıdır. Doğum günü paradoksu (Birthday Attack) nedeniyle bu direnç teorik olarak $2^{n/2}$ dir.

**Kırılma Süreci (CWE-328):**
- **MD5 (128-bit):** 2004 yılında Xiaoyun Wang ve ekibi diferansiyel analizle çarpışma direncini kırdı. 2012 yılında Flame casus yazılımı, meşru bir Microsoft Windows Update kod imzalama sertifikasının MD5 özetini sahte bir sertifikayla çarpıştırarak milyonlarca sisteme meşru güncelleme gibi sızdı.
- **SHA-1 (160-bit):** 2017 yılında CWI Amsterdam ve Google, **SHAttered** saldırısıyla iki farklı içeriğe sahip PDF dosyasının aynı SHA-1 özetini üretmesini sağladı ($2^{63}$ hesaplama maliyetiyle).

Bu nedenle, iki dosyanın MD5 veya SHA-1 özetlerinin aynı olması, dosyaların aynı içeriğe sahip olduğunu artık kanıtlamaz! Saldırgan biri zararsız, diğeri kötü amaçlı iki dosya üretip aynı özeti verecek şekilde manipüle edebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Katı modda zayıf algoritmaları engelleyen ve SHA-2 / BLAKE2b standardını zorlayan kontrol mekanizması:

```python
ALLOWED_HASH_ALGORITHMS = frozenset({"sha256", "sha512", "sha3_256", "blake2b"})

def enforce_cryptographic_algorithm(algo_name: str) -> str:
    cleaned = algo_name.strip().lower()
    if cleaned in ("md5", "sha1"):
        raise ValueError(
            f"Zafiyet Engellendi: '{cleaned}' algoritması çarpışma saldırılarına karşı kırıktır (CWE-328). "
            f"Kurumsal sistemlerde sha256 veya blake2b kullanımı zorunludur."
        )
    if cleaned not in ALLOWED_HASH_ALGORITHMS:
        raise ValueError(f"Desteklenmeyen algoritma: {cleaned}")
    return cleaned
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, sahada bazı eski sistemlerin hala 'hızlı olsun diye MD5 kullanıyoruz' dediğini duyacaksın. Onlara Flame yazılımını ve SHAttered saldırısını hatırlat. Hız güvenlikten ödün verilerek kazanılıyorsa, o hız felakete daha çabuk koşmaktan başka bir işe yaramaz. Modern BLAKE2b algoritması MD5'ten bile daha hızlıdır ve kriptografik olarak kurşun geçirmezdir."

---

## SORU 3: Hash Karşılaştırmasında Neden `==` Değil de `hmac.compare_digest` Kullanılmalıdır (CWE-208)?

### 1. Soru Başlığı ve Tanımı
İki kriptografik özet değerini karşılaştırırken standart string eşitliği (`hash1 == hash2`) yerine neden `hmac.compare_digest(hash1, hash2)` kullanılmalıdır? Yan Kanal Zamanlama Saldırısı (Side-Channel Timing Attack - CWE-208) nedir ve nasıl bertaraf edilir?

### 2. Derinlemesine Teknik Analiz
Standart string karşılaştırma algoritmaları (Python, C, Java) performans optimizasyonu amacıyla **Kısa Devre Değerlendirmesi (Short-circuit Evaluation)** yapar:
- Karşılaştırma en soldaki ilk karakterden başlar.
- Karakterler eşleştiği sürece döngü devam eder.
- Eşleşmeyen ilk karakterle karşılaşıldığı anda döngü durur ve `False` döndürülür.

**Saldırı Senaryosu (CWE-208):**
Hedef sunucu bir dosyanın veya gizli bir API belirtecinin SHA-256 özetini doğrulamaktadır.
1. Saldırgan ilk karakteri `0` olarak tahmin edip dener. Eşleşmezse sunucu 5 mikrosaniyede `False` döner.
2. Saldırgan ilk karakteri `a` yapar. Eğer ilk karakter doğruysa sunucu ikinci karaktere geçer ve işlem 7 mikrosaniyede biter.
3. Aradaki 2 mikrosaniyelik farkı ağ üzerinden ölçen istatistiksel bir saldırgan (Box-Cox analizi ve tekrarlı isteklerle), ilk karakterin `a` olduğunu anlar.
4. Bu işlemi sırasıyla 64 karakter için tekrarlayarak hash değerini bayt bayt yeniden inşa eder (**Timing Attack**).

**Çözüm: Sabit Zamanlı Karşılaştırma (`hmac.compare_digest`):**
`hmac.compare_digest` fonksiyonu, ilk karakter hatalı olsa dahi dizgenin sonuna kadar XOR işlemi yaparak döngüyü tamamlar ve tüm karşılaştırmayı tam olarak **sabit bir sürede ($O(N)$)** bitirir. Saldırgana hiçbir zamanlama ipucu sızdırılmaz.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bütünlük doğrulamasında zamanlama saldırılarına dirençli karşılaştırma:

```python
import hmac

def timing_safe_hash_verify(computed_hash: str, expected_hash: str) -> bool:
    """Zamanlama saldırılarına karşı sabit sürede çalışan güvenli hash doğrulayıcı."""
    # Uzunlukları ve karakterleri güvenli sabit zamanda karşılaştır
    return hmac.compare_digest(computed_hash.lower(), expected_hash.lower())
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, hackerlar sadece ön kapıyı kırmaz; kapının gıcırtısını, lambanın saniyelik titreşimini bile dinlerler. Mikro saniyeler seviyesinde sızan zaman farkı, en güçlü şifreleri bile kağıttan kaleye çevirir. Kriptografide eşitlik ararken her zaman `compare_digest` kullanacaksın. Sessiz ve sabit adımlarla yürüyeceksin."
