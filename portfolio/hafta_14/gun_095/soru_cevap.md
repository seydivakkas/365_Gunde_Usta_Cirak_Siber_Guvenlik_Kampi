# GÜN 095: Güvenlik Betikleri Performans Ölçümü — Mülakat ve Uzmanlık Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap dokümanı performans mühendisliği, SOC otomasyonu ve siber güvenlik mimarisi mülakatlarına hazırlık için pedagojik olarak yapılandırılmıştır.*

---

## SORU 1: Güvenlik Fonksiyonlarında Duvar Saati (Wall Time) ve CPU Saati (Process Time) Ayrımı ile Sayaç Seçimi

### 1. Soru Başlığı ve Tanımı
Bir güvenlik betiğinin performansını analiz ederken Duvar Saati (Wall Time / `time.perf_counter`) ile Süreç CPU Saati (Process Time / `time.process_time`) arasındaki teknik fark nedir? Kriptografik işlemler veya log ayrıştırma görevlerinde neden `time.time()` yerine yüksek çözünürlüklü monotonik sayaçlar kullanılmalıdır?

### 2. Derinlemesine Teknik Analiz
Performans ölçümünde kullanılan zaman sayaçları işletim sisteminin farklı alt sistemlerine dayanır:

1. **`time.time()` (Real-time Clock / Epoch Time):**
   - Unix epoch (1 Ocak 1970) başlangıcından bu yana geçen süreyi temsil eder.
   - Sistem yöneticisi saati değiştirdiğinde veya arka planda NTP (Network Time Protocol) zaman senkronizasyonu devreye girdiğinde ileri veya geri sıçrayabilir.
   - Monotonik değildir; iki ölçüm arasındaki fark negatif çıkabilir. Windows ortamlarında zaman çözünürlüğü yaklaşık 15.6 milisaniye gibi oldukça kabadır.
2. **`time.perf_counter()` (Monotonic Wall Time):**
   - Donanımın yüksek frekanslı sayaçlarını (TSC - Time Stamp Counter veya ACPI/HPET) okur.
   - Kesinlikle tek yönlü ilerler (monotoniktir), sistem saati değişikliklerinden etkilenmez.
   - Sürecin I/O beklemeleri, kilit (mutex/lock) beklemeleri ve işletim sistemi uyku süreleri dahil olmak üzere **gerçek dünyada geçen tam süreyi** nanometrik hassasiyetle ölçer.
3. **`time.process_time()` (CPU Time):**
   - Sürecin yalnızca CPU çekirdeğinde aktif kod yürüttüğü süreyi (kullanıcı + çekirdek modu CPU süresi) ölçer.
   - Ağdan paket bekleme, diskten dosya okuma veya `time.sleep()` sırasındaki boşta bekleme sürelerini sayaca dahil etmez.

Eğer bir kriptografik algoritmanın saf hesaplama karmaşıklığını ölçecekseniz `process_time` kullanılır; ancak bir SIEM pipeline'ının veya ağ paket yakalama filtresinin gerçek gecikmesini ölçecekseniz `perf_counter` kullanılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankanın API ağ geçidinde JWT imza doğrulama süresi ölçülmektedir. Geliştirici `time.time()` kullanarak süreleri loglamaktadır. Gece yarısı NTP sunucusu saat senkronizasyonu yaptığında bir imza doğrulama süresi `-0.89 saniye` olarak kaydedilmiş, bu anormallik izleme sisteminde yanlış alarmlara yol açmıştır.

**Pratik Çözüm:**
Kod tabanındaki tüm performans ölçümleri `time.perf_counter()` ile güncellenmiştir:
```python
t_start = time.perf_counter()
verify_jwt_signature(token)
duration_ms = (time.perf_counter() - t_start) * 1000.0
```
Böylece saat ayarlamalarından bağımsız, nanosaniye hassasiyetinde ve monotonik doğruluk elde edilmiştir.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, saniye ölçen saatle mikrosaniyelik kripto hesabı yapılmaz. `time.time()` insanlara saatin kaç olduğunu söylemek içindir; kodun ne kadar sürdüğünü ölçmek için değil. Güvenlik analizinde süreyi ölçeceksen elin doğrudan `perf_counter()` fonksiyonuna gitmelidir.

---

## SORU 2: Dağıtık Güvenlik Sistemlerinde Kuyruk Gecikmesi (Tail Latency) ve p99 Persentil Analizi

### 1. Soru Başlığı ve Tanımı
Bir güvenlik altyapısının (örneğin WAF, DLP veya SIEM) performans değerlendirmesinde neden "ortalama süre" (mean latency) yanıltıcı bir metriktir? Kuyruk Gecikmesi (Tail Latency) nedir ve güvenlik SLA bütçelerinde neden 95. (p95) ve 99. (p99) persentil metrikleri esas alınır?

### 2. Derinlemesine Teknik Analiz
Ortalama (aritmetik ortalama), tüm ölçümlerin toplamının ölçüm sayısına bölünmesidir. İstatistikte ortalama, uç değerlere (outliers) karşı aşırı hassastır ve dağılımın şeklini gizler:
- Örneğin bir WAF motoruna gelen 10.000 isteğin 9.900 tanesi 1 ms'de işlenirken, 100 tanesi (belirli karmaşık regex veya kötücül yükler yüzünden) 500 ms sürsün.
- Ortalama süre: $\approx 5.9 \text{ ms}$ çıkar. Bu değer yönetime sunulduğunda *"Sistemimiz 6 ms'de çalışıyor, harika!"* denilebilir.
- Oysa gerçekte her 100 kullanıcıdan 1 tanesi yarım saniye beklemekte veya zaman aşımına (timeout) uğramaktadır!

İşte bu gizlenen en kötü durum dilimine **Kuyruk Gecikmesi (Tail Latency)** denir:
- **p95 Persentili:** Gelen isteklerin $\%95$'inin bu sürenin altında tamamlandığını, en yavaş $\%5$'lik kısmın bu süreyi aştığını gösterir.
- **p99 Persentili:** En yavaş $\%1$'lik dilimin sınırıdır.
Mikroservis mimarilerinde tek bir kullanıcı isteği arka planda 20 farklı güvenlik servisini tetikleyebilir. Eğer her servisin p99 gecikmesi yüksekse, ana kullanıcının yavaşlığa çarpma olasılığı katlanarak artar ($1 - 0.99^{20} \approx \%18$). Yani neredeyse her 5 kullanıcıdan biri felç olur!

Saldırganlar DoS veya kaynak tüketme saldırılarında (CWE-400) tam olarak bu p99 kuyruğundaki zayıf noktaları hedef alırlar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SOC ekibinde log zenginleştirme servisi için SLA hedefi belirlenmiştir: "Loglar ortalama 10 ms altında zenginleştirilecek." Ancak haftalık denetimde bazı fidye yazılımı alarmlarının SIEM'e 45 saniye geç ulaştığı görülür. İncelemede servisin p99 gecikmesinin 40 saniye olduğu anlaşılır; ortalama ise normal logların çokluğu nedeniyle 8 ms görünmektedir.

**Pratik Çözüm:**
Performans profilleme motoruna persentil kontrolü ve sıkı SLA kapısı eklenir:
```python
result = run_benchmark(enrich_log_func, iterations=1000)
if result.p99_wall_ms > 50.0:  # 50 ms p99 SLA sınırı
    raise PerformanceBudgetExceededError(f"p99 SLA ihlali: {result.p99_wall_ms} ms")
```
Sistem ortalamaya değil, p99 kuyruğuna göre optimize edilerek darboğazlar giderilmiştir.

### 4. Ustanın Çırağa Tavsiyesi
Bir gölün ortalama derinliği 1 metre olabilir evlat; ama 5 metrelik bir çukur varsa orada boğulursun! Performans ölçerken ortalamaya bakıp rehavete kapılma. Güvenlik analisti her zaman en kötü durumu, yani p99 ve p99.9 persentilini denetler.

---

## SORU 3: Yan Kanal Zamanlama Saldırıları (Timing Attacks - CWE-208) ve Sabit Zamanlı Profilleme

### 1. Soru Başlığı ve Tanımı
Yan Kanal Zamanlama Saldırısı (Side-Channel Timing Attack - CWE-208) nedir? Kriptografik anahtar, parola veya HMAC doğrulamasında erken dönen (early exit) algoritmalar nasıl istismar edilir ve performans ölçüm araçlarıyla bu zafiyet nasıl tespit edilir?

### 2. Derinlemesine Teknik Analiz
Bilgisayar işlemcileri verileri işlerken harcanan süre, yürütülen komut sayısına ve dallanma (branching) tahminlerine bağlıdır. Standart dize veya bayt karşılaştırma operatörleri (`==`, `memcmp`, `strcmp`):
```python
# Standart eşitlik (Savunmasız - Erken Çıkış)
def insecure_compare(a, b):
    if len(a) != len(b): return False
    for x, y in zip(a, b):
        if x != y:
            return False  # İlk uyuşmazlıkta döner!
    return True
```
İlk farklı baytı bulduğu anda döngüyü sonlandırır (Early-Exit).
- Eğer aranan gizli parola `S3CR3T` ise ve saldırgan `A00000` gönderirse: Karşılaştırma 1. karakterde hemen biter (örneğin 120 ns).
- Eğer saldırgan `S00000` gönderirse: Karşılaştırma 1. karakteri geçer, 2. karakterde biter (örneğin 240 ns).
Saldırgan ağ üzerinden binlerce istek gönderip `time.perf_counter_ns()` ile sürelerin istatistiksel dağılımını (ANOVA / t-test) çıkardığında, sürenin biraz daha uzun sürdüğü karakteri bularak parolayı karakter karakter kaba kuvvet (brute-force) ile çözer.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir web uygulamasında API isteklerinin HMAC-SHA256 imzası standart `==` ile doğrulanmaktadır. Güvenlik testlerinde analist, bir benchmark betiği yazarak 10.000 istek koşturur. İlk baytı doğru olan isteklerin ortalama süresinin 15 nanosaniye daha uzun sürdüğünü kanıtlar ve CWE-208 zafiyetini raporlar.

**Pratik Çözüm:**
Tüm hassas doğrulamalarda Python'un `hmac.compare_digest()` fonksiyonu zorunlu kılınır:
```python
import hmac

# Sabit zamanlı (Constant-time) güvenli karşılaştırma
is_valid = hmac.compare_digest(gelen_imza, beklenen_imza)
```
Bu fonksiyon, girdi nerede uyuşmazsa uyuşsun tüm baytları sonuna kadar XOR işlemine tabi tutar ve sabit sürede tamamlanır. Profilleme testinde tüm karakter varyasyonlarının süreleri eşitlenir.

### 4. Ustanın Çırağa Tavsiyesi
Hızlı kod her zaman iyi kod değildir evlat. Güvenlik ve kriptografi dünyasında bazen bilerek yavaşlar veya bilerek sabit sürede kalırız. Erken çıkış (early exit) genel yazılımda performansı artırırken, kriptografide kapıyı saldırgana sonuna kadar açar. Kriptografik doğrulama yapıyorsan her zaman sabit zamanlı (constant-time) kal.
