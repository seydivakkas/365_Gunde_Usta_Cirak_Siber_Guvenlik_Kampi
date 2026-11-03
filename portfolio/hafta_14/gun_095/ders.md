# Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Mimarisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu ders notu yalnızca görüntüleme ve kişisel eğitim amacıyla paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya ticari amaçla kullanılamaz.*

---

## 1. Usta Girişi: Güvenlikte Performans Neden Hayatidir?

Evlat, acemi güvenlikçiler performansı yalnızca yazılımcıların ve veritabanı yöneticilerinin sorunu zanneder. *"Biz güvenliğe bakarız, hız yazılımcının işi"* derler. Bu, siber güvenlikte yapılabilecek en ölümcül yanılgılardan biridir!

Gerçek dünyayı düşün:
- Bir **SIEM log toplayıcısı** saniyede 50.000 olay (event) almaktadır. Eğer yazdığın ayrıştırıcı (parser) veya DLP maskeleme betiği bir satırı 1 milisaniyede değil de 3 milisaniyede işlerse, log kuyruğu dakikalar içinde şişer, bellek tükenir ve sistem gelen yeni logları düşürmeye (drop) başlar. Saldırganın tam o anda içeri sızdığını düşün; saldırı logları kuyruk dolduğu için yok olur!
- Bir **WAF veya IDS kuralı** her HTTP isteğini denetler. Eğer regex ifaden katastrofik geri izleme (ReDoS - CWE-1333) yüzünden 10 saniye kilitlenirse, tüm web sunucusu yanıt veremez hale gelir. Güvenlik aracı bizzat bir DoS (CWE-400) aracına dönüşür.
- **Kriptografik Zamanlama Saldırıları (Timing Attacks - CWE-208):** Bir karşılaştırma fonksiyonunun çalışma süresi ile girdi verisi arasında mikrosaniyelik bir ilişki varsa, saldırgan ağ üzerinden süreleri ölçerek parolayı veya anahtarı bayt bayt deşifre edebilir.

İşte bu yüzden bir güvenlik mühendisi, yazdığı her savunma aracının, her denetim betiğinin ne kadar süre harcadığını, ne kadar CPU yaktığını ve belleği nasıl tükettiğini ölçmek, profillemek ve güvenceye almak zorundadır.

---

## 2. Zamanı Ölçmenin İncelikleri: Doğru Sayacı Seçmek

Python'da veya herhangi bir sistem dilinde zaman ölçerken acemilerin yaptığı ilk hata `time.time()` kullanmaktır.

### `time.time()` Neden Güvenlik Ölçümlerinde Kullanılamaz?
1. **NTP Güncellemeleri ve Saat Atlamaları:** `time.time()` sistem duvar saatini (wall-clock time) okur. Eğer işletim sistemi tam ölçüm anında NTP (Network Time Protocol) sunucusuyla senkronize olup saati 2 saniye ileri veya geri alırsa, ölçümünüz negatif çıkabilir veya tamamen sapar!
2. **Düşük Çözünürlük:** Özellikle Windows platformlarında `time.time()` çözünürlüğü yaklaşık 15.6 milisaniyedir. Mikrosaniye düzeyindeki bir hash fonksiyonunu bu sayaçla asla ölçemezsiniz.

### Doğru Sayaçlar:
- **`time.perf_counter()` (Yüksek Çözünürlüklü Monotonik Sayaç):**
  - Donanımın TSC (Time Stamp Counter) veya HPET sayaçlarını kullanır.
  - Kesinlikle geri gitmez (monotoniktir), sistem saat değişikliklerinden etkilenmez.
  - İş parçacığının beklemeleri, I/O gecikmeleri ve kilitler dahil olmak üzere **toplam geçen gerçek duvar süresini (wall time)** nanometrik hassasiyetle ölçer.
- **`time.process_time()` (Süreç CPU Saati):**
  - Yalnızca geçerli sürecin (process) CPU çekirdeğinde harcadığı aktif hesaplama süresini ölçer.
  - Disk okuma, ağ beklemesi veya `time.sleep()` gibi beklemeleri saymaz. Bir algoritmanın saf işlemci yükünü analiz etmek için mükemmeldir.

---

## 3. Isınma Döngüsü (Warmup) ve İstatistiğin Gücü

Bir fonksiyonu bir kez çalıştırıp *"bu fonksiyon 2.4 ms sürüyor"* demek bilimsel olarak geçersizdir evlat.

### Neden Isınma (Warmup) Şarttır?
1. **CPU Önbelleği (L1/L2/L3 Cache):** İlk çalıştırmada kod ve veriler RAM'den çekilir (Cache Miss). Sonraki çalıştırmalarda CPU önbelleğinden hızlıca gelir.
2. **Python Baytkod ve Modül Yüklemesi:** İlk çağrıda fonksiyon çerçevesi (frame), global değişkenler ve yerel simgeler çözümlenir.
3. **İşletim Sistemi Zamanlayıcısı (OS Jitter):** Tam ilk çalıştırma anında arka planda bir antivirüs taraması veya OS kesmesi (interrupt) tetiklenmiş olabilir.

Bu yüzden ölçüm motorumuz **önce 2-3 ısınma döngüsü** koşturur, bu döngüleri çöpe atar; ardından asıl ölçümleri başlatır.

### Ortalama Neden Yalan Söyler? Persentil (p95, p99) Mimarisi
Eğer 100 çalıştırmanın 99'u 1 ms, 1 tanesi 1000 ms (1 saniye) sürerse:
- Ortalama: $\approx 11 \text{ ms}$ görünür. Bu rakam ne 1 ms'yi yansıtır ne de 1000 ms'lik felaketi!
- **Medyan (p50):** $1 \text{ ms}$ (merkezi eğilimi gösterir).
- **p95 / p99 (Kuyruk Gecikmesi - Tail Latency):** En kötü $\%5$ ve $\%1$'lik dilimdeki kullanıcıların veya logların ne kadar beklediğini gösterir. Bir saldırgan sistemin zayıf anını yakalamak için kuyruk gecikmesini istismar eder. Güvenlik SLA'ları (Hizmet Seviyesi Anlaşması) her zaman **p99 persentili** üzerinden denetlenir!

---

## 4. Bellek Profilleme: `tracemalloc` ile Bellek Tavanı

Zaman tek maliyet değildir; bellek tükenmesi sistemleri çökerten birincil etkendir (**CWE-401 / CWE-400**).
Python'un yerleşik `tracemalloc` kütüphanesi, interpreter seviyesinde tahsis edilen her baytlık bloğu izler:
```python
tracemalloc.start()
tracemalloc.reset_peak()
# ... Güvenlik işlevi yürütülür ...
current_bytes, peak_bytes = tracemalloc.get_traced_memory()
tracemalloc.stop()
```
Bu sayede bir fonksiyonun çalışırken RAM'de ne kadarlık bir tepe noktası (peak) oluşturduğunu kesin olarak tespit ederiz.

---

## 5. Siber Güvenlik Optimizasyon Örnekleri

Dersimizin pratik laboratuvarında şu üç kritik güvenlik senaryosunu karşılaştırdık:

1. **SHA-256 vs BLAKE2b:**
   - SHA-256 endüstri standardıdır ancak 32-bit işlemler üzerine kuruludur.
   - BLAKE2b, modern 64-bit işlemci mimarilerinde SHA-256'ya göre belirgin şekilde daha hızlı çalışır ve SHA-3 seviyesinde kriptografik güvenlik sunar.
2. **Log Birleştirmede `+` (String Concat) vs `List.join()`:**
   - Python'da dizeler değiştirilemez (immutable) nesnelerdir. Her `s += line` çağrısında yeni bir bellek bloğu açılır ve eski veri kopyalanır ($O(n^2)$ bellek kopyalama maliyeti).
   - `"".join(liste)` ise toplam boyutu baştan hesaplar ve tek seferde tahsis eder ($O(n)$ hız ve minimum tepe bellek).
3. **Derlenmiş Regex (`re.compile`) vs Dinamik Arama:**
   - Her log satırında `re.search()` çağırmak, içsel regex önbelleği dolsa bile ayrıştırma (parsing) yükü bindirir.
   - Önceden derlenmiş desen (`COMPILED_PATTERN.search()`) üretim log hatlarında ciddi CPU tasarrufu sağlar.

---

## 6. Ustanın Çırağa Öğütleri

1. **Ölçmediğin Şeyi İyileştiremezsin:** Tahminlerle kod optimize edilmez. *"Burası yavaş gibi duruyor"* diyerek karmaşık kodlar yazma. Önce profilleyiciyi bağla, darboğazın (bottleneck) nerede olduğunu sayılarla kanıtla.
2. **Performans Bütçesi (Performance Budget) Belirle:** Güvenlik middleware'lerine her zaman bir bütçe koy (örneğin: *"Her istek doğrulaması en fazla 5 ms sürebilir"*). Bütçeyi aşan durumlarda sistemin sessizce şişmesine izin verme; derhal alarm (`PerformanceBudgetExceededError`) üret.
3. **Premature Optimization (Erken Optimizasyon) Tuzağına Düşme:** Önce kodu güvenli, okunabilir ve sağlam yaz. Ardından darboğaz oluşturan kritik yolları (hot path) optimize et.
