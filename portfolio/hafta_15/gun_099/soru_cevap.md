# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 099: Soru-Cevap — CIA Triad ve Temel Güvenlik Özellikleri

---

## Soru 1: Bir sistemde salt şifreleme (Encryption) yapmak neden Bütünlük (Integrity) ve Kimlik Doğrulamayı (Authenticity) garanti etmez?

### 1. Soru Başlığı ve Tanımı
Gizlilik sağlayan şifreleme algoritmalarının şekillendirilebilirlik (malleability) özelliği, bit-flip saldırıları ve doğrulanmış şifrelemenin (Authenticated Encryption) zorunluluğu.

### 2. Derinlemesine Teknik Analiz
Pek çok yazılımcı bir veriyi şifrelediğinde (örneğin CBC modunda AES veya CTR modunda akış şifreleyici kullanarak) verinin kurcalanamaz hale geldiğini zanneder. Oysa şifreleme yalnızca **Gizlilik (Confidentiality)** sağlar.

Örneğin, CTR veya CBC modunda çalışan bir şifreli metinde, saldırgan açık metni tam olarak bilmese bile belirli bir baytın konumunu biliyorsa (örneğin bir finansal mesajdaki `TUTAR=0100` alanının yerini), şifreli metnin o baytına XOR tabanlı bir bit-flip uygulayabilir:
$$C' = C \oplus \Delta$$
Alıcı taraf anahtarla şifreyi çözdüğünde:
$$P' = C' \oplus K = (C \oplus \Delta) \oplus K = P \oplus \Delta$$
Sonuç olarak `TUTAR=0100`, alıcı tarafından `TUTAR=9100` olarak çözülür ve alıcı sistem hiçbir hata almadan işlemi yürütür!
Şifrelemenin kurcalanmaya karşı dayanıklı olması için mutlaka bir Mesaj Doğrulama Kodu (HMAC) ile mühürlenmesi (Encrypt-then-MAC yaklaşımı) veya AEAD (GCM modu gibi Authenticated Encryption with Associated Data) mimarisi kullanılması şarttır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankalararası EFT ağında, işlemler şifrelenmiş tüneller üzerinden taşınmaktadır ancak HMAC veya dijital imza kontrolü yapılmamaktadır. Saldırgan araya girerek (MitM) şifreli paketteki alıcı hesap numarasının geçtiği baytları bit-flip tekniğiyle değiştirmiş ve parayı kendi hesabına yönlendirmiştir.

**Çözüm:** `IntegrityGuard.seal_message()` kullanılarak şifreli verinin üzerine HMAC-SHA256 mührü eklenir. Alıcı sistem şifreyi çözmeden önce `IntegrityGuard.verify_seal()` ile mührü sabit zamanlı kontrol eder. 1 bit dahi değişmişse işlem derhal reddedilir (`IntegrityVerificationError`).

### 4. Ustanın Çırağa Tavsiyesi
Evlat, şifreli bir kutuyu açmadan önce kutunun mührüne bakacaksın. Mühürsüz şifre, hırsıza açık bırakılmış çek defteri gibidir; hırsız çekin rengini değiştiremez ama üzerindeki sıfırların sayısını değiştirebilir!

---

## Soru 2: Zamanlama Saldırıları (Timing Attacks - CWE-208) nedir ve kriptografik özet karşılaştırmalarında neden standart `==` işleci kullanılamaz?

### 1. Soru Başlığı ve Tanımı
Kriptografik doğrulamalarda bellek karşılaştırma döngülerinin çalışma süresinden sızan bilgi (Side-Channel Leaks) ve `hmac.compare_digest` fonksiyonunun teknik önemi.

### 2. Derinlemesine Teknik Analiz
Programlama dillerinde iki metin dizgisi karşılaştırılırken performans optimizasyonu amacıyla "kısa devre" (short-circuiting) mantığı uygulanır. C tabanlı `memcmp` veya Python'daki standart `==` işleci baytları soldan sağa teker teker inceler:
```python
# Güvensiz karşılaştırma (CWE-208)
def insecure_compare(a, b):
    if len(a) != len(b): return False
    for x, y in zip(a, b):
        if x != y:
            return False  # İlk uyuşmazlıkta döngü kırılır!
    return True
```
Eğer saldırganın gönderdiği HMAC mührünün ilk baytı doğruysa, işlemci 1 karşılaştırma yapıp çıkar. Eğer ilk 5 baytı doğruysa, işlemci 5 karşılaştırma yapıp çıkar. Bu nanosaniye/mikrosaniye seviyesindeki gecikme farkları yerel ağda ve hatta uzak internet bağlantılarında istatistiksel analizle (P95/P99 ölçümleriyle) ölçülebilir. Saldırgan 256 denemede ilk baytı, sonraki 256 denemede ikinci baytı bulur ve tüm HMAC mührünü brute-force yapmadan rekonstrükte eder!

**Kriptografik Çözüm:** Karşılaştırma her zaman sabit zamanlı (constant-time) olmalıdır:
```python
# Güvenli karşılaştırma (Sabit Zamanlı)
def constant_time_compare(val1, val2):
    return hmac.compare_digest(val1, val2)
```
Bu fonksiyon, veriler uyuşsa da uyuşmasa da dizginin tamamını baştan sona tarar ve her durumda tam olarak aynı sürede yanıt döner.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir web API'sinde webhook çağrılarını doğrulamak için `X-Signature-SHA256` başlığı kontrol edilmektedir. Backend kodu `if request.headers['X-Signature'] == expected_sig:` satırını içermektedir. Güvenlik araştırmacıları yüksek frekanslı istekler ve hassas zamanlama analiziyle gizli webhook imza anahtarını bilmeksizin geçerli imzalar üretmeyi başarmış ve sahte ödeme bildirimleri göndermiştir.

**Çözüm:** Tüm doğrulama mantığında `hmac.compare_digest` kullanılarak zamanlama kanalı tamamen kapatılmıştır. `IntegrityGuard.verify_seal()` bu kuralı zorunlu kılar.

### 4. Ustanın Çırağa Tavsiyesi
Çırağım, güvenlikte sadece sonuca değil, sonuca giderken harcadığın zamana da bakarlar! Saldırgan senin ne düşündüğünü değil, ne kadar süre düşündüğünü ölçerek sırrını çözer. Kriptografide her adımın tek bir ritimde, sabit zamanlı olmalıdır!

---

## Soru 3: Blokzincir tarzı hash-zincirleme (Hash-Chained Logging) mimarisi İnkar Edilemezlik (Non-Repudiation) sağlarken geleneksel Syslog sistemlerine göre hangi üstünlükleri sunar?

### 1. Soru Başlığı ve Tanımı
Geleneksel işletim sistemi loglarının manipülasyon riski, `NonRepudiationAuditor` mimarisinin kriptografik kilitlenme mekanizması ve adli bilişim güvencesi.

### 2. Derinlemesine Teknik Analiz
Standart loglama mekanizmalarında (Syslog, Windows Event Log, dosya bazlı loglar) her kayıt birbirinden bağımsız birer metin satırıdır. Bir saldırgan sisteme sızıp yönetici (root/SYSTEM) yetkisi elde ettiğinde:
1. Log dosyasını doğrudan düzenleyebilir (`nano /var/log/auth.log`).
2. Kendi IP adresini ve gerçekleştirdiği eylemleri içeren satırları silebilir.
3. Arada hiçbir boşluk bırakmadan dosyanın zaman damgalarını (`touch -t`) değiştirebilir.

**Hash-Chained (Kriptografik Zincir) Mimarisi:**
Bu mimaride her blok $B_i$, bir önceki bloğun dijital mührünü ($H_{i-1}$) kendi girdi kümesine dahil eder:
$$H_i = \text{HMAC}_K\Big(H_{i-1} \parallel i \parallel \text{Eylem} \parallel \text{Kullanıcı} \parallel \text{VeriHash} \parallel \text{Zaman}\Big)$$
Bu matematiksel bağımlılık sayesinde:
- Aradan bir kayıt silinirse: $B_{i+1}$'in $onceki\_hash$ değeri $B_{i-1}$ ile uyuşmaz.
- Bir kaydın içeriği (örneğin transfer edilen para) değiştirilirse: $B_i$'nin $veri\_hash$ değeri değişir, dolayısıyla hesaplanan HMAC $H_i$ değişir ve sonraki tüm blokların bağları kopar.
- Doğrulama fonksiyonu `verify_chain_integrity()` zinciri tek bir geçişte ($O(N)$) tarayarak tahrifatın tam olarak hangi blokta gerçekleştiğini tespit eder.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kripto para borsasında çalışan kötü niyetli bir veritabanı yöneticisi, gece yarısı veritabanına girerek kendi cüzdanına 10 BTC aktarmış ve işlem kayıtlarını log tablosundan silmiştir. Sabah yapılan rutin incelemede loglarda hiçbir şüpheli hareket görülmemiştir.

**Çözüm:** Borsa, tüm yetkili işlemleri `NonRepudiationAuditor` mimarisine bağlamıştır. Zincir doğrulandığında, 1042. blok ile 1044. blok arasındaki 1043. bloğun silindiği ve zincirdeki hash bağı kopukluğu anında tespit edilmiş, denetim anahtarının HMAC imzası sayesinde silinen işlemin hash izi ortaya çıkarılmıştır.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, kağıda yazılan yazı silinir, ama taşa kazınan mühür silinmez. Kriptografik denetim zinciri dijital dünyanın mermer taşıdır. Sisteme giren herkes bilmelidir ki, attığı her adım bir sonrakine kilitlenir; yaptıklarını ne inkar edebilir ne de tarihten silebilir!
