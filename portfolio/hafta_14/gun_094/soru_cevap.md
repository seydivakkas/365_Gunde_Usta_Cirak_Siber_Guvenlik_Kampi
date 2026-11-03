# GÜN 094: Regex ile Kişisel Veri Maskeleme — Mülakat ve Uzmanlık Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap dokümanı siber güvenlik analistliği, DLP mühendisliği ve teknik mülakat hazırlığı için pedagojik olarak yapılandırılmıştır.*

---

## SORU 1: ReDoS (Regular Expression Denial of Service - CWE-1333) Mekanizması ve Catastrophic Backtracking Tehdidi

### 1. Soru Başlığı ve Tanımı
Bir güvenlik analisti veya geliştirici tarafından hassas verileri yakalamak amacıyla yazılan bir düzenli ifade (Regex), nasıl bir Hizmet Dışı Bırakma (DoS) saldırı vektörüne dönüşebilir? Katastrofik Geri İzleme (Catastrophic Backtracking) nedir ve regex motorunun CPU çekirdeğini %100 kilitlemesine nasıl yol açar?

### 2. Derinlemesine Teknik Analiz
Çoğu programlama dilinde (Python, Java, JavaScript, .NET) varsayılan regex motoru **NFA (Nondeterministic Finite Automaton)** mantığıyla çalışır. NFA motorları bir deseni eşleştirmeye çalışırken birden fazla alternatif dal olduğunda birini seçer ve ilerler; eğer eşleşme bir noktada başarısız olursa, bir önceki karara geri dönüp (backtrack) diğer alternatifleri dener.

Eğer regex deseni iç içe gruplar ve tekrarlar barındırıyorsa (örneğin: `(a+)+$` veya `^([a-zA-Z0-9]+)*@`):
- Girdi metni `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!` olduğunda (sonunda eşleşmeyi bozan `!` karakteri varsa),
- Regex motoru baştaki `a` harflerini gruplara dağıtmanın binlerce farklı yolunu hesaplar (1. grup 2 tane, 2. grup 26 tane; 1. grup 3 tane, 2. grup 25 tane vb.).
- Durum karmaşıklığı polinomik ($O(n^2)$) veya doğrudan üstel ($O(2^n)$) büyüklüğe fırlar.
- 30-40 karakterlik kötücül bir girdi dahi tek bir CPU çekirdeğini saatlerce meşgul edebilir. Bu saldırıya **CWE-1333 (Inefficient Regular Expression Complexity / ReDoS)** denir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesinin API ağ geçidinde gelen JSON yüklerini denetleyen bir DLP regex filtresi bulunmaktadır. Saldırgan, e-posta alanına `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@evil.org` değerini gönderir. Regex motoru bu istek karşısında kilitlenir; Kubernetes pod'u sağlık kontrollerine (health check) yanıt veremez hale gelir ve tüm küme çöker.

**Pratik Çözüm:**
1. **İç İçe Kümeleri Kaldırın:** `(a+)+` desenleri yerine `[a-zA-Z0-9._%+-]+` gibi tekil ve deterministik karakter sınıfları kullanın.
2. **Kelime Sınırları ve Uzunluk Kısıtı:** Regex çalıştırılmadan önce alan uzunluğunu sınırlandırın (örneğin e-posta alanı $\le 254$ karakter).
3. **Deterministik Motorlar (DFA / Google re2):** Kritik ağ geçitlerinde NFA yerine geri izleme yapmayan lineer zamanlı $O(n)$ garantisi veren regex motorlarını (`re2`) veya ReDoS algılama kalkanlarını tercih edin.

### 4. Ustanın Çırağa Tavsiyesi
Çırak, regex yazarken *"ne kadar kısa yazarsam o kadar zekice"* yanılgısına düşme. Her parantez ve her `+` veya `*` işareti regex motoruna bir karar noktası ekler. İki tane joker karakteri asla iç içe koyma. Bir regex yazdıktan sonra mutlaka Regex101 gibi araçlarla "Catastrophic Backtracking" uyarısı verip vermediğini test etmeden canlı sisteme sürme.

---

## SORU 2: PCI-DSS Gereksinim 3.4 ve Luhn Algoritması (ISO/IEC 7812) ile Yanlış Pozitiflerin Önlenmesi

### 1. Soru Başlığı ve Tanımı
Kredi kartı verilerini loglardan ve telemetri akışlarından temizlerken neden yalnızca 16 haneli sayı deseni (`\b\d{16}\b`) aramak yetersizdir? PCI-DSS standardı hangi hanelerin görünmesine izin verir ve Luhn Algoritması (Mod-10) siber güvenlik operasyonlarında yanlış pozitifleri (False Positive) nasıl engeller?

### 2. Derinlemesine Teknik Analiz
Kurumsal ortamlarda sistem logları incelendiğinde; sipariş numaraları, kargo takip kodları, donanım UUID/seri numaraları, zaman damgalı işlem kimlikleri veya telemetri bayt dizgileri sıklıkla 13-19 basamaklı rakam bloklarından oluşur.
Eğer DLP motoru sadece regex ile 16 haneli her sayıyı maskelemeye kalkarsa:
- Gerçek sipariş numaraları veya takip kodları yıldızlanır, operasyonel ekipler müşterinin siparişini loglarda bulamaz hale gelir.
- Güvenlik analistleri binlerce sahte alarm arasında boğulur.

Bu sorunu çözmek için ISO/IEC 7812 standardının tanımladığı **Luhn Algoritması (Mod-10)** kullanılır:
- Kredi kartlarının son hanesi bir kontrol basamağıdır (checksum).
- Sağdan sola doğru gidilirken tek indeksli basamaklar 2 ile çarpılır (çarpım 9'u geçerse basamaklar toplanır).
- Çift indeksli basamaklar aynen toplanır.
- Tüm toplamın $10$'a tam bölünmesi şarttır (`toplam % 10 == 0`).
Rastgele 16 haneli bir sayının şans eseri Luhn testinden geçme olasılığı yalnızca $\%10$'dur. Böylece yanlış pozitif oranı anında $\%90$ oranında düşürülür.

PCI-DSS Gereksinim 3.4 uyarınca; kart verisi diske yazılırken veya loglanırken yalnızca ilk 6 hane (BIN - Bank Identification Number) ve son 4 hane açık bırakılabilir; aradaki tüm basamaklar sansürlenmelidir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir ödeme ağ geçidinde saatte 500.000 işlem loglanmaktadır. Loglarda hem `pan="4532-0151-1283-0366"` (geçerli kart) hem de `invoice_id="1234567890123456"` (fatura no) bulunmaktadır.

**Pratik Çözüm:**
DLP motoru önce regex ile adayı yakalar, ardından aday dizgiyi `verify_luhn()` fonksiyonuna gönderir:
```python
if verify_luhn(candidate):
    # Luhn geçti: Gerçek kart verisi, PCI-DSS formatında maskele
    masked_val = f"{digits[:6]}******{digits[-4:]}"
else:
    # Luhn geçmedi: Fatura veya işlem numarası, dokunma
    masked_val = candidate
```
Bu sayede fatura numarası bozulmadan logda kalırken, kredi kartı PCI-DSS uyumlu biçimde maskelenir.

### 4. Ustanın Çırağa Tavsiyesi
Bir güvenlik sisteminde yanlış pozitifler (false positives), yanlış negatifler (false negatives) kadar tehlikelidir evlat. Yanlış pozitif üreten bir güvenlik aracı, operasyonel ekipler tarafından *"bu sürekli işimizi engelliyor"* denilerek kapatılır. Güvenlik aracının kapatılması ise tam bir felakettir. Asla tek katmanlı doğrulamayla yetinme; regex ile yakala, algoritma ile teyit et.

---

## SORU 3: Log Sanitization Boru Hatlarında MASK, REDACT ve HASH (Pseudonymization) Karşılaştırması

### 1. Soru Başlığı ve Tanımı
KVKK ve GDPR düzenlemelerine tabi bir siber güvenlik altyapısında; hassas kişisel verileri loglardan arındırırken MASK (Kısmi Maskeleme), REDACT (Tam Gizleme) ve HASH (Tuzlu Pseudonymization) yöntemleri hangi senaryolarda tercih edilmelidir? Adli bilişim (forensics) ve fraud analizinde hangi yaklaşım hukuki ve teknik dengeyi sağlar?

### 2. Derinlemesine Teknik Analiz
Her maskeleme yönteminin veri kaybı ve güvenlik dengesi farklıdır:

1. **MASK (Format-Preserving Partial Masking):**
   - Örnek: `123******50` (TCKN), `ah***@kurum.com` (Email).
   - *Teknik Özellik:* Orijinal verinin biçimini (uzunluk, önek, son ek) korur.
   - *Kullanım:* Çağrı merkezi logları, operasyonel debug süreçleri. Destek personeli arayan kişinin kimliğini doğrulamak için son 2 haneyi görmek zorundadır.

2. **REDACT (Full Anonymization / Suppression):**
   - Örnek: `[REDACTED_TCKN]`, `[REDACTED_CARD]`.
   - *Teknik Özellik:* Orijinal veriye dair hiçbir bilgi kalmaz; entropi sıfırlanır. Geri dönüşü (re-identification) matematiksel olarak imkansızdır.
   - *Kullanım:* Üçüncü parti geliştiricilere açılan test logları, açık kaynak veri setleri, genel denetim raporları.

3. **HASH (Salted Pseudonymization):**
   - Örnek: `TCKN#a8f10c44b912` (SHA-256(TCKN + SECRET_SALT)[:12]).
   - *Teknik Özellik:* Gerçek kimlik asla açığa çıkmaz; ancak aynı kimlik her geçtiğinde aynı pseudonym değeri üretilir.
   - *Kullanım:* SIEM korelasyon kuralları, dolandırıcılık (fraud) tespiti ve kullanıcı davranış analitiği (UEBA). Bir saldırganın birden fazla hesap üzerinde deneme yapıp yapmadığı, kimliği açık edilmeden tespit edilebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kurumunda SOC analistleri, bir kullanıcının dakikada 50 başarısız transfer denemesi yaptığını tespit etmek zorundadır. Eğer loglar `[REDACTED_TCKN]` şeklinde tamamen silinirse, analist bu 50 işlemin aynı kişiye mi yoksa 50 farklı kişiye mi ait olduğunu anlayamaz.

**Pratik Çözüm:**
Log akışında **tuzlu hashleme (Pseudonymization)** uygulanır:
```python
pseudonym = "TCKN#" + hashlib.sha256((tckn + HSM_SECRET_SALT).encode()).hexdigest()[:12]
```
Böylece logda `user=TCKN#f4c281` görünür. SOC analisti sistemde aynı kimliğin 50 kez deneme yaptığını görerek alarm üretir, ancak kullanıcının gerçek TCKN'sini öğrenemez. Adli makamlar resmi talepte bulunduğunda ise sadece HSM yetkisine sahip uyumluluk görevlisi bu hash ile gerçek kaydı eşleştirebilir.

### 4. Ustanın Çırağa Tavsiyesi
Veri güvenliği sadece "silip yok etmek" değildir evlat. Güvenlik operasyonunun çalışabilmesi için verinin analitik değerini korurken gizliliğini sağlamayı bilmelisin. Düz hash (tuzsuz SHA-256) asla kullanma; saldırganlar gökkuşağı tablolarıyla (rainbow tables) 11 haneli tüm TCKN'lerin hash'ini dakikalar içinde çözebilir. Her zaman yüksek entropili bir sistem tuzu (salt) veya HMAC kullan.
