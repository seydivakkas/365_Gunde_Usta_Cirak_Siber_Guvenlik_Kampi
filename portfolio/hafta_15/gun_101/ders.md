# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 101: Kriptografik Hash Fonksiyonları ve Çakışma Dinamikleri

## Usta-Çırak / Hoca Dersi Girişi

Evlat, hoş geldin! Bugün kriptografinin dijital parmak izi olan **Hash Fonksiyonları ve Çakışma (Collision)** mimarisini inceleyeceğiz.

Günlük hayatta adli bilişimden blokzincirlere, dijital imzalardan parola saklamaya kadar her yerde hash fonksiyonlarını kullanırız. Ancak çırakların çoğu hash fonksiyonlarını "büyülü bir kıyma makinesi" zanneder. "Girdiyi atarsın, geriye dönmez, kimse taklit edemez" derler. Fakat bir fonksiyonun girdi kümesi sonsuz, çıktı kümesi ise sabit uzunlukta (örneğin 256 bit) ise, **Güvercin Yuvası İlkesi (Pigeonhole Principle)** gereği mutlaka iki farklı girdi aynı çıktıya denk gelecektir!

Önemli olan soru "çakışma var mı?" sorusu değildir. Çakışma matematikte kaçınılmazdır. Önemli olan soru: **"Bir saldırgan bu çakışmayı insan ömrü içinde hesaplayabilir mi?"** sorusudur. İşte bugün MD5 ve SHA-1'in nasıl tarihe gömüldüğünü, Doğum Günü Paradoksunun gücünü ve SHA-256'nın neden yıkılmaz bir kale olduğunu öğreneceksin.

---

## 1. Kriptografik Hash Fonksiyonunun Üç Temel Özelliği

Bir matematiksel özet fonksiyonunun kriptografik olarak güvenli sayılabilmesi için şu üç direnci sağlaması şarttır:

### 1.1 İlk Ön Görüntü Direnci (Pre-image Resistance / Tek Yönlülük)
Verilen bir özet değeri $h$ için, $H(m) = h$ eşitliğini sağlayan herhangi bir $m$ mesajını bulmanın imkansız olmasıdır.
- **Hesaplama Karmaşıklığı:** $n$ bitlik bir çıktı için $O(2^n)$ işlem gerektirir.
- **Anlamı:** Hash fonksiyonu tek yönlüdür; özeti bilinen bir verinin orijinali geri döndürülemez.

### 1.2 İkinci Ön Görüntü Direnci (Second Pre-image Resistance / Zayıf Çakışma Direnci)
Verilen belirli bir $m_1$ mesajı için, $m_2 \neq m_1$ ve $H(m_2) = H(m_1)$ olacak şekilde ikinci bir $m_2$ mesajı bulmanın imkansız olmasıdır.
- **Hesaplama Karmaşıklığı:** Yine $O(2^n)$ işlem gerektirir.
- **Anlamı:** Saldırgan, senin imzaladığın geçerli bir sözleşmenin yerine aynı hash'i veren sahte bir sözleşme koyamaz.

### 1.3 Çakışma Direnci (Collision Resistance / Güçlü Çakışma Direnci)
Önceden belirlenmiş hiçbir mesaj olmaksızın, $H(m_1) = H(m_2)$ ve $m_1 \neq m_2$ koşulunu sağlayan **herhangi iki farklı mesaj çifti** bulmanın imkansız olmasıdır.
- **Hesaplama Karmaşıklığı:** $O(2^n)$ değil, Doğum Günü Paradoksu nedeniyle yalnızca **$O(2^{n/2})$** işlemdir!

---

## 2. Doğum Günü Paradoksu ve Matematiksel İspatı

Bir odada kaç kişi olursa, en az iki kişinin doğum gününün aynı olma olasılığı %50'yi geçer?
Çoğu insan $365 / 2 \approx 183$ kişi diye tahmin eder. Oysa cevap sadece **23 kişidir!**

### 2.1 Matematiksel Olasılık Analizi
$k$ kişinin doğum günlerinin birbirinden tamamen farklı olma olasılığı:
$$P(\text{hepsi farklı}) = \frac{365}{365} \times \frac{364}{365} \times \frac{363}{365} \times \dots \times \frac{365 - k + 1}{365}$$
Taylor serisi yaklaşımıyla ($1 - x \approx e^{-x}$):
$$P(\text{hepsi farklı}) \approx \prod_{i=1}^{k-1} e^{-i / 365} = e^{-\sum_{i=1}^{k-1} i / 365} = e^{-k(k-1) / (2 \times 365)}$$
En az bir ortak doğum günü olasılığı $P \ge 0.5$ olması için:
$$1 - e^{-k^2 / (2 \times 365)} \ge 0.5 \implies e^{-k^2 / 730} \le 0.5 \implies \frac{k^2}{730} \ge \ln(2) \approx 0.693$$
$$k \approx \sqrt{2 \ln(2) \times 365} \approx 1.1774 \times \sqrt{365} \approx 22.49 \implies 23 \text{ Kişi!}$$

### 2.2 Kriptografiye Yansıması
$n$-bitlik bir hash fonksiyonunda olası çıktı sayısı $N = 2^n$'dir. Doğum günü saldırısıyla herhangi bir çakışma bulmak için gereken deneme sayısı:
$$k \approx \sqrt{2 \ln(2) \times 2^n} \approx 1.1774 \times 2^{n/2} = O(2^{n/2})$$
- **MD5 (128-bit):** Güvenlik seviyesi 128 bit değil, $2^{64}$ işlemdir! (Günümüz bilgisayarları için son derece kolaydır).
- **SHA-1 (160-bit):** Güvenlik seviyesi 160 bit değil, $2^{80}$ işlemdir.
- **SHA-256 (256-bit):** Güvenlik seviyesi **$2^{128}$** işlemdir. $2^{128}$ sayısı, evrendeki bilinen tüm atomların sayısıyla yarışacak büyüklüktedir; brute-force veya doğum günü saldırısıyla kırılamaz.

---

## 3. Tarihten İki Büyük Çakışma Felaketi

### 3.1 MD5'in Çöküşü ve Flame Zararlısı (2012)
2004 yılında Xiaoyun Wang ve ekibi, MD5'in diferansiyel kriptoanaliz ile çakışmaya açık olduğunu kanıtladı. 2012 yılında Orta Doğu'daki kritik altyapıları hedef alan **Flame (Flamer)** siber casusluk zararlısı ortaya çıktı. Flame'i geliştiren devlet destekli aktörler, Microsoft'un Terminal Server yetkilendirme otoritesindeki MD5 tabanlı eski bir sertifikayı kullanarak **sahte bir Microsoft Windows Update Kök Sertifikası** ürettiler! MD5 çakışması sayesinde zararlı yazılım kendini resmi Windows Güncellemesi gibi göstererek yüz binlerce hedef sisteme sızdı.

### 3.2 SHA-1'in Sonu: SHAttered Saldırısı (2017)
Google ve CWI Amsterdam araştırmacıları, 2017 yılında **SHAttered** projesini duyurdu. Araştırmacılar, içerikleri tamamen farklı (biri mavi, diğeri kırmızı arka plana sahip) ancak **SHA-1 özetleri birebir aynı olan iki adet PDF belgesi** ürettiler. Bu operasyon için 9 trilyon SHA-1 hesaplaması yapıldı ve SHA-1 resmi olarak güvenilmez ilan edildi (CWE-328).

---

## 4. Çığ Etkisi (Avalanche Effect)

İyi bir kriptografik hash fonksiyonunda girdideki en küçük değişim (örneğin sadece 1 bitin 0'dan 1'e dönmesi), çıktıdaki bitlerin yaklaşık **%50'sinin rastgele değişmesine** yol açmalıdır.

Eğer bir bitlik değişim çıktıda sadece birkaç biti değiştiriyorsa, o fonksiyon bir şifreleme veya hash fonksiyonu değil, basit bir sağlama toplamıdır (checksum - CRC32 gibi). Çığ etkisi, saldırganın girdideki değişikliklerle çıktıdaki değişiklikler arasında matematiksel bir korelasyon kurmasını (kriptoanaliz) engeller.

```
Girdi 1: "SiberGuvenlik2026_Kripto_G101_A"
SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

Girdi 2: "SiberGuvenlik2026_Kripto_G101_B"  (Sadece son karakter 0x41 -> 0x42, 1 bit fark)
SHA-256: e8c61e0f0685973347b3a985bc81ff8c8e8880d6b9d6a3f4e19502693e5069a2

Fark     : 256 bitten 127 bit değişti -> Değişim Oranı: %49.61 (MÜKEMMEL ÇIĞ ETKİSİ)
```

---

## 5. Ustanın Nasihati

Evlat, tarihten ders almayan mühendis aynı çukura iki kez düşer. MD5 ve SHA-1 artık müzedir; onları canlı sistemlerde dosya doğrulamada, şifre saklamada veya dijital imzada kullanan kişi açıkça görevi ihmal etmektedir! Bugünün standardı SHA-256, SHA-512 ve BLAKE2b'dir. Yazdığın her kodda kırılmış algoritmaları filtrele, hash karşılaştırmalarında zamanlama saldırılarına karşı daima `hmac.compare_digest` kullan!
