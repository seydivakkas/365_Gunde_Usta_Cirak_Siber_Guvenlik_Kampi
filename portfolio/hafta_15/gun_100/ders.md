# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 100: Kriptografide Entropi ve Rastgelelik Prensipleri

## Usta-Çırak / Hoca Dersi Girişi

Evlat, 100. güne eriştik! Bir siber güvenlik mühendisi için 100. gün bir eşiktir. Bugün, kriptografinin kalbi olan **Entropi ve Rastgelelik** konusunu işleyeceğiz.

Sana bir sır vereyim: En güçlü şifreleme algoritması bile (ister AES-256 olsun, ister kuantum dirençli Kyber olsun), ürettiği anahtarı tahmin edilebilir bir rastgelelik kaynağından alıyorsa bir çöp yığınından farksızdır! Kriptografide her şey belirsizlik (uncertainty) üzerine kuruludur. Eğer bir saldırgan senin bir sonraki üreteceğin baytı ya da anahtarının üretildiği tohumu (seed) tahmin edebiliyorsa, algoritmanın matematiksel karmaşıklığı sıfıra iner.

Çıraklar zanneder ki `import random` yazıp `random.randint()` çağırdıklarında rastgele sayı üretirler. Hayır! O bir illüzyondur. O deterministik bir matematik formülüdür. Gel şimdi gerçek rastgelelik ile sahte rastgeleliğin farkını, Shannon entropisini ve NIST istatistiksel testlerini derinlemesine öğrenelim.

---

## 1. Shannon Entropisi: Bilginin ve Belirsizliğin Matematiği

1948 yılında Claude Shannon, "A Mathematical Theory of Communication" adlı makalesiyle bilgi teorisini kurdu. Shannon'a göre entropi, bir mesajdaki ortalama bilgi yoğunluğunu ve öngörülemezliği ölçer:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Burada $P(x_i)$, $x_i$ baytının veya sembolünün dizide görülme olasılığıdır.

### 1.1 Entropi Sınırları ve Anlamı
- **Minimum Entropi (0.0 bit/bayt):** Dizi tamamen tek bir karakterden oluşuyorsa (örneğin `"AAAA..."`), hiçbir sürpriz yoktur. Olasılık $P('A') = 1$, $\log_2(1) = 0$, dolayısıyla $H(X) = 0$.
- **Maksimum Entropi (8.0 bit/bayt):** 1 bayt 8 bitten oluştuğu için alabileceği 256 farklı değer ($0-255$) vardır. Eğer her bayt eşit olasılıkla ($P = 1/256$) görülürse:
  $$H(X) = -256 \times \left(\frac{1}{256} \log_2 \frac{1}{256}\right) = - \log_2(2^{-8}) = 8.0 \text{ bit/bayt}$$
- **Kriptografik Eşik:** Güvenli bir kriptografik anahtarın, oturum token'ının veya şifreleme tuzunun (salt) Shannon entropisi **en az 7.5 bit/bayt** olmalıdır. 7.0'ın altındaki değerler zafiyet göstergesidir (CWE-331).

---

## 2. Min-Entropi (Worst-Case Entropy)

Shannon entropisi ortalama belirsizliği ölçer. Ancak güvenlikte "ortalama" bizi kurtarmaz; saldırgan en zayıf halkaya vurur! İşte bu yüzden NIST SP 800-90B standardı **Min-Entropi** ($H_\infty$) metriğini zorunlu kılar:

$$H_\infty(X) = -\log_2\Big(\max_{i} P(x_i)\Big)$$

Min-entropi, veri akışındaki en yüksek olasılıklı (en sık görülen) sembolün belirsizliğidir. Örneğin bir sistemde 255 bayt tamamen rastgele ama bir bayt %50 olasılıkla geliyorsa, Shannon entropisi yüksek görünse bile min-entropi çöker!

---

## 3. PRNG vs CSPRNG: Ölümcül Ayrım

Bir güvenlik uzmanının bilmesi gereken en hayati ayrım:

```
+------------------------------------+------------------------------------+
|  STANDART PRNG (Mersenne Twister)  |      CSPRNG (Kriptografik PRNG)    |
+------------------------------------+------------------------------------+
| Python 'random' modülü             | Python 'secrets' / 'os.urandom'    |
| Simülasyon, oyun, veri bilimi için | Anahtar, token, IV, parola için    |
| Durumu (state) tahmin edilebilir   | Durumu matematiksel olarak gizlidir|
| 624 çıktıdan sonra çözülür!        | Geriye ve ileriye doğru güvenli    |
| CWE-338: Kriptografide YASAKTIR!   | FIPS 140-3 & NIST Onaylı           |
+------------------------------------+------------------------------------+
```

### 3.1 Mersenne Twister Zafiyeti (CWE-338)
Python'ın yerleşik `random` modülü **Mersenne Twister (MT19937)** algoritmasını kullanır. Bu algoritma mükemmel bir tekdüze dağılıma ve $2^{19937}-1$ gibi devasa bir periyoda sahiptir. Ancak **doğrusal bir sonlu durum makinesidir**. Bir saldırgan üretilen ardışık **624 adet 32-bitlik tamsayıyı** gözlemlediğinde, algoritmanın tüm dahili durumunu (internal state) rekonstrükte eder ve gelecekte üretilecek tüm sayıları 0 hata payıyla tahmin eder!

### 3.2 CSPRNG ve İşletim Sistemi Entropi Havuzu
Kriptografik güvenli sözde rastgele üreteçler (`os.urandom()`, `secrets`, Windows `BCryptGenRandom`, Linux `/dev/urandom`), işlemcinin donanımsal gürültülerini, fare hareketlerini, klavye vuruş gecikmelerini ve disk/ağ kesintilerini (interrupts) toplayarak bir entropi havuzuna aktarır. Bu havuz tek yönlü bir kriptografik fonksiyonla (AES-CTR-DRBG veya ChaCha20) karıştırılır. Bir önceki veya bir sonraki sayıyı tahmin etmek matematiksel olarak imkansızdır.

---

## 4. Gerçek Dünya Vakası: Debian OpenSSL Zafiyeti (CVE-2008-0166)

2006 yılında Debian Linux dağıtımındaki bir geliştirici, Valgrind bellek denetleyicisinin "başlatılmamış bellek kullanımı" (uninitialized memory) uyarısını gidermek amacıyla OpenSSL kaynak kodundaki şu satırı sildi:
```c
/* MD_Update(&m,buf,j); kaldırıldı! */
```
Bu satır, işletim sisteminden gelen rastgele gürültüyü OpenSSL entropi havuzuna ekleyen satırdı! Bu satır kaldırılınca, OpenSSL anahtar üretirken rastgelelik tohumu olarak **yalnızca işletim sisteminin Süreç Kimliğini (PID - Process ID)** kullanmaya başladı!
Linux'ta PID en fazla 32.767 olabilir. Yani üretilebilecek tüm SSH ve SSL özel anahtarlarının sayısı trilyonlarca olması gerekirken **sadece 32.767 adede düştü!** Saldırganlar 32.767 anahtarın tamamını 1 saat içinde hesaplayıp bir veritabanına koydular ve dünyadaki milyonlarca Debian tabanlı sunucunun SSH anahtarlarını şifre bilmeden kırdılar!

İşte yetersiz entropi (CWE-331) ve tahmin edilebilir tohum (CWE-337) böylesine felaketlere yol açar.

---

## 5. NIST SP 800-22 İstatistiksel Rastgelelik Testleri

Rastgeleliğin kalitesini doğrulamak için NIST testleri uygulanır:

1. **Monobit (Frekans) Testi:**
   Tüm akıştaki 0 ve 1 bitlerinin sayısının birbirine eşit olup olmadığını inceler:
   $$S_n = \frac{|n_1 - n_0|}{\sqrt{n}}, \quad p = \text{erfc}\left(\frac{S_n}{\sqrt{2}}\right)$$
   Eğer $p < 0.01$ ise veri rastgele değildir; bitler tek tarafa kaymıştır.

2. **Ki-Kare ($\chi^2$) Uygunluk Testi:**
   256 farklı bayt değerinin her birinin gözlemlenen frekansını ($O_i$), beklenen tekdüze frekansla ($E = N/256$) karşılaştırır:
   $$\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E)^2}{E}$$

---

## 6. Ustanın Nasihati

Evlat, siber güvenlikte "şans" yoktur; matematik vardır. Kodunda parola sıfırlama token'ı, API anahtarı veya şifreleme IV'si üretirken elin asla `random` modülüne gitmesin! `secrets` ve `os.urandom` senin kutsal kalkanındır. Yazdığın her anahtarın entropisini ölç, 7.5 bitin altına inen hiçbir veriye canını emanet etme!
