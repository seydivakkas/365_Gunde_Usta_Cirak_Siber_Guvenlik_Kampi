# Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Mimarisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu ders notu yalnızca görüntüleme ve kişisel eğitim amacıyla paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya ticari amaçla kullanılamaz.*

---

## 1. Usta Girişi: Siber Güvenlikte Veri Sızıntısı ve Maskeleme Zorunluluğu

Evlat, siber güvenlik dendiğinde akla ilk gelen şey güvenlik duvarları (Firewall), tersine mühendislik veya saldırı senaryolarıdır. Ancak kurumsal hayatta en büyük felaketler çoğu zaman dışarıdan değil, kurumun kendi ürettiği sistem ve log kayıtlarının içinden patlak verir.

Bir web uygulamasını, bir mikroservis kümesini veya bir SIEM boru hattını düşün:
Bir geliştirici hata ayıklamak (debug) için şöyle bir satır yazar:
```python
logger.debug(f"Ödeme isteği alındı: {request.data}")
```
O anda veritabanından veya istemciden gelen T.C. Kimlik Numarası, kredi kartı bilgisi (PAN), telefon numarası veya gizli API anahtarı, anında düz metin (plaintext) olarak diske yazılır. Bu loglar log toplayıcılarla ElasticSearch, Splunk veya Graylog kümelerine akar; onlarca analist, destek personeli ve üçüncü parti entegratörün erişimine açılır.

İşte tam bu noktada **KVKK (Kişisel Verilerin Korunması Kanunu)**, **GDPR (General Data Protection Regulation)** ve **PCI-DSS (Payment Card Industry Data Security Standard)** devreye girer. PCI-DSS Gereksinim 3.4 uyarınca, kredi kartı numaraları saklanırken ilk 6 ve son 4 hane haricindeki tüm alanlar kesinlikle maskelenmek zorundadır. Loglara kontrolsüzce hassas veri yazılması **CWE-532 (Insertion of Sensitive Information into Log File)** ve **CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)** zafiyetidir.

Bizim görevimiz: Telemetri verisi daha log dosyasına yazılmadan veya merkezi SIEM'e iletilmeden önce, veriyi akış anında tarayan, hassas kalıpları tespit eden ve güvenli şekilde maskeleyen bir **DLP (Data Loss Prevention / Veri Sızıntısı Önleme)** motoru inşa etmektir.

---

## 2. Düzenli İfadelerin (Regex) Gücü ve Tuzakları: ReDoS Felaketi

Düzenli İfadeler (Regular Expressions), metin içerisindeki karmaşık veri desenlerini yakalamak için kullandığımız en güçlü araçlardan biridir. Ancak siber güvenlikte bilinçsizce yazılan bir regex, bizzat bir hizmet dışı bırakma (Denial of Service - DoS) silahına dönüşebilir. Bu zafiyete **CWE-1333: Inefficient Regular Expression Complexity (ReDoS)** adı verilir.

### Catastrophic Backtracking (Katastrofik Geri İzleme) Nedir?
Regex motorlarının çoğu NFA (Nondeterministic Finite Automaton) mimarisi kullanır. Eğer regex deseniniz iç içe belirsiz tekrarlar içeriyorsa (örneğin: `(a+)+$` veya `(a|aa)+$`), regex motoru eşleşmeyen bir girdi gördüğünde tüm olasılık kombinasyonlarını denemek için geriye doğru iz sürmeye (backtracking) başlar.

Girdi metni `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!` olduğunda:
- 10 karakter için: $2^{10} = 1.024$ işlem
- 30 karakter için: $2^{30} = 1.073.741.824$ işlem
- 50 karakter için: CPU çekirdeği %100 yükte saatlerce kilitlenir!

### ReDoS'tan Korunma Kuralları
1. **İç İçe Kümelerden Kaçının:** `(a+)+` yerine sınırları belirli `\b` veya net karakter sınıfları kullanın.
2. **Kelime Sınırları (`\b`):** Desenlerin başına ve sonuna `\b` koyarak arama alanını kelime düzeyinde izole edin.
3. **Girdi Boyut Tavanı (CWE-400):** Maskeleme motoruna gelen metin boyutunu baştan sınırlayın (örneğin 1 MB).
4. **Ön Kontrol / Desen Filtresi:** Bariz kötücül tekrarlı kalıpları işlemciye vermeden önce basit `str` kontrolleriyle reddedin.

---

## 3. Neden Sadece Regex Yetmez? İkincil Algoritmik Doğrulama

Çırakların en sık yaptığı hata şudur: *"Hocam, 16 haneli her sayıyı regex ile yakalayıp kart diye maskeledim!"*
Peki o 16 haneli sayı bir sipariş takip numarasıysa, bir GUID ise veya bir barkod ise ne olacak? Sisteminiz sürekli yanlış pozitif (False Positive) üretecek ve operasyon felç olacaktır.

Bu yüzden profesyonel bir DLP motoru **iki aşamalı filtreleme** kullanır:
1. **Aşama 1 (Kaba Eleme - Regex):** Metin içindeki muhtemel adayları yakalar.
2. **Aşama 2 (Hassas Doğrulama - Algoritmik Kontrol):** Adayın gerçekten geçerli bir kimlik veya kart olup olmadığını matematiksel formüllerle doğrular.

### A. Kredi Kartlarında Luhn Algoritması (ISO/IEC 7812)
Kredi kartı numaralarının son basamağı (Check Digit), Luhn Mod-10 formülüyle üretilir:
1. Rakamlar sağdan sola doğru taranır.
2. Sağdan 2., 4., 6... (tek indeksli) basamaklar 2 ile çarpılır.
3. Eğer çarpım 9'dan büyükse, çarpımın basamakları toplanır (veya doğrudan 9 çıkarılır).
4. Çift indeksli basamaklar doğrudan eklenir.
5. Toplamın $10$'a göre modu alınır (`toplam % 10 == 0`). Eğer sıfır değilse, bu gerçek bir kredi kartı değildir; asla maskelenmemeli ya da sahtecilik uyarısı verilmelidir.

### B. T.C. Kimlik Numarası Algoritması
11 haneli TCKN rastgele bir numara değildir:
- 1. basamak kesinlikle `0` olamaz.
- 10. basamak formülü:
  $$\text{Basamak}_{10} = \left( \left( \sum \text{Tek İndeksler} \times 7 \right) - \sum \text{Çift İndeksler} \right) \pmod{10}$$
- 11. basamak formülü:
  $$\text{Basamak}_{11} = \left( \sum_{i=1}^{10} \text{Basamak}_i \right) \pmod{10}$$

### C. Uluslararası Banka Hesap Numarası (IBAN - ISO 7064 MOD-97)
Türkiye IBAN'ları `TR` ile başlar ve toplam 26 karakterdir:
- İlk 4 karakter (Ülke kodu `TR` ve 2 haneli sağlama toplamı) dizginin sonuna taşınır.
- Tüm harfler sayısal değerlere dönüştürülür (`A=10, B=11 ... Z=35`).
- Elde edilen devasa sayının 97'ye göre modu alınır:
  $$\text{Sayı} \pmod{97} \equiv 1$$
Eğer kalan 1 değilse, aktarılan veri hatalı veya sahtedir.

---

## 4. Maskeleme Stratejileri: MASK, REDACT ve HASH

Hassas veriyi sistemde nereye göndereceğinize göre maskeleme yöntemini seçersiniz:

| Yöntem | Format Örneği | Güvenlik Düzeyi | Kullanım Alanı |
| :--- | :--- | :--- | :--- |
| **MASK (Kısmi)** | `123******50` / `453201******0366` | Orta | Operasyonel loglar, destek ekranları (kullanıcıyı doğrulamak için ilk ve son haneler lazımdır). |
| **REDACT (Tam Karartma)** | `[REDACTED_TCKN]` / `[REDACTED_CARD]` | Yüksek | Üçüncü parti denetimler, açık veri setleri, genel SIEM log dışa aktarımları. |
| **HASH (Pseudonym)** | `TCKN#a8f10c44...` | Çok Yüksek | Veri analitiği ve fraud tespiti (aynı kişinin hareketlerini kimliğini bilmeden korele etmek için). |

---

## 5. Ustanın Çırağa Öğütleri

1. **Loglara Asla Körlemesine Güvenme:** Bir sistemin en büyük sızıntı kaynağı yetersiz denetlenen debug loglarıdır. Üretim ortamında (production) log seviyesini `INFO` veya `WARN` seviyesine çek ve DLP maskeleme motorunu loglama aracı katmanında (Logging Handler / Middleware) zorunlu kıl.
2. **Ters Sırada Değiştirme Prensibi:** Bir metin içinde birden fazla eşleşmeyi değiştirirken, metni her zaman **sondan başa doğru** (ters sırada) değiştir. Eğer baştan değiştirirsen, metnin uzunluğu değişeceği için sonraki eşleşmelerin karakter indeksleri kayar ve veriyi bozarsın!
3. **Null-Byte ve Karakter Zehirlemelerini Unutma (CWE-158):** Logları işlerken araya sızan `\x00` baytı C tabanlı log yönlendiricilerde (syslog, rsyslog) metnin erken kesilmesine ve kalan logun gizlenmesine yol açabilir. Her zaman baştan temizle.
