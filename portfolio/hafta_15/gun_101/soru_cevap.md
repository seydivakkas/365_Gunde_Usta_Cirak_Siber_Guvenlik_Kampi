# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 101: Soru-Cevap — Kriptografik Hash Fonksiyonları ve Çakışma

---

## Soru 1: Doğum Günü Paradoksu (Birthday Paradox) $n$-bitlik bir hash fonksiyonunun çakışma direncini neden $2^n$ yerine $2^{n/2}$ seviyesine indirir?

### 1. Soru Başlığı ve Tanımı
Doğum Günü Paradoksunun kombinatoryal olasılık matematiği, hedefli çakışma (Second Pre-image) ile serbest çakışma (Collision) arasındaki fark ve hash güvenliğine etkisi.

### 2. Derinlemesine Teknik Analiz
Çoğu insan bir hash fonksiyonunun $n$-bitlik çıktısı olduğunda, çakışma bulmak için $2^n$ deneme yapılması gerektiğini düşünür. Bu mantık **İkinci Ön Görüntü Direnci (Second Pre-image Resistance)** için geçerlidir; çünkü orada belirli bir hedef $m_1$ vardır ve saldırgan tam olarak o hedefe eşit $H(m_2) = H(m_1)$ sonucunu arar.

Ancak **Genel Çakışma Direncinde (Collision Resistance)** hedef sabit değildir. Saldırgan herhangi iki mesajın ($m_i \neq m_j$) aynı hash'i üretmesini arar.
$k$ adet rastgele mesaj üretildiğinde, bu mesajlar arasındaki olası ikili karşılaştırma sayısı kombinasyon formülü ile hesaplanır:
$$C(k, 2) = \frac{k(k - 1)}{2} \approx \frac{k^2}{2}$$
Toplam olası hash alanı $N = 2^n$ olduğunda, bir çakışma oluşma olasılığının %50'yi aşması için gereken karşılaştırma sayısı yaklaşık $N$'e ulaşmalıdır:
$$\frac{k^2}{2} \approx N \implies k^2 \approx 2N \implies k \approx \sqrt{2N} = \sqrt{2 \times 2^n} = \sqrt{2} \times 2^{n/2} = O(2^{n/2})$$
Bu matematiksel gerçeklik nedeniyle:
- 128-bitlik MD5 fonksiyonunda arama uzayı $2^{128}$ değil, yalnızca $2^{64}$ denemedir!
- 160-bitlik SHA-1 fonksiyonunda arama uzayı $2^{160}$ değil, yalnızca $2^{80}$ denemedir!
- 256-bitlik SHA-256 fonksiyonunda arama uzayı $2^{256}$ değil, $2^{128}$ denemedir. $2^{128}$ mertebesi günümüz teknolojisiyle kırılması fiziksel olarak imkansız bir güvenlik marjı sağlar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir yazılım şirketi, ürettiği binary dosyaların dijital imzasını doğrularken imza boyutundan tasarruf etmek amacıyla SHA-256 yerine eski MD5 algoritmasını kullanmaya devam etmiştir. Saldırganlar, Doğum Günü saldırısı prensibiyle biri zararsız bir hesap makinesi, diğeri ise arka kapı (backdoor) içeren bir truva atı olan iki farklı dosya hazırlamış ve diferansiyel kriptoanalizle ikisinin de MD5 özetini aynı yapmayı başarmıştır. Şirket zararsız dosyayı onaylayıp imzaladığında, saldırgan aynı imzayı zararlı yazılıma iliştirerek antivirüsleri atlatmıştır.

**Çözüm:** `HashAnalyzer.compute_digest()` motorunda `md5` ve `sha1` varsayılan olarak yasaklanmıştır (`BrokenHashAlgorithmError`). Dijital imza ve bütünlük kontrollerinde en az 256-bitlik SHA-256 veya SHA-512 kullanılmalıdır.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, tek bir hedefi vurmak zordur; ama havaya binlerce saçma sıkarsan iki saçmanın havada çarpışma olasılığı sandığından çok daha yüksektir! Doğum Günü Paradoksu saçmaların çarpışmasıdır. Güvenliğini $2^n$'e göre değil, daima $2^{n/2}$'ye göre hesaplayacaksın!

---

## Soru 2: Çığ Etkisi (Avalanche Effect) nedir ve bir hash fonksiyonunun zayıf çığ etkisi göstermesi saldırganlara hangi kriptoanaliz kapılarını açar?

### 1. Soru Başlığı ve Tanımı
Girdideki 1 bitlik değişimin çıktıdaki bitlere difüzyon (yayılma) oranı, Shannon'ın Karmaşa (Confusion) ve Yayılma (Diffusion) ilkeleri ve zayıf çığ etkisinin getirdiği diferansiyel kriptoanaliz riskleri.

### 2. Derinlemesine Teknik Analiz
Kriptografide Claude Shannon tarafından tanımlanan iki temel prensip vardır:
1. **Karmaşa (Confusion):** Anahtar/girdi ile şifreli metin/özet arasındaki ilişkinin olabildiğince karmaşık ve doğrusal olmayan hale getirilmesi.
2. **Yayılma (Diffusion):** Girdideki tek bir sembolün veya bitin etkisinin çıktının tamamına yayılması.

**Çığ Etkisi (Avalanche Effect)**, yayılma ilkesinin pratik ölçüsüdür:
$$d_H(H(m), H(m \oplus \Delta_1)) \approx \frac{n}{2}$$
Burada $d_H$ Hamming Mesafesi (farklılaşan bit sayısı), $\Delta_1$ ise yalnızca 1 biti değişmiş girdi farkıdır. İdeal bir hash fonksiyonunda değişim oranı **%50 $\pm$ %5** aralığında olmalıdır.

**Zayıf Çığ Etkisinin Riskleri:**
Eğer bir fonksiyonda 1 bit değiştiğinde çıktıda yalnızca 3-4 bit değişiyorsa ya da belirli girdi bitleri çıktının sadece belirli bloklarını etkiliyorsa:
- **Diferansiyel Kriptoanaliz:** Saldırgan girdi farkları ($\Delta X$) ile çıktı farkları ($\Delta Y$) arasında istatistiksel olasılık haritaları çıkarır.
- **Tersine Mühendislik:** Fonksiyonun dahili durum matrisleri doğrusal denklemlere indirgenerek ilk ön görüntü (pre-image) veya çakışma (collision) trilyonlarca kat daha hızlı çözülür.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Özel bir gömülü sistem üreticisi, mikrodenetleyicinin CPU gücü yetersiz olduğu için standart SHA-256 yerine kendi geliştirdiği "hafifletilmiş" bir hash algoritması kullanmıştır. Bu algoritmada çığ etkisi testi yapıldığında, 1 bitlik girdi değişiminin çıktıda yalnızca %12'lik bir değişime yol açtığı görülmüştür. Güvenlik araştırmacıları diferansiyel analizle bu algoritmanın 15 dakikada tersine çevrilebildiğini ve sahte firmware yüklemelerine olanak tanıdığını ispatlamıştır.

**Çözüm:** `HashAnalyzer.calculate_avalanche_effect()` fonksiyonu çalıştırılarak algoritmaların çığ etkisi denetlenir. Değişim oranı %35 ile %65 arasında olmayan algoritmalar `AvalancheEffectFailureError` fırlatılarak doğrudan elenir.

### 4. Ustanın Çırağa Tavsiyesi
Çırağım, dağın tepesindeki bir çakıl taşını oynattığında eteğe kadar tüm dağ iniyorsa ona çığ denir. Eğer çakıl taşı yuvarlanıp iki adım ötede duruyorsa o sıradan bir taş parçasıdır. Kriptografide her fısıltı çıktıda fırtınaya dönüşmek zorundadır!

---

## Soru 3: SHA-1'i tarihe gömen Google'ın SHAttered saldırısı nasıl çalıştı ve neden yazılım dünyasında "Git commit hash'leri güvenlidir" varsayımını sarstı?

### 1. Soru Başlığı ve Tanımı
2017 SHAttered SHA-1 çakışma saldırısının mekanizması, PDF formatının iç yapısı kullanılarak yapılan sahtecilik ve Git versiyon kontrol sisteminin SHA-256'ya geçiş zorunluluğu.

### 2. Derinlemesine Teknik Analiz
SHA-1, 1995 yılında NSA tarafından tasarlanmış 160-bitlik bir hash fonksiyonudur. 2005'ten itibaren teorik zayıflıkları bilinse de pratikte bir çakışma üretilememişti.

**SHAttered Saldırısı (2017):**
Google ve CWI araştırmacıları, Merkle-Damgård blok yapısını hedef alan iki aşamalı bir diferansiyel çakışma saldırısı gerçekleştirdiler:
1. İki farklı PDF belgesi hazırlandı. Belgelerin ilk başlık blokları tamamen aynıydı.
2. Ardından gelen blokta özel olarak hesaplanmış bir diferansiyel fark ($\Delta$) yerleştirildi.
3. PDF formatının esnek yapısı kullanılarak, bu fark bloğu PDF ayrıştırıcısına bir belgede birinci resmi, diğer belgede ise tamamen farklı ikinci resmi göstermesini sağlayan bir JPEG parser manipülasyonu olarak gizlendi.
4. Yaklaşık $9 \times 10^{18}$ SHA-1 işlemi (bir GPU yılıyla 110 yıl sürecek bir işlem gücü) harcanarak **aynı SHA-1 hash'ine sahip iki farklı geçerli PDF belgesi** oluşturuldu!

**Git ve Yazılım Dünyasına Etkisi:**
Git versiyon kontrol sistemi, commit'leri, ağaçları ve dosya nesnelerini kimliklendirmek için SHA-1 kullanmaktaydı. Bir saldırgan aynı SHA-1'e sahip iki farklı kod parçası üreterek, geliştiricilerin kod incelemesinde gördüğü zararsız kaynak kodun yerine üretim ortamına arka kapı (backdoor) içeren bir kodu gizlice enjekte edebilirdi. Bu saldırı, Linus Torvalds ve Git ekibinin Git mimarisini SHA-1'den SHA-256'ya (`objectFormat = sha256`) geçirme sürecini başlattı.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir açık kaynak yazılım deposunda dağıtılan yazılım paketleri SHA-1 sağlama toplamlarıyla doğrulanmaktadır. Saldırgan, SHAttered benzeri bir çakışma bloğu kullanarak orijinal derlenmiş binary dosya ile arka kapı enjekte edilmiş binary dosyanın SHA-1 özetini eşitlemiştir. İndirme yapan kullanıcılar hash kontrolü yaptıklarında değerlerin uyuştuğunu görerek zararlı yazılımı kurmuşlardır.

**Çözüm:** Depo yöneticisi SHA-1 kontrolünü tamamen kaldırarak SHA-256 ve BLAKE2b algoritmalarını zorunlu kılmıştır. `HashAnalyzer.compute_digest()` kırılmış algoritmaları doğrudan engelleyerek geliştiricileri FIPS 180-4 standartlarına yönlendirir.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, kriptografide "şimdilik bir şey olmaz" demek, barut fıçısının üstünde sigara içmeye benzer! SHA-1'in kırılması 12 yıl sürdü ama kırıldığı gün arkasında trilyonlarca dolarlık güvensiz altyapı bıraktı. Kırılma işaretleri beliren hiçbir algoritmada bir gün bile bekleme; gemiyi hemen terk et ve sağlam limanlara (SHA-256/SHA-512) sığın!
