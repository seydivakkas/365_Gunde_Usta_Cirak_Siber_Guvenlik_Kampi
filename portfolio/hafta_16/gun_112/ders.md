# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 112: Mini Proje 15 — İmzalı Yapılandırma Konsepti (Signed Configuration Concept)

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, bu hafta seninle asimetrik kriptografinin kalbine indik; RSA ve ECC'nin matematiğini çözdük, dijital imzalarla veri bütünlüğünü kanıtladık, X.509 zincirleriyle güven ağları ördük, TLS güvenlik sınırlarıyla tüneller kazdık ve NIST SP 800-57 ile anahtarların yaşam döngüsünü yönettik. Bugün Hafta 16'nın büyük taçlandırma projesindeyiz: **İmzalı Yapılandırma Konsepti (Signed Configuration Concept)**.

**Çırak:** Hocam, yazılımlarımızın kaynak kodunu Git ile sürümlüyor, derleyip imzalıyoruz. Ancak yapılandırma dosyaları (JSON/YAML) genelde sunucuda öylece duran metin dosyalarıdır. Neden bir konfigürasyonu imzalamak bu kadar hayati bir güvenlik kalkanıdır?

**Usta:** Çünkü evlat, bir kalenin kapısını çelikten yapsan bile nöbetçi listesini (yapılandırmayı) değiştiren bir hain, kapıyı ardına kadar açabilir! Modern mikroservislerde, Kubernetes kümelerinde veya güvenlik duvarlarında tek bir port ayarını (`allow_all: true` veya `port: 80`) değiştirmek tüm savunmayı yerle bir eder. Eğer konfigürasyonun kriptografik olarak imzalanmamışsa, sunucuya sızan bir saldırgan kodu değiştiremezse bile konfigürasyonu tahrif ederek sistemi felç eder. Bugün seninle öyle bir mimari kuracağız ki, konfigürasyondaki tek bir virgül bile değişse sistem ayağa kalkmayı reddedecek!

---

## 1. Tehdit Modeli ve İmzalı Yapılandırma Mimarisi

Bir üretim ortamında yapılandırma dosyalarına yönelik 4 ölümcül saldırı vektörü mevcuttur:

1. **Doğrudan Tahrifat (Tampering / CWE-353):** Saldırgan veya yetkisiz personel `config.json` dosyasını açıp güvenlik duvarı kurallarını veya veritabanı adresini değiştirir.
2. **Rollback / Geri Alma Saldırısı (CWE-294):** Saldırgan yeni ve güvenli konfigürasyon yerine, 6 ay önce yasal olarak imzalanmış fakat bilinen bir güvenlik açığı içeren eski bir konfigürasyonu sunucuya yükler.
3. **Yetkisiz İmzalayıcı (Untrusted Signer / CWE-295):** Saldırgan kendi ürettiği bir anahtarla konfigürasyonu imzalar ve geçerli bir imza formatıyla sunucuya yutturmaya çalışır.
4. **Algoritma Düşürme (Algorithm Downgrade / CWE-327):** İmza algoritması alanına `none` yazılarak doğrulama katmanı atlatılmaya çalışılır (JWT `alg: none` zafiyetinde olduğu gibi).

```
+-----------------------------------------------------------------------------------+
|               İMZALI YAPILANDIRMA MİMARİSİ (SIGNED CONFIG PIPELINE)               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ 1. Ham Yapılandırma ] ===> [ 2. RFC 8785 Kanonikleştirici (JCS) ]              |
|                                            |                                      |
|                                            v                                      |
|                             [ SHA-256 Payload Hash ]                              |
|                                            |                                      |
|                                            v                                      |
|  [ 3. Çoklu İmza (Dual Signing) ] <== [ İmza Bloğu: Epoch + Tarih + Hash ]         |
|       - SecOps Lead (RSA-SHA256)                                                  |
|       - Infra Director (RSA-SHA256)                                               |
|                                            |                                      |
|                                            v                                      |
|  [ 4. Mühürlü Zarf (Envelope) ] ===> [ 5. Sistem Başlangıç Doğrulayıcısı (Boot) ] |
|                                            |                                      |
|                               (Tek bir kontrol bile başarısız olursa)             |
|                                            v                                      |
|                                 [ FAIL-SAFE SHUTDOWN ]                            |
+-----------------------------------------------------------------------------------+
```

---

## 2. RFC 8785 JSON Kanonikleştirme (JCS) Zorunluluğu

Kriptografik imzalarda en sık düşülen tuzak, JSON verisini ham metin olarak hash'lemektir. Oysa JSON sözlüklerinde anahtarların sırası tanımsızdır:
- `{"port": 443, "host": "local"}` ile `{"host": "local", "port": 443}` anlamsal olarak tamamen aynıdır.
- Ancak SHA-256 hash'leri tamamen farklı çıkar!
- Farklı işletim sistemlerindeki satır sonu karakterleri (`\r\n` vs `\n`) veya boşluklar imza doğrulamasını bozar.

**RFC 8785 Standardı Çözümü:**
Veri imzalanmadan önce kanonik kurallara tabi tutulur:
1. Anahtarlar sözlük hiyerarşisi boyunca alfabetik (lexicographical) olarak sıralanır.
2. Tüm gereksiz boşluklar (`separators=(',', ':')`) temizlenir.
3. Karakter kümesi kesinlikle UTF-8 olarak kodlanır.
Bu sayede verinin semantik içeriği değişmedikçe dünyanın neresinde serileştirilirse serileştirilsin deterministik tek bir hash elde edilir!

---

## 3. Anti-Rollback Kalkanı: Monotonik Epoch Sayacı (CWE-294)

Bir saldırgan geçerli imzalı eski bir dosyayı ele geçirirse ne olur? Örneğin geçen yılki güvenlik duvarı kuralında `telnet (port 23)` açıktı ve SecOps bunu yasal olarak imzalamıştı. Bu yıl telnet kapatıldı (Epoch: 5). Saldırgan sunucuya girip geçen yılki dosyayı (Epoch: 1) yerine koysa ne olur? İmza geçerlidir, içerik bozulmamıştır!

İşte bu saldırıyı **Monotonik Epoch Sayacı** engeller:
- Her yeni konfigürasyon yayınlandığında `epoch` değeri 1 artırılır ($1, 2, 3, \dots$).
- Sistem doğrulayıcısı yerel güvenli hafızasında en son kabul ettiği epoch numarasını tutar.
- Gelen konfigürasyonun epoch değeri, sistemin mevcut epoch değerinden küçükse:
  $$\text{IncomingEpoch} < \text{SystemCurrentEpoch} \implies \text{ABORT (Rollback Attack Detected!)}$$
- Sistem, meşru dahi olsa eski sürümü çöpe atar ve geriye düşürmeyi imkansız kılar.

---

## 4. Çift İmza (Dual Signing) ve Yetki Ayrımı (CWE-285)

Kritik üretim ortamlarında hiçbir tek kişinin konfigürasyonu tek başına değiştirme yetkisi olmamalıdır:
- **Politika:** Bir konfigürasyonun yürürlüğe girebilmesi için güven deposunda kayıtlı en az iki farklı otoritenin bağımsız imzası (`required_signatures = 2`) şart koşulur.
- İmzalayıcı 1: Güvenlik Mimarı (SecOps Lead).
- İmzalayıcı 2: Altyapı Operasyon Lideri (Infra Director).
- Eğer zarfta yalnızca bir imza varsa veya aynı kişi iki kez imzaladıysa doğrulayıcı `InsufficientSignaturesError` ile işlemi durdurur.

---

## 5. Fail-Safe Tutumu: Asla Açık Varsayılana Düşme!

Bir güvenlik motorunun en tehlikeli anı, doğrulama hatası aldığı andır.
- **Tehlikeli Yaklaşım (Fail-Open):** "İmza geçersiz ama sistem hizmet vermeye devam etsin, varsayılan ayarlarla açılayım."
- **Doğru Güvenlik Yaklaşımı (Fail-Safe / Fail-Closed):** Yapılandırma doğrulaması tek bir baytlık tahrifat, zaman aşımı veya imza hatası verirse, sistem derhal açılışı durdurmalı (`Emergency Exit`), alarm üretmeli ve çalışmayı reddetmelidir!

---

## Ustanın Çırağa Öğüdü
Evlat! Hafta 16 boyunca öğrendiğin her şeyi bu projede birleştirdin. Bu proje senin kriptografi ustalığının mührüdür. 
1. Koduna nasıl özen gösteriyorsan, konfigürasyonuna da öyle özen göstereceksin.
2. Kanonikleştirme olmadan imza atılmaz; determizm kriptografinin ruhudur.
3. Zaman ve epoch sayaçlarını asla ihmal etme; dün geçerli olan bir kural, bugün ölümcül bir tuzak olabilir. Bu ilkeleri aklına ve koduna kazı!
