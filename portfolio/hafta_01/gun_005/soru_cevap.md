<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 005: Soru-Cevap ve Kavram Doğrulama

Bu belge, Varlık Envanteri ve Veri Sınıflandırmasına ilişkin `SORU BANKASI` standartlarına göre katı 4 bölümlü formatta hazırlanmıştır.

---

### G005-SC1: Varlık envanteri ve veri sınıflandırması: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
Bir varlığın cihaz, uygulama, kimlik veya veri olması ona farklı koruma gereksinimleri getirir; kritiklik yalnızca parasal donanım değerine bağlı değildir. Varlık envanteri, kurumun sahip olduğu tüm dijital ve fiziksel kaynakların sahipleriyle birlikte kayıt altına alınmasıdır; veri sınıflandırması ise bu kaynakların taşıdığı bilginin gizlilik, bütünlük ve yasal etki derecesine göre derecelendirilerek uygun savunma kontrolleriyle (şifreleme, erişim yetkisi, segmentasyon) eşleştirilmesidir.

#### 2. Teknik Gerekçe
Sahip olduğun şeyi bilmeden koruyamazsın (NIST CSF ID.AM). Farklı varlık türleri farklı saldırı vektörlerine maruz kalır: Bir cihaz fiziksel hırsızlığa ve port taramasına maruz kalırken; bir kimlik kimlik avına (phishing) ve parola püskürtmeye (password spraying); bir web uygulaması SQL Injection'a; bir veri tabanı ise yetkisiz dışarı sızdırmaya (exfiltration) açıktır. Dolayısıyla her varlığa türüne ve veri sınıfına özel kontrol (cihaza BitLocker, kimliğe MFA/PAM, veriye AES-256) uygulanmalıdır.

#### 3. Yaygın Hata
Güvenlik önceliğini cihazın satın alma faturasına göre belirlemek. $45.000'lık bir güvenlik duvarını $2.500'lık bir müşteri veritabanından daha değerli sanarak bütçeyi ve koruma odak noktasını yanlış yönlendirmek.

#### 4. Standart ve Kaynak
* NIST CSF 2.0: ID.AM (Asset Management) ve PR.DS (Data Security).
* ISO/IEC 27001:2022 Ek A Madde 8.1 (Kullanıcı Uç Nokta Cihazları) ve Madde 5.12 (Bilgilerin Sınıflandırılması).

---

### G005-SC2: Varlık envanteri ve veri sınıflandırması: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Laboratuvarımızın girdisi, 5 farklı varlık türünü içeren `varlik_envanteri.json` dosyasıdır. İşlem, `asset_classifier.py` motorunun varlık kimliklerini, sahiplik alanlarını, veri sınıflarını ve kontrollerini doğrulaması; donanım maliyeti ile iş etki değeri arasındaki çarpanı (Crown Jewels Index) hesaplaması ve güvenlik uyumsuzluklarını denetlemesidir. Beklenen sonuç, 5 varlığın $69.500 donanım ve $58.050.000 iş riski ile hatasız doğrulanmasıdır. Negatif kontrol ise bir varlığın `sahip` bilgisi silindiğinde (Orphan Asset) veya şifresiz gizli veri tespit edildiğinde sistemin hata fırlatmasıdır.

#### 2. Teknik Gerekçe
Siber güvenlik denetim araçları, belirsizliği ve insan hatasını ortadan kaldırmalıdır. Sahipsiz bir varlığın (Shadow IT) varlığı, o varlığın yama yönetimi ve log takibi dışında kalması anlamına geldiğinden, envanter doğrulayıcının eksik sahiplik durumunda işlemi derhal durdurması (`AssetValidationError`) kurumsal bir güvenlik zorunluluğudur.

#### 3. Yaygın Hata
Laboratuvar ortamında yalnızca tüm alanları dolu "mükemmel" verileri test etmek; sahipsiz varlık, mükerrer ID veya sınıflandırma-kontrol uyumsuzluğu gibi sınır durumları denetlememek.

#### 4. Standart ve Kaynak
* CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets) ve Control 3 (Data Protection).
* NIST SP 800-137: Information Security Continuous Monitoring (ISCM).

---

### G005-SC3: 'Varlık envanteri ve veri sınıflandırması' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; sahipsiz varlıkların (Gölge BT) ağda unutulması, hassas verilerin sınıflandırılmayıp şifresiz açık paylaşımlarda saklanması veya kritik varlıkların yanlışlıkla DMZ gibi güvensiz ağlara yerleştirilmesiyle oluşur. Risk; periyodik envanter taramaları, otomatik veri keşif araçları (DLP) ve ağ segmentasyon denetimleriyle tespit edilir. Önleme ise zorunlu varlık sahipliği ataması, en az yetki prensibi (Least Privilege), veri minimizasyonu, şifreleme ve ağ mikro-segmentasyonu ile sağlanır.

#### 2. Teknik Gerekçe
Saldırganlar kuruma girdiklerinde genellikle en iyi korunan kapılardan değil, unutulmuş ve güncellenmeyen sahipsiz test sunucularından giriş yaparlar. Ayrıca sınıflandırılmamış veriler şifrelenmediği için saldırganın bellek veya ağ dinleme yoluyla veriyi düz metin (plaintext) olarak ele geçirmesi mümkündür. DLP araçları ve ağ tarayıcıları düzenli olarak sınıflandırılmamış varlıkları sinyal olarak yakalamalı; IAM ve şifreleme kontrolleri yetkisiz erişimi engellemelidir.

#### 3. Yaygın Hata
Veri sınıflandırmayı çalışanların inisiyatifine bırakmak veya envanter çıkarmayı bir kerelik statik bir Excel doldurma görevi olarak görmek.

#### 4. Standart ve Kaynak
* NIST SP 800-60 Vol. 1 Rev. 1: Guide for Mapping Types of Information and Information Systems to Security Categories.
* FIPS PUB 199: Standards for Security Categorization of Federal Information and Information Systems.
