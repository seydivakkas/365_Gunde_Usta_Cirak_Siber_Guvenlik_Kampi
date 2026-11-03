# GÜN 013: Soru-Cevap Odası (Derinlemesine Teknik Analiz)
**Konu:** Güvenli Araştırma, Kaynak Doğrulama ve CRAAP Güvenilirlik Çerçevesi  
**Tarih:** 2026-10-27  

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G013-SC1): Güvenli araştırma ve kaynak doğrulama: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Net ve Doğrudan Yanıt
Güvenli araştırma ve kaynak doğrulama; siber güvenlikte zafiyet, tehdit ve savunma yöntemlerine dair toplanan ham bilgilerin CRAAP testi, kriptografik bütünlük (GPG/SHA-256) ve kaynak hiyerarşisi ilkeleriyle filtrelenerek doğrulanması sürecidir. Bir blog yazısı, resmî üretici bülteni ve doğrulanmamış bir forum cevabı asla aynı kanıt seviyesinde değildir; doğrulanmamış kaynaklara güvenmek kurumsal sistemlere sahte yama, zafiyetli konfigürasyon veya doğrudan Truva Atı sokulmasına yol açar.

#### 2. Derin Teknik Gerekçe ve Mantık
Siber güvenlik bilgi ekosistemi asimetrik bir bilgi kirliliğine sahiptir. Yeni çıkan zafiyetlerde (1-day / 0-day) saldırganlar bilinçli olarak dezenformasyon yayar, SEO zehirlemesi yapar veya GitHub üzerinde araştırmacıları hedef alan tuzak PoC (Trojanized Proof-of-Concept) depoları yayınlar. Bu depoların içine Base64 ile gizlenmiş tersine kabuklar (reverse shell) veya bilgi hırsızları (infostealer) yerleştirilir. Savunmacı için bilginin doğrulanması; yayın tarihi (Currency), alan adı otoritesi (Authority), kriptografik sağlama toplamı (Accuracy) ve çapraz teyit (Triangulation) mekanizmasıyla yapılır. Resmî birincil kaynaklar (NIST NVD, CVE.org, Üretici MSRC/Cisco bültenleri) dijital olarak imzalanmış kesin teknik kanıt sunarken; topluluk içerikleri yalnızca izole sandbox ortamlarında statik incelemeden geçtikten sonra dikkate alınabilir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En yaygın hata, "Arama motorunda en üstte çıkan veya GitHub'da yıldız (star) almış olan kod güvenilirdir" varsayımıdır. Saldırganlar bot hesaplarla GitHub depolarına dakikalar içinde yüzlerce sahte yıldız basabilmekte ve Google reklamlarıyla en tepeye sahte indirme linkleri yerleştirebilmektedir.

#### 4. Resmî Standart ve Kaynak
- **NIST NICE Framework:** *Knowledge Skill Ability: Threat Intelligence Analysis (K0013, K0019) & Source Verification Methodologies*.
- **ISO/IEC 27001:2022 Control 5.7:** *Threat Intelligence* (Bilgilerin güvenilir, eyleme dönüştürülebilir ve doğrulanmış kaynaklardan elde edilmesi zorunluluğu).

---

### Soru 2 (G013-SC2): Güvenli araştırma ve kaynak doğrulama: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Net ve Doğrudan Yanıt
Laboratuvarın girdisi; aynı güvenlik konusunu ele alan iki farklı kaynağı içeren sentetik vaka verisi (`guvenlik_arastirma_kaynaklari.json`) ve CRAAP doğrulama kriterleridir (`craap_dogrulama_kriterleri.json`). İşlemi; kaynakların CRAAP kriterlerine göre puanlanması, kriptografik imza/hash denetimi ve çapraz teyit (triangulation) analizi yapılmasıdır. Beklenen sonucu; resmî ve doğrulanmış kaynağın yüksek puanla (≥80) onaylanmasıdır. Negatif kontrolü ise; zehirli Truva Atı (`curl | sh`) içeren sahte PoC'un ve `chmod 777` gibi yıkıcı tavsiyelerin kırmızı bayrakla (FLAG-04, FLAG-05) tespit edilip reddedilmesidir.

#### 2. Derin Teknik Gerekçe ve Mantık
Laboratuvar motoru (`security_source_validator.py`), girdileri hiçbir dış ağa bağlanmadan, tamamen deterministik ve güvenli bir yerel ortamda ayrıştırır. Pozitif akışta, NIST NVD ve CIS Benchmark belgeleri tam puan alarak onaylanır. Negatif kontrollerde ise:
1. Anonim GitHub PoC'u içinde gizlenmiş `curl ... | sh` komutu saptanır ve `FLAG-04-ZEHIRLI-POC-TRUVA-ATI` bayrağı ile FELAKET seviyesinde reddedilir.
2. 2011 tarihli forum gönderisi hem 5 yılı aştığı için (`FLAG-01-ESKI-KAYNAK`) hem de `chmod 777` yetki kaldırma tavsiyesi içerdiği için (`FLAG-05-YIKICI-GUVENLIK-TAVSIYESI`) elenir.
3. Kriptografik imza (GPG/SHA-256) bulunmayan kaynaklar ceza puanı alır.

#### 3. Yaygın Hata ve Sektör Yanılgısı
Sektördeki yanılgı, negatif kontrol yapılmadan araştırmanın tamamlandığını düşünmektir. Gerçek dünyada bir analistin en büyük yeteneği, doğru bilgiyi bulmaktan ziyade, doğru gibi görünen zehirli ve manipüle edilmiş bilgiyi anında tespit edip çöpe atabilme refleksidir.

#### 4. Resmî Standart ve Kaynak
- **NIST SP 800-150:** *Guide to Cyber Threat Information Sharing* (Bölüm 3.4: Information Quality and Source Trust).
- **CIS Critical Security Controls v8:** *Control 10: Centralized Security Log and Source Evaluation*.

---

### Soru 3 (G013-SC3): 'Güvenli araştırma ve kaynak doğrulama' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Net ve Doğrudan Yanıt
Risk; analistin acelecilik, dikkatsizlik veya eksik bilgi nedeniyle doğrulanmamış, eski veya manipüle edilmiş kaynaklardaki kod ve yönergeleri kurumsal sistemlere uygulamasıyla oluşur. Tespit; kaynak otoritesinin olmaması, kriptografik özet (SHA-256) eksikliği, kod içinde gizlenmiş (base64/obfuscated) indiriciler ve sistem günlüklerindeki olağan dışı dış bağlantı denemeleriyle yapılır. Önleme ise; CRAAP değerlendirme çerçevesi, çift kaynaklı çapraz teyit (triangulation), kriptografik imza zorunluluğu ve izole sandbox inceleme kontrolleriyle sağlanır.

#### 2. Derin Teknik Gerekçe ve Mantık
- **Risk Mekanizması:** Saldırganlar zafiyet yönetim süreçlerine sızmak için Tedarik Zinciri ve Zehirli PoC saldırılarını kullanır. Analist, bir zafiyeti doğrulamak için indirdiği betiği yönetici haklarıyla çalıştırdığında, kurumun güvenlik personeli bizzat saldırganın içerideki truva atı haline gelir.
- **Tespit Mekanizması:**
  - *Statik Kod Taraması:* İndirilen betiklerde `eval()`, `base64_decode`, `exec()`, `curl | sh` veya harici IP adreslerine yönelik ham soket bağlantılarının aranması.
  - *Sertifika ve Hash Denetimi:* Üretici bültenindeki SHA-256 ile indirilen dosyanın hash'inin uyuşmaması (Man-in-the-Middle veya sahte ayna sunucu tespiti).
- **Önleme Kontrolleri:**
  - *Çapraz Teyit Kuralı:* Bir zafiyet veya yama en az bir birincil resmî kaynaktan (NVD/Vendor PSIRT) doğrulanmadan asla canlı sisteme dokunulmaz.
  - *Sandbox Zorunluluğu:* Tüm üçüncü taraf topluluk araçları internete çıkışı engellenmiş, geçici ve geri alınabilir sanal makinelerde çalıştırılır.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En ölümcül hata; "Bir güvenlik önlemini tek başına eksiksiz savunma sanmaktır." Yalnızca virüs tarayıcısına (antivirüs) güvenerek bir exploit betiğini çalıştırmak büyük bir hatadır; çünkü yeni üretilmiş özel bir Truva Atı (FUD - Fully Undetectable) antivirüs taramasını kolayca atlatabilir. Savunma ancak kaynak doğrulama ve sandbox mimarisiyle tam koruma sağlar.

#### 4. Resmî Standart ve Kaynak
- **MITRE ATT&CK Framework:** *Technique T1588.005: Obtain Capabilities: Exploits & T1195: Supply Chain Compromise*.
- **US CISA Cybersecurity Alert:** *Alert on Malicious Proof-of-Concept Exploits Targeting Security Researchers*.
