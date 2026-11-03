<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 072: Soru ve Cevaplar (Değişkenler, Veri Tipleri ve Güvenli Giriş Doğrulama)

---

## G072-SC1: Python Dinamik Tip Sisteminde `isinstance(True, int)` Miras Tuzağı ve Tip Karmaşası Güvenliği

### Soru Başlığı ve Tanımı
Python programlama dilinde `bool` sınıfının `int` sınıfından kalıtım alması (`issubclass(bool, int) == True`) nedeniyle ortaya çıkan tip karmaşası (Type Confusion) zafiyeti nedir ve siber güvenlik araçlarında beklenmeyen mantıksal hatalara yol açmaması için nasıl engellenir?

### Derinlemesine Teknik Analiz
Python 2.2 ve 2.3 sürümlerinde boolean tipi dile sonradan eklenirken, geriye dönük uyumluluk (backward compatibility) amacıyla `bool` sınıfı `int` sınıfının doğrudan bir alt sınıfı (subclass) olarak tasarlanmıştır. Bu tasarım kararı gereğince:
1. **İçsel Temsil:** `True` sabiti `1`, `False` sabiti ise `0` tamsayı değerini taşır.
2. **Tip Kontrolü Yanılsaması:** `isinstance(val, int)` kontrolü çalıştırıldığında, `val` eğer bir `bool` ise Python kalıtım zincirini takip ederek `True` döndürür.
3. **Güvenlik Riski:** Bir güvenlik otomasyonunda kullanıcıdan port numarası, kullanıcı kimliği (UID) veya işlem önceliği (priority) gibi tamsayı alanlar beklenirken; JSON ayrıştırıcıdan veya parametrelerden gelen `{"port": true}` girdisi `isinstance(val, int)` süzgecinden başarıyla geçer. Bu durum, aracın `1` numaralı portu (TCP Multiplexing) hedef almasına veya `1` numaralı UID'ye (daemon) yetkisiz işlem yapmasına yol açar.
4. **Savunma Mantığı:** Tip denetiminde `isinstance(val, int)` çağrılmadan önce açıkça `if isinstance(val, bool): raise SecureInputValidationError(...)` kontrolü yapılmalı ya da `type(val) is int` ile katı tip eşitliği aranmalıdır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir güvenlik ekibi, kurum içi sunucularda çalışan servislerin portlarını uzaktan tarayan bir Python CLI aracı geliştirmiştir. Aracın API uç noktasına gönderilen JSON yükünde bir kullanıcı `{"target_port": true}` değeri gönderir. API katmanı `isinstance(port, int)` kontrolü yaptığı için hata vermez ve soket `1` numaralı porta bağlanmaya çalışır. Bu durum, loglarda sahte alarmlara ve arka uçta iş parçacıklarının kilitlenmesine neden olur.
**Pratik Çözüm:** `SecureInputAndTypeValidator.validate_integer()` fonksiyonumuz, girdi üzerinde ilk olarak `if isinstance(val, bool): raise SecureInputValidationError(...)` kuralını çalıştırarak tip karmaşasını kökünden engeller.

### Ustanın Çırağa Tavsiyesi
Çırak, Python'ın "her şey bir nesnedir" esnekliği senin en büyük düşmanın olabilir. Bir fonksiyon tamsayı bekliyorsa, boolean'ın tamsayı kılığına girip kapıdan geçmesine izin verme. Nüfus cüzdanını doğrudan kontrol et, benzerliğe aldanma!

---

## G072-SC2: Dizin Atlatma (Path Traversal) Savunmasında `os.path.commonpath` Algoritmasının Matematiksel Üstünlüğü

### Soru Başlığı ve Tanımı
Kullanıcıdan dosya veya dizin yolu alan siber güvenlik uygulamalarında, klasik metin tabanlı filtrelerin (örneğin `../` kaldırma) yetersiz kalmasının sebebi nedir ve `os.path.commonpath` fonksiyonu dizin atlatma saldırılarına karşı nasıl kesin bir matematiksel bariyer oluşturur?

### Derinlemesine Teknik Analiz
Dizin atlatma (CWE-22 / Path Traversal) saldırılarında amaç, uygulamanın çalışması için tahsis edilen güvenli temel dizinin (jail/sandbox) dışına çıkarak `/etc/passwd`, `/etc/shadow` veya Windows SAM/SYSTEM gibi hassas dosyalara erişmektir.
1. **Metin Filtreleme Zafiyeti:** Acemi geliştiriciler `filename.replace("../", "")` veya regex ile `\.\.` araması yaparlar. Saldırganlar bu filtreleri `....//` (içteki `../` silinince dıştakiler birleşip `../` olur), URL kodlaması (`%2e%2e%2f`), Unicode eşdeğerleri veya ters bölü (`..\..\`) kullanarak kolayca aşarlar.
2. **Mutlak Yol Çözümleme (`abspath`):** İlk adım olarak göreli yol işletim sisteminin dosya sistemi mantığıyla mutlak yola dönüştürülür: `abs_target = os.path.abspath(os.path.join(base_dir, untrusted_filename))`. Bu işlem sembolik bağları, göreli noktaları ve çift bölüleri çözer.
3. **Matematiksel Küme Kesişimi (`commonpath`):** `os.path.commonpath([abs_base, abs_target])` fonksiyonu, iki mutlak yolun paylaştığı en derin ortak ata dizini döndürür. Eğer hedef dosya gerçekten `abs_base` dizini veya onun bir alt dizini içindeyse, ortak ata **kesinlikle `abs_base` olmak zorundadır**:
   $$\text{commonpath}([\text{abs\_base}, \text{abs\_target}]) == \text{abs\_base}$$
   Eğer saldırgan `../../` ile bir üst dizine çıkmışsa, ortak yol `abs_base`'in bir üst klasörü (örneğin `C:\Users` veya `/etc`) olacaktır ve eşitlik bozulacaktır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir web tabanlı PCAP analiz aracı, kullanıcıların analiz edilecek yakalama dosyasının adını parametre olarak seçmesine izin verir: `GET /analyze?file=test.pcap`. Saldırgan `file=../../../../Windows/win.ini` gönderir. Kod yalnızca `../` temizliği yaptığı için işletim sistemi Windows API'sinde `..\` karakterini tanır ve sistem dosyasını okuyarak web sayfasında gösterir (Local File Inclusion).
**Pratik Çözüm:** `SecureInputAndTypeValidator.validate_safe_path()` metodumuz, hem Unix hem Windows uyumlu olarak `os.path.commonpath` karşılaştırması yapar. Temel dizin eşleşmediği anda `SecureInputValidationError("Dizin atlatma tespiti")` fırlatarak saldırıyı önler.

### Ustanın Çırağa Tavsiyesi
Evlat, dosya yolları bir labirenttir. Saldırgan labirentin duvarlarından atlamak için her işletim sisteminin farklı kaçış karakterlerini dener. Labirentin dışına çıkılıp çıkılmadığını metinle arayarak anlayamazsın; mutlak koordinatları hesaplayıp sınır kapısını kontrol edeceksin.

---

## G072-SC3: Unicode Kanonikleştirme (NFKC) ve Null Byte (`\x00`) Zehirlemesine Karşı Derin Savunma

### Soru Başlığı ve Tanımı
Kullanıcı girdilerinin güvenlik doğrulamasına sokulmadan önce kanonikleştirilmesi (Canonicalization) ne anlama gelir, Unicode NFKC normalizasyonu ve Null Byte (`\x00`) filtrelemesi yapılmadığında güvenlik mekanizmaları nasıl atlatılabilir?

### Derinlemesine Teknik Analiz
Bir verinin bilgisayar sistemlerinde birden fazla farklı bayt dizilimiyle temsil edilebilmesine "Kanonik Olmama (Non-Canonical Form)" denir.
1. **Unicode NFKC (Compatibility Decomposition and Canonical Composition):** Unicode standardında görsel olarak aynı veya benzer olan ancak farklı kod noktalarına (code points) sahip binlerce karakter vardır (Homoglyph ve Fullwidth karakterler). Örneğin standart Latin `A` (`U+0041`) ile tam genişlikli `Ａ` (`U+FF21`) farklı baytlardır. Eğer bir güvenlik filtresi `admin` kelimesini engelliyorsa, saldırgan `\uFF41dmin` göndererek filtreyi aşabilir. Python `unicodedata.normalize('NFKC', text)` çalıştırıldığında, tüm uyumluluk varyantları tek ve standart ASCII/Unicode temsiline indirgenir.
2. **Null Byte (`\x00`) Zehirlemesi (C-String Termination):** Python dizeleri (strings) uzunluk tabanlı (length-prefixed) nesnelerdir ve içlerinde `\x00` baytı barındırabilirler. Ancak Python'ın alt katmanında çalışan C kütüphaneleri ve işletim sistemi çekirdeği (Kernel), dizeleri `\x00` (null terminator) görene kadar okur.
   - Saldırgan dosya adını `delil.log\x00.evil.exe` olarak gönderir.
   - Python seviyesindeki regex kontrolü uzantıyı `.evil.exe` görüp engelleyebilir ya da tersine, `.log` olduğunu onaylayabilir.
   - İşletim sistemine `open()` çağrısı yapıldığında C katmanı `\x00`'da durur ve `delil.log` dosyasının üzerine yazar.
3. **Derin Savunma Kuralı:** Girdi işleme boru hattında doğrulama yapılmadan önce **ilk işlem** her zaman kanonikleştirme, null byte temizliği ve normalizasyon olmalıdır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir siber istihbarat platformu, şüpheli etki alanlarını (domains) sisteme kaydetmeden önce kara liste kontrolü yapmaktadır. Saldırgan, yasaklı `banka.com` adresini sisteme kaydettirebilmek için Latin 'a' yerine Kiril alfabesindeki 'а' (`U+0430`) karakterini kullanarak `bаnkа.com` gönderir. Regex filtreleri Latin alfabesi aradığı için alan adını onaylar ve saldırgan kimlik avı (phishing) altyapısını sisteme entegre eder.
**Pratik Çözüm:** `SecureInputAndTypeValidator.canonicalize_string()` metodumuz, girdideki her karakteri NFKC normalizasyonundan geçirir, `\x00` tespit ettiği an derhal işlemi durdurur ve temizlenmiş metni doğrulama motoruna iletir.

### Ustanın Çırağa Tavsiyesi
Çırak, kirli suyla yemek yapılmaz! Bir girdiyi önce arıtma tesisinden (kanonikleştirme) geçireceksin, içindeki görünmez zehirleri (null byte, gizli kodlamalar) süzeceksin, ancak ondan sonra tencereye (mantıksal işleme) atacaksın. Sıralamayı şaşırma!
