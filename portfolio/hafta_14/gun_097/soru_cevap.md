# GÜN 097: Mini Proje 13 — Çevrimdışı Güvenlik Araç Seti — Mülakat ve Uzmanlık Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap dokümanı kritik altyapı güvenliği, SCADA savunması ve izole sistem mühendisliği mülakatlarına hazırlık için pedagojik olarak yapılandırılmıştır.*

---

## SORU 1: Hava Boşluklu (Air-Gapped) Ortamlarda Sıfır Dış Bağımlılık (Pure Standard Library) İlkesi ve Tedarik Zinciri Güvenliği

### 1. Soru Başlığı ve Tanımı
Kritik altyapılarda (nükleer tesisler, SCADA sistemleri, askeri ağlar) güvenlik araçları geliştirilirken neden üçüncü parti harici paketler (`pip`, PyPI, npm) kesinlikle yasaklanır ve yalnızca yerel standart kütüphane (Pure Standard Library) kullanımı zorunlu tutulur? Bu yaklaşım yazılım tedarik zinciri saldırılarını (Supply Chain Attacks) nasıl engeller?

### 2. Derinlemesine Teknik Analiz
Genel yazılım dünyasında geliştiriciler hızlı prototipleme için yüzlerce üçüncü parti paket yüklerler. Ancak açık kaynak ekosisteminde şu riskler mevcuttur:
1. **Zehirli Paketler ve Typosquatting:** Popüler kütüphanelerin isim benzerlikleriyle PyPI'a zararlı yükler yüklenmektedir.
2. **Hesap Ele Geçirme (Account Takeover):** Güvenilir bir kütüphane geliştiricisinin GitHub veya PyPI hesabı çalındığında, yeni sürüme arka kapı (backdoor) enjekte edilebilmektedir (Örn: XZ Utils, SolarWinds, EventStream vakaları).
3. **Gizli Telemetri ve Veri Sızıntısı:** Birçok harici paket, geliştiricisinin sunucularına kullanım istatistiği, IP veya telemetri verisi göndermeye çalışır.

Hava boşluklu ortamlarda sistemlerin dış dünyaya fiziksel olarak hiçbir bağlantısı yoktur. Eğer bir güvenlik mühendisi USB bellek ile içeri aktardığı bir betikte harici bir `requests` veya derlenmiş C uzantısı (binary wheel) çalıştırırsa:
- Paket ya eksik dinamik kütüphaneler yüzünden çöker,
- Ya da kontrolsüz bir bağımlılık ağacı yüzünden denetlenemez güvenlik riskleri doğurur.

Python'un yerleşik standart kütüphanesi (`hashlib`, `hmac`, `re`, `tracemalloc`, `time`, `json`, `os`), Python Vakfı tarafından en katı güvenlik standartlarıyla denetlenen, CPython çekirdeğiyle gömülü gelen ve internete ihtiyaç duymayan tek güvenilir temeldir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir enerji dağıtım santralinin SCADA merkezinde bir analist, PLC yapılandırmalarını denetlemek için internetten indirdiği açık kaynaklı bir Python kütüphanesini USB bellek ile izole ortama sokmuştur. Kütüphanenin içinde gizlenmiş olan zararlı bir komut dizisi, izole ağdaki yerel yayın (broadcast) paketlerini dinleyerek santralin PLC kontrol portlarını (Port 502 Modbus) hedef almış ve türbin kontrolörlerini durdurmuştur.

**Pratik Çözüm:**
Santralde "Air-Gap Güvenlik Protokolü" devreye alınmış; harici paketlerin içeri sokulması tamamen yasaklanmıştır. Tüm denetim araçları `sec_toolkit` mimarisiyle, yalnızca Python Standart Kütüphanesi kullanılarak yeniden yazılmış ve `sec_toolkit doctor` komutu ile ortama üçüncü parti hiçbir modülün sızmadığı doğrulanmıştır.

### 4. Ustanın Çırağa Tavsiyesi
Çırak, modern yazılımcıların çoğu bir HTTP isteği atmak veya hash almak için 10 tane kütüphane indirir. İnternet varken herkes geliştiricidir. Asıl mühendislik, internetin fişi çekildiğinde elindeki temel taşlarla piramit inşa edebilmektir. Standart kütüphaneye hakim olan bir analistin bileğini hiçbir saldırgan bükemez.

---

## SORU 2: İzole SCADA/ICS Sistemlerinde Dosya Bütünlük İzleme (FIM) ve Firmware Tahrifatı Savunması

### 1. Soru Başlığı ve Tanımı
İnternet bağlantısı olmayan izole endüstriyel kontrol sistemlerinde (ICS/SCADA), bir saldırganın yerel erişimle veya USB üzerinden gerçekleştirebileceği yapılandırma/firmware tahrifatları (Stuxnet benzeri saldırılar) Dosya Bütünlük İzleme (FIM) taban çizgisi mimarisi ile nasıl engellenir?

### 2. Derinlemesine Teknik Analiz
Stuxnet gibi gelişmiş kalıcı tehditler (APT), hava boşluklu sistemlere genellikle taşınabilir depolama birimleri (USB bellekler) veya bakım teknisyenlerinin dizüstü bilgisayarları üzerinden bulaşır. Saldırganın ilk hedefi kritik kontrol yazılımlarının DLL dosyalarını, PLC lojik bloklarını veya sistem konfigürasyonlarını değiştirmektir.

Geleneksel imza tabanlı antivirüsler çevrimdışı ortamlarda imza veritabanlarını güncelleyemedikleri için yeni tahrifatları tespit edemezler. Çözüm, **Matematiksel Taban Çizgisi (Cryptographic Baseline) ve FIM** yaklaşımıdır:
1. **Temiz Durumun Mühürlenmesi (Baseline):** Sistem ilk güvenli kurulum anında, tüm kritik dosya ve dizinlerin SHA-256 kriptografik özetleri 64 KB parçalı akışla hesaplanır ve değiştirilemez bir JSON taban çizgisine yazılır.
2. **Periyodik Bütünlük Taraması (Integrity Scan):** Sistem periyodik olarak tüm dosyaların anlık özetini hesaplar ve `hmac.compare_digest` ile taban çizgisiyle karşılaştırır.
3. **Anomali Sınıflandırması:**
   - `MODIFIED`: Boyutu aynı kalsa bile içeriği 1 bayt değişen dosyalar anında yakalanır.
   - `ADDED`: Sisteme sızdırılan yetkisiz ikili dosyalar veya betikler tespit edilir.
   - `REMOVED`: Silinen güvenlik logları veya denetim modülleri açığa çıkarılır.

Bu sayede saldırgan dosyanın değiştirilme zaman damgasını (timestamp) tahrif etse (timestomping) dahi kriptografik hash değişeceği için saldırı anında alarm üretir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir petrol rafinerisinde izole PLC kontrol sunucusunda çalışan `system_conf.ini` dosyasında bir parametre (basınç emniyet vanası eşiği) fiziksel erişim sağlayan bir saldırgan tarafından 100 bar'dan 250 bar'a çıkarılmıştır. Dosya boyutu ve tarihi değiştirilmediği için standart Windows Gezgini ile fark edilememiştir.

**Pratik Çözüm:**
Arka planda çalışan çevrimdışı FIM tarayıcısı devreye girmiş; taban çizgisiyle anlık SHA-256 özetini kıyaslayarak uyuşmazlığı tespit etmiştir:
```bash
$ sec_toolkit fim --dir /scada/config/ --action scan --baseline-file base.json
{"MODIFIED": ["system_conf.ini"], "ADDED": [], "REMOVED": []}
[Çıkış Kodu: 1 - KRİTİK GÜVENLİK İHLALİ]
```
Sistem derhal acil durum protokolünü tetiklemiş ve basınç vanası manuel kilitlenerek felaket önlenmiştir.

### 4. Ustanın Çırağa Tavsiyesi
Bir dosyaya dışarıdan bakarak güvenli olduğunu anlayamazsın evlat. Saldırgan dosyanın adını, boyutunu, hatta tarihini taklit edebilir. Ama kriptografik özeti taklit edemez. Bütünlük mühürdür; mühür kırılmışsa içeriye düşman girmiştir.

---

## SORU 3: Hava Boşluklu Sistemlerden Adli Kanıt ve Log Çıkarırken DLP Maskeleme Zorunluluğu

### 1. Soru Başlığı ve Tanımı
Hava boşluklu bir ağda meydana gelen bir güvenlik olayı sonrasında, adli inceleme veya dış denetim amacıyla log dosyaları izole alandan dışarı çıkarılırken neden yerel bir DLP (Data Loss Prevention) maskeleme motorundan geçirilmek zorundadır? Bu sürecin KVKK, GDPR ve gizlilik hukuku açısından bağlayıcılığı nedir?

### 2. Derinlemesine Teknik Analiz
İzole sistemlerde çalışan personelin kimlik bilgileri, özel anahtarlar, HSM parolaları ve endüstriyel sırlar telemetri ve sistem loglarına yazılabilir. Bir denetim veya arıza analizi için bu logların harici bir analiste veya üretici firmaya iletilmesi gerektiğinde iki zıt güvenlik ihtiyacı çarpışır:
1. **Analitik İhtiyaç:** Analistin sistemin nasıl çalıştığını, hangi kullanıcının hangi saatte ne işlem yaptığını anlaması gerekir.
2. **Gizlilik ve Sızıntı Koruması (CWE-359 / CWE-532):** Logların içindeki TCKN, kredi kartı, şifre ve token'ların izole bölge dışına düz metin olarak çıkarılması yasal bir suçtur ve kritik sırların sızmasına yol açar.

Çözüm, **Çevrimdışı Deterministik DLP Maskeleme** motorudur:
- Loglar dışarı aktarılmadan önce hava boşluklu makinede taranır.
- Luhn algoritmasıyla kartlar, modüler algoritmayla TCKN'ler tespit edilir.
- İki aşamalı maskeleme uygulanır:
  - Format koruyucu maskeleme (`123******50`, `453201******0366`): Hata ayıklama için operatörün formatı görmesini sağlar.
  - Kriptografik Pseudonymization (`TCKN#a8f1...`): Dış analistin aynı kullanıcının hareketlerini kimliğini bilmeden korele etmesini sağlar.
- Null-byte enjeksiyonları (`\x00`) temizlenerek adli ayrıştırıcıların zehirlenmesi önlenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir savunma sanayii laboratuvarında çalışan yazılımın çökme raporu (crash dump) ve logları, yazılımı geliştiren dış tedarikçiye gönderilecektir. Logların içinde operatörlerin T.C. Kimlik Numaraları ve HSM erişim token'ları bulunmaktadır. Güvenlik politikası gereği ham logların dışarı çıkışı yasaktır.

**Pratik Çözüm:**
Loglar dışarı alınmadan önce izole ortamda `sec_toolkit mask` aracıyla taranır:
```bash
$ sec_toolkit mask --file sensitive_traffic.log --style MASK > sanitized_traffic.log
```
Tüm TCKN ve token'lar algoritmik olarak maskelenir; hassas veriler temizlenmiş olarak üreticiye iletilir. Ne sistem sırları dışarı sızar ne de hata ayıklama yeteneği kaybolur.

### 4. Ustanın Çırağa Tavsiyesi
Veri dışarı çıktığı an senin kontrolünden çıkar evlat. Bir log dosyasını bir e-postaya eklemeden veya bir USB'ye kopyalamadan önce "bu dosyayı saldırganın eline versem bana zarar verebilir mi?" sorusunu soracaksın. Maskeleme senin son savunma hattındır; o hattı asla boş bırakma.
