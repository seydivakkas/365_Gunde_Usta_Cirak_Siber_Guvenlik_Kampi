# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 084: Soru-Cevap ve Güvenlik Senaryoları (Mini Proje 11)

---

### Soru 1: Log Toplama ve Analiz Boru Hatlarında Log Injection (CWE-117) ve SIEM Körlüğü

#### Soru Başlığı ve Tanımı
Log Enjeksiyonu (Log Forgery / CWE-117) nedir; bir saldırgan HTTP istek parametrelerine veya kullanıcı adı alanlarına CRLF (`\r\n`) karakterleri enjekte ederek SIEM sistemlerini ve güvenlik analistlerini nasıl manipüle eder?

#### Derinlemesine Teknik Analiz
Web sunucuları ve uygulama loglayıcıları genellikle metin tabanlı (line-delimited) dosyalara kayıt yazar. Her log satırı yeni bir olayı simgeler.
Eğer uygulama istemciden gelen veriyi (örneğin kullanıcı adı, HTTP başlığı veya sorgu parametresi) doğrudan loga yazarsa:
1. Saldırgan kullanıcı adı alanına `alice\r\n[2026-11-01T04:00:00Z] [INFO] root login successful from 127.0.0.1` enjekte eder.
2. Log dosyasında bu girdi tek satır yerine iki ayrı satır olarak belirir.
3. İkinci satır tamamen saldırganın kurguladığı sahte bir olay kaydıdır.
4. Bu durum iki büyük tehlike doğurur:
   - **Adli Delil Karartma:** Gerçekte başarısız olan bir yetkisiz erişim, loglarda meşru bir yönetici oturumu gibi gösterilebilir.
   - **SIEM / Parser Çökertme:** Regex veya pozisyonel indeksleme kullanan SIEM ayrıştırıcıları beklenmeyen satır sonlarıyla karşılaşınca kural eşleştirmelerini kaçırır ve "SIEM körlüğü" (blind spot) oluşur.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankacılık uygulamasında saldırgan şüpheli transfer denemeleri yapmaktadır. Her denemede açıklama alanına CRLF ve sahte onay mesajları enjekte eder. Denetim ekibi logları incelerken sahte onay kayıtlarını görüp saldırıyı fark edemez.

**Pratik Çözüm:**
`TestedSecurityLogTool` mimarisinde `LogContentSanitizer.sanitize_line()` katmanı yer alır.
- Girdi metni incelenir; `\r\n` karakterleri tespit edildiğinde tek bir boşluk (`" "`) ile değiştirilerek satırın fiziksel olarak ikiye bölünmesi kesin olarak engellenir.
- Eğer sistem kritik/katı modda (`strict=True`) çalıştırılıyorsa, CRLF karakteri görüldüğü an log satırı işleme alınmaz ve `LogInjectionAttemptException` fırlatılarak saldırı anında SOC ekibine raporlanır.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, bir log satırı tek bir atomik gerçekliktir. Eğer bir kullanıcı girdisi o satırı ikiye bölebiliyorsa, logların artık gerçekliği değil saldırganın senaryosunu anlatıyor demektir. CRLF'i her zaman kapıda temizle!"

---

### Soru 2: PCI-DSS ve KVKK/GDPR Kapsamında Loglarda Hassas Veri (PAN ve Kimlik Bilgisi) Maskeleme Stratejileri

#### Soru Başlığı ve Tanımı
Ödeme Kartı Sektörü Veri Güvenliği Standardı (PCI-DSS Gereksinim 3.4) ve KVKK/GDPR düzenlemelerine göre log dosyalarında kredi kartı birincil hesap numaralarının (PAN), parolaların ve kişisel verilerin açık metin saklanması neden yasaktır? Log aracında bu veriler performans kaybı yaşanmadan nasıl maskelenir?

#### Derinlemesine Teknik Analiz
PCI-DSS standardı, kredi kartı PAN numarasının ilk 6 ve son 4 hanesi haricindeki kısımların okunamaz (maskeli, şifreli veya tokenlaştırılmış) olmasını emreder. Benzer şekilde kullanıcı parolaları, API gizli anahtarları ve session/bearer tokenları log dosyalarına yazıldığında (CWE-532):
1. Log dosyaları genellikle birden fazla geliştirici, DevOps mühendisi ve üçüncü taraf izleme aracı tarafından okunabilir;
2. Log yedekleri ve SIEM depoları sızdırıldığında tüm müşteri kartları ve kimlik bilgileri saldırganların eline geçer;
3. Bu durum ağır regülasyon cezalarına ve kurumsal itibar kaybına yol açar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret ödeme mikroservisi hata ayıklama (debugging) amacıyla gelen tüm JSON istek gövdesini olduğu gibi `logger.info(req.body)` ile diske yazmıştır. Sızan bir log yedeğinde binlerce müşterinin kredi kartı ve CVV kodlarının açık metin durduğu tespit edilmiştir.

**Pratik Çözüm:**
`TestedSecurityLogTool` içerisinde önceden derlenmiş (compiled regex) yüksek performanslı arındırıcılar kullanılır:
1. `CREDIT_CARD_PATTERN`: `\b(?:\d{4}[-\s]?){3}(\d{4})\b` deseni yakalanarak `****-****-****-\1` ile değiştirilir.
2. `PASSWORD_PATTERN`: `(?i)\b(password|secret)\s*[:=]\s*['"]?([^'\"\s]+)['"]?` deseni yakalanarak `\1=***REDACTED***` ile maskelenir.
3. `AWS_KEY_PATTERN`: `AKIA...` anahtarları `AKIA***REDACTED***` haline getirilir.
4. `BEARER_PATTERN`: JWT tokenları `Bearer [REDACTED_JWT]` olarak anonimleştirilir.

#### Ustanın Çırağa Tavsiyesi
"Evladım, log dosyası geliştiricinin karalama defteri değildir. Bir gün bir saldırgan o log dosyalarını ele geçirdiğinde aradığı tek bir şifre veya kart numarası bulamamalıdır. Maskeleme işini geliştiricinin vicdanına değil, log aracının otomatik filtresine emanet edeceksin."

---

### Soru 3: Güvenlik Log Aracının Kendi Güvenliği: Path Traversal ve DoS Koruması

#### Soru Başlığı ve Tanımı
Bir güvenlik log analiz aracı, harici log dosyalarını okurken kendisi nasıl bir saldırı vektörüne (CWE-22 Path Traversal, CWE-59 Symlink Attack, CWE-400 Resource Exhaustion) dönüşebilir? Fail-closed mimari ile bu riskler nasıl bertaraf edilir?

#### Derinlemesine Teknik Analiz
Saldırganlar güvenlik araçlarının "yüksek yetkili" çalıştığını bilir. Eğer log analiz aracına dışarıdan bir dosya yolu parametresi verilebiliyorsa:
1. **Path Traversal (CWE-22):** `../../../../etc/shadow` veya `../../windows/system32/config/SAM` yolu verilerek log aracı bir keylogger/dosya okuyucu gibi kullanılabilir.
2. **Symlink Tuzağı (CWE-59):** Log dizini içine zararsız görünen `app.log` adında bir sembolik bağ konur, ancak bu bağ `/etc/passwd` dosyasına işaret eder. Araç sembolik bağı takip ederek gizli sistem dosyasını okur ve içeriğini arayüze döker.
3. **Log Bomb / DoS (CWE-400):** Gigabaytlarca uzunlukta tek bir satır veya döngüsel veri gönderilerek log aracının belleği (RAM) tüketilir ve loglama servisi çökertilir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir web tabanlı log görüntüleme panelinde yönetici "İncelenecek log dosyasını seçin" alanına sahiptir. Saldırgan buraya path traversal ile sistem dosyası yolu göndererek sunucu parolalarını tarayıcısında okumuştur.

**Pratik Çözüm:**
`TestedSecurityLogTool` fail-closed mimari ile üçlü kontrol uygular:
1. `SecureLogPathResolver`: Yol mutlaklaştırılmadan önce `is_symlink()` ile kontrol edilir. Ardından `resolve()` edilip `relative_to(allowed_base_dir)` ile sınır denetimi yapılır. Dizin dışına taşma varsa `SecurityPathTraversalException` veya `SymlinkViolationException` fırlatılır.
2. `Null-Byte Denetimi`: Yolda veya satırda `\x00` varsa `NullByteForbiddenException` ile reddedilir.
3. `Maksimum Satır Uzunluğu`: 4096 karakterden uzun satırlar DoS korumasıyla `...[TRUNCATED]` ile kırpılır veya `strict=True` modunda `LogLineLengthLimitException` fırlatılır.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, kale kapısını koruyan muhafızın kendisi sarhoş olursa kapıyı kilitlemenin anlamı kalmaz. Güvenlik aracı yazarken ilk önce 'Bu aracı bana karşı nasıl kullanabilirler?' diye soracaksın. Temel dizini sınırla, sembolik bağlara güvenme, sınırsız hiçbir girdiyi belleğe alma!"
