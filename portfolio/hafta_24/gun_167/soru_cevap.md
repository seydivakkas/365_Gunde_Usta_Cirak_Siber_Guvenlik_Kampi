# Gün 167: Path Traversal ve Dosya Erişimi — Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. Python'da `os.path.join(base_dir, user_input)` fonksiyonu güvenli bir dosya yolu birleştirme yöntemi olarak kabul edilir mi? Bir saldırgan kullanıcı girdisi olarak mutlak bir yol (`/etc/passwd` veya `C:\Windows\System32\drivers\etc\hosts`) girdiğinde işletim sistemi düzeyinde ne gerçekleşir ve bu zafiyet nasıl engellenir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın standart kütüphane fonksiyonlarının davranışlarını ezbere kabul etmeyip derinlemesine bilmesini bekliyorum. Çoğu geliştirici `os.path.join`'in parametreleri birbiri ardına eklediğini zanneder; oysa POSIX ve Windows standartlarında mutlak yol parametresi geldiğinde önceki tüm bileşenlerin yok sayıldığını ve kök dizine sıçrandığını bilmelidir. Ayrıca `os.path.realpath` ve `os.path.commonpath` kanonik hapishane (Jail) doğrulamasının teknik matematiğini açıklamalıdır.

### Doğru Yanıt (Çırak / Aday İfadesi)
Hayır, `os.path.join(base_dir, user_input)` kesinlikle tek başına güvenli değildir ve doğrudan Path Traversal zafiyetine yol açar. Python ve POSIX/Windows yol birleştirme standartlarına göre, eğer birleştirilen argümanlardan biri mutlak bir yol ile başlıyorsa (örneğin `/etc/passwd` veya Windows'ta `C:\Windows\...`), `os.path.join` önceki tüm argümanları (bizim belirlediğimiz `base_dir` dahil) çöpe atar ve doğrudan bu mutlak yoldan itibaren birleştirir.
Örneğin:
`os.path.join("/var/www/uploads", "/etc/passwd")` ifadesinin sonucu `"/var/www/uploads/etc/passwd"` DEĞİL, doğrudan `"/etc/passwd"` olur.
Bu tuzağı engellemenin yolu, girdi üzerinde katı temizlik yapmak ve dosya yolunu kanonikleştirip (`os.path.realpath`) hedef dizinin kanonik kök dizinle başlayıp başlamadığını `os.path.commonpath([base_dir, target_path]) == base_dir` ile doğrulamaktır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Sadece `os.path.abspath` kullanmak sembolik bağlar (symlinks) karşısında yetersiz kalır; çünkü `abspath` sembolik bağları çözmez.
Doğru mimari:
1. Girdi üzerinde önce `os.path.basename` veya katı alfanümerik beyaz liste uygulanmalıdır.
2. Yol `os.path.realpath` ile kanonikleştirilmelidir; bu fonksiyon tüm sembolik bağları (`..`, `.`, junction/symlink) gerçek fiziksel konuma çözümler.
3. Çözümlenen kanonik yolun izin verilen `base_dir` kanonik yolu içerisinde kaldığı `os.path.commonpath` ile kontrol edilmelidir.
4. Girdinin mutlak yol belirteci (`/` veya `\`) içerip içermediği birleştirmeden önce denetlenmelidir.

---

### Soru:
2. Bir web uygulamasında `filename = filename.replace("../", "")` şeklinde bir filtreleme yapılmıştır. Bir saldırgan bu korumayı "İç İçe Geçmiş Dizin Atlama (Nested Traversal)" ve "Çok Katmanlı URL Kodlama (Double Encoding)" teknikleriyle nasıl kolayca bertaraf eder?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın tek geçişli (Single-Pass) kara liste temizleme yöntemlerinin neden kusurlu olduğunu; özyinelemeli/iç içe payload'ların (`....//`) çalışma mantığını ve web sunucusu ile uygulama katmanı arasındaki kod çözme (Double Decoding) uyumsuzluklarını anlayıp anlamadığını görmek istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Tek geçişli `replace("../", "")` filtresi, saldırganın `....//` dizisini göndermesi durumunda çöker. Filtre ortadaki `../` karakterini sildiğinde, dışarıda kalan `.` ve `./` karakterleri birleşerek yeni bir `../` oluşturur. Böylece `....//....//etc/passwd` girdisi filtre sonrasında `../../etc/passwd` haline gelir ve saldırı başarıyla gerçekleşir.
Çok katmanlı URL kodlamada (Double Encoding) ise saldırgan nokta ve eğik çizgi karakterlerini iki kez kodlar (`%252e%252e%252f`). Web sunucusu ilk katmanı çözdüğünde geriye `%2e%2e%2f` kalır. Uygulamanın naif filtresi bunu zararsız bir dosya adı zannedip geçirir; ardından uygulama çatısı veya dosya sistemi ikinci kez kod çözdüğünde payload `../` karakterine dönüşür.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Kara liste mantığıyla regex veya `replace` ile tehlikeli karakterleri silmeye çalışmak temelde hatalı bir paradigmadır. 
Savunma kuralları:
1. **Çoklu Kod Çözme Normalizasyonu (Multi-Pass Normalization):** Girdi, ardışık kod çözme işlemlerinde artık değişmeyene kadar (en fazla 3 döngü) çözülmeli ve gizli `%252e` türevleri maskesiz hale getirilmelidir.
2. **Karakter Silmek Yerine Reddetmek:** Şüpheli bir dizgi (`../`, `..\\`, `....//`) tespit edildiğinde temizlenmeye çalışılmamalı; istek derhal HTTP 403 / 400 ile reddedilmeli ve güvenlik alarmı üretilmelidir.
3. **Pozitif Beyaz Liste (Allowlist):** Yalnızca güvenli karakter kümesine (`^[a-zA-Z0-9_\-\.]+$`) ve izin verilen uzantılara (`.pdf`, `.png`) onay verilmelidir.

---

### Soru:
3. Null Byte Enjeksiyonu (`%00`) dosya yolu manipülasyonunda tarihsel olarak nasıl kullanılmıştır ve modern mimarilerde kullanıcı girdisini dosya sistemine doğrudan bağlamak yerine uygulanan "Dolaylı Nesne Referansı (Indirect Object Reference / UUID Mapping)" mimarisi nasıl çalışır?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın C kökenli bellek modelleri (null-terminated string) ile yüksek seviyeli diller arasındaki etkileşimi bilmesini ve dosya yönetiminde en üst düzey kurumsal mimari olan "dosya sistemi soyutlaması ve metaveri ayrımı" prensibini kavrayıp kavramadığını ölçüyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
C dilinde dizgiler `\0` (ASCII 0x00 / Null byte) karakteri ile sonlandırılır. Eski web platformlarında ve eski PHP/Python sürümlerinde `dosya_adi = user_input + ".pdf"` gibi uzantı sabitlemesi yapıldığında, saldırgan `../../etc/passwd%00` gönderirdi. Yüksek seviyeli dil bu dizgiyi C tabanlı dosya sistemi API'sine (`open()` syscall) ilettiğinde işletim sistemi ilk `\0` karakterinde dizgiyi keserdi; böylece sonuna eklenen `.pdf` tamamen yok sayılarak doğrudan `/etc/passwd` okunurdu. Modern dillerde `\0` içeren dosya yolları ValueError fırlatsa da, saldırganlar hâlâ bu bayt ile filtreleri şaşırtmaya çalışmaktadır.
Kullanıcı girdisini dosya adına bağlamaktan tamamen kurtulmanın nihai çözümü **Dolaylı Nesne Referansı (UUID Mapping)** mimarisidir: Kullanıcı yüklediği dosyanın adını belirleyemez. Sunucu rastgele bir UUIDv4 üretir, dosyayı diskte `b4f8a12c-9d...dat` adıyla saklar. Orijinal dosya adı, MIME türü ve erişim yetkileri ilişkisel bir veritabanında saklanır. Kullanıcıya yalnızca UUID referansı verilir; böylece dizin atlama saldırı yüzeyi matematiksel olarak sıfırlanır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
UUID Mapping mimarisinde kullanıcı dosya yoluna veya dosya uzantısına asla müdahale edemez.
Kurumsal akış:
1. Dosya yüklendiğinde içerik taranır, hash'i çıkarılır.
2. Diske veya nesne depolama servisine (AWS S3, MinIO, Azure Blob) `UUIDv4` adıyla yazılır.
3. Kullanıcı indirme talebinde bulunduğunda URL `/download?file_id=8f9d3b2a-1122-...` biçimindedir.
4. Uygulama veritabanından oturum sahibinin bu UUID'ye erişim hakkı olup olmadığını kontrol eder (BOLA / IDOR koruması).
5. Yanıt `Content-Disposition: attachment; filename="orijinal_ad.pdf"` başlığıyla sunulur; ancak sunucu arkada doğrudan UUID'ye karşılık gelen izole nesneyi okur. Böylece yerel dosya sisteminin hiçbir yolu dış dünyaya açılmaz.
