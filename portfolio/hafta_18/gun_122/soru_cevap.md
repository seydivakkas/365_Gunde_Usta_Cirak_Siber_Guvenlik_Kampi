# GÜN 122: Savunma Derinliği ve Kontrol Tipleri Soru - Cevap Dokümanı

## SORU 1: Modern Güvenlik Mimarilerinde 'Perimeter-Only' (Yalnızca Çevre) Savunma Yaklaşımı Neden Çökmüştür ve Savunma Derinliği (Defense-in-Depth) Bunu Nasıl Aşar?

### 1. Soru Başlığı ve Tanımı
Geleneksel "Kale ve Hendek" (Castle-and-Moat) olarak bilinen dış ağ güvenlik duvarı odaklı sınır güvenliği anlayışı modern tehditler karşısında neden yetersiz kalmaktadır ve 7 katmanlı Savunma Derinliği mimarisi bu açığı nasıl kapatır?

### 2. Derinlemesine Teknik Analiz
Geleneksel çevre güvenliği modeli (Perimeter Security), ağı "dışarısı güvensiz, içerisi tamamen güvenli" ikilemiyle ele alır. Bu yaklaşımın çöküş nedenleri:
1. **İç Ağda Yanal Yayılma Serbestisi (Unrestricted Lateral Movement):** Saldırgan oltalama (phishing), VPN zafiyeti veya tedarik zinciri saldırısıyla çevre duvarını bir kez aştığında, iç ağda hiçbir mikro-segmentasyon veya kimlik kontrolüyle karşılaşmaz (CWE-653).
2. **Sınırların Silinmesi (Perimeter Dissolution):** Bulut bilişim (AWS/Azure/GCP), uzaktan çalışma (WFH), SaaS uygulamaları ve mobil cihazlar nedeniyle fiziksel bir "çevre" kalmamıştır. Veri ve kullanıcılar dağıtık haldedir.
3. **İç Tehditler (Insider Threats):** Kötü niyetli veya ihmalkar iç çalışanlar zaten çevre duvarının içindedir; dolayısıyla sınır güvenlik duvarları onların yapacağı veri sızıntılarına karşı tamamen kördür.

**Savunma Derinliği Çözümü:**
Savunma Derinliği (DiD), güvenliği tek bir hatta toplamak yerine 7 katmana dağıtır (Fiziksel -> Çevre -> İç Ağ -> Uç Nokta -> Uygulama -> Veri -> Kimlik). Saldırgan birinci katmanı (örneğin dış güvenlik duvarını) delse bile, ikinci katmanda mikro-segmentasyona takılır; onu aşsa uç noktada EDR'a yakalanır; onu aşsa veritabanında AES-256 şifreleme ve DLP engeliyle karşılaşır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekomünikasyon şirketi milyonlarca dolar harcayarak çevreye en güçlü NGFW ve DDoS cihazlarını kurmuştur. Ancak bir çalışanın dizüstü bilgisayarına oltalama e-postasıyla sızan fidye yazılımı (Ransomware), iç ağda hiçbir VLAN/ZTNA kısıtlaması olmadığı için 12 dakika içinde Active Directory dahil 400 sanal sunucuya yayılmış ve tüm şirketi kilitlemiştir.

**Pratik Çözüm:**
1. **İç Ağ Mikro-Segmentasyonu:** Sunucular rol bazlı izole alt ağlara bölünür; muhasebe ile IT veya DMZ ile veritabanı arasındaki Doğu-Batı trafiği engellenir (CWE-653 önlenir).
2. **Uç Nokta EDR ve FIM:** Her sunucuya anomali tespit eden ve şüpheli şifreleme aktivitesini anında donduran EDR kurulur.
3. **Değiştirilemez Yedekleme (Immutable Backup):** Veri katmanında, ransomware'in şifreleyemeyeceği WORM (Write Once Read Many) çevrimdışı yedekler devreye alınır.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, sadece bahçe kapısını kilitleyip evin pencerelerini, çelik kasasını ve oda kapılarını açık bırakamazsın! Bahçe kapısı bir gün rüzgardan da açılır, bir posta görevlisinin dikkatsizliğinden de. Gerçek güvenlik uzmanı, dış kapının her an kırılabileceğini varsayan ve evin içindeki her odayı ayrı bir kale gibi inşa eden kişidir."

---

## SORU 2: Bir Katmanda Yalnızca 'Önleyici' (Preventive) Kontrol Bulunup 'Tespit Edici' (Detective) Kontrol Bulunmaması Neden Ölümcül Bir 'Kör Nokta' (Blind Spot) Yaratır?

### 1. Soru Başlığı ve Tanımı
Savunma mimarisinde yalnızca önleyici kontrollerin (örn: WAF, Disk Şifreleme) konuşlandırılıp tespit ve izleme kontrollerinin (SIEM, FIM, NIDS) ihmal edilmesi neden kritik bir güvenlik açığıdır ve bu durum tespit süresini (Dwell Time) nasıl etkiler?

### 2. Derinlemesine Teknik Analiz
Güvenlik literatüründe kabul görmüş temel bir aksiyom vardır: **"Engelleyemediğini tespit et, tespit edemediğini yönetemezsin."**

Yalnızca önleyici kontrol kullanmanın doğurduğu teknik zafiyetler:
1. **Sessiz Atlatma (Silent Bypass):** Hiçbir önleyici kontrol %100 kusursuz değildir. WAF kuralları karmaşık karakter kodlamalarıyla (Unicode/Hex/Double-Encoding), EDR'lar bellek enjeksiyonuyla (Process Hollowing / Reflective DLL Loading) atlatılabilir. Eğer o katmanda tespit edici (Detective) mekanizma ve günlükleme yoksa saldırgan sistemi sessizce aşar.
2. **Keşif ve Fuzzing Serbestisi:** Saldırgan önleyici kontrolü aşmak için binlerce istek atar. Tespit kontrolü yoksa bu denemeler hiçbir SOC analistine alarm olarak düşmez; saldırgan rahatça zafiyeti keşfeder.
3. **Dwell Time Patlaması:** Saldırganın ağa sızması ile tespit edilmesi arasında geçen süre (Dwell Time) endüstri ortalamasında 200 günün üzerindedir. Tespit kontrolleri olmayan kurumlarda bu süre yıllara varır ve veriler çoktan sızdırılmış olur.

İdeal mimaride önleyici kontrol ilk dalgayı süzer; tespit kontrolü ise kontrolü aşan veya zorlayan her anomalide alarm üreterek SOC ekibini tetikler.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir finans kurumu web uygulamasına yalnızca WAF kurmuş ancak API uç noktalarındaki istekleri SIEM'e aktarmamış ve log analizi yapmamıştır. Bir saldırgan WAF kuralını atlatacak özel bir SQL Injection payload'u geliştirmiş ve 3 ay boyunca her gece 1.000 müşterinin kimlik bilgilerini parça parça çekmiştir. Kurum veri sızıntısını ancak veriler karanlık ağda (Dark Web) satılığa çıktığında öğrenebilmiştir.

**Pratik Çözüm:**
1. **Tespit Edici Kontrol Entegrasyonu:** Web katmanına Zeek NIDS ve API günlük denetleyicisi konuşlandırılır.
2. **SIEM / UEBA Korelasyonu:** Gece saatlerinde olağandışı veritabanı sorgu hacmi üreten IP'ler için anında P1 (Kritik) alarm üretilir.
3. **Kör Nokta Doğrulaması:** `defense_in_depth_engine.py` içindeki `audit_architecture_resilience` fonksiyonu çalıştırılarak tespit kontrolü olmayan tüm katmanlar zorunlu olarak denetlenir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kapıya çelik kilit takıp güvenlik kamerasını sökmek akıl kârı değildir! Hırsız maymuncukla kilidi açarken kameran yoksa hırsızın içeri girdiğini ev boşaldığında anlarsın. Her önleyici bariyerin yanına bir çift göz, yani tespit edici bir kontrol koyacaksın. Kilit geciktirir, kamera yakalatır!"

---

## SORU 3: Savunma Derinliği Mimarilerinde 'Tek Hata Noktası' (Single Point of Failure - CWE-1008) Nasıl Analiz Edilir ve Çoklu Kontrol Çiftleri ile Nasıl Giderilir?

### 1. Soru Başlığı ve Tanımı
Bir siber saldırı kategorisine karşı sistemde yalnızca tek bir önleyici kontrolün bulunması neden CWE-1008 (Single Point of Failure) mimari kusurunu doğurur ve savunma derinliği yaklaşımıyla bu risk nasıl elimine edilir?

### 2. Derinlemesine Teknik Analiz
Tek Hata Noktası (SPoF), bir sistem bileşeninin devre dışı kalması veya atlatılması durumunda tüm sistemin savunmasız hale gelmesi durumudur.

Güvenlik mimarisinde SPoF şu şekilde ortaya çıkar:
1. **Tekillik Yanılgısı:** Örneğin "SQL Injection saldırılarına karşı WAF'ımız var, bu yeterli" denildiğinde; WAF tek hata noktası haline gelir. WAF yazılımındaki bir zero-day açığı veya yanlış bir kural konfigürasyonu (misconfiguration) anında tüm veritabanını korunmasız bırakır.
2. **Farklı Katmanlarda Çapraz Doğrulama Eksikliği:**
   Bir saldırı vektörünün engellenmesi için katmanlar arası görev paylaşımı yapılmalıdır:
   - *Katman 5 (Uygulama):* WAF ile ilk filtreleme + Kod seviyesinde ORM parametreli sorgular (Prepared Statements).
   - *Katman 6 (Veri):* Veritabanında durağan veri şifreleme (AES-256) ve veri maskeleme (Data Masking).
   - *Katman 7 (Kimlik):* Veritabanı kullanıcısına En Az Yetki İlkesi (Least Privilege - tablo bazlı kısıtlama).
3. **Mühendislik Kuralı:** Eğer bir saldırı kategorisi (örneğin Ransomware veya SQLi) için mimarideki aktif önleyici kontrol sayısı $N \le 1$ ise, motorumuz bunu doğrudan **CWE-1008 SPoF** olarak işaretler ve mimariyi güvenli kabul etmez.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir hastane bilgi sisteminde, veri tabanına erişim güvenliği sadece kurumsal VPN'e bağlanmış olmaya dayandırılmıştır (Perimeter tek hata noktası). Bir doktorun VPN kimlik bilgisi oltalama ile çalındığında, saldırgan iç ağa girmiş ve hiçbir ilave şifre veya yetki kontrolü olmadan tüm hasta geçmişini tek bir SQL sorgusuyla indirmiştir.

**Pratik Çözüm:**
1. **SPoF'un Ortadan Kaldırılması:**
   - VPN üzerine Donanım Tabanlı MFA eklenir (Kimlik Katmanı).
   - Veritabanı sorguları için API Gateway ve parametreli sorgu şartı getirilir (Uygulama Katmanı).
   - Veritabanındaki hasta kimlik bilgileri kolon bazlı şifrelenir (Veri Katmanı).
2. **Denetim Motoru ile Sağlama:** `defense_in_depth_engine.py` çalıştırılarak her bir saldırı tipi için en az 2 bağımsız önleyici kontrolün varlığı doğrulanır (`len(protecting_ctrls) >= 2`).

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, ip cambazları neden altlarına güvenlik ağı gerer bilir misin? İpe güvendikleri için değil; ip koptuğunda yere çakılmamak için! Mimarinde tek bir kontrole güveniyorsan, o kontrolün ipi koptuğunda şirketin yere çakılır. Her kritik tehdidin altına mutlaka ikinci ve üçüncü bir güvenlik ağı sereceksin. İşte gerçek mühendislik budur!"
