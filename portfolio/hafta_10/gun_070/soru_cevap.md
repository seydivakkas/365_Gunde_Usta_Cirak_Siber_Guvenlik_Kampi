<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 070: Soru ve Cevaplar (Aşama 3 Kalite Özeti ve Ağ Analizi Kabulü)

---

## G070-SC1: Aşama 3 Kalite Değerlendirmesinde 6 Temel Ağ Analizi Sütununun Rolü ve Kapsam Bütünlüğü

### Soru Başlığı ve Tanımı
Aşama 03 (Gün 51 - Gün 70) boyunca icra edilen ağ analizi ve paket inceleme yetenekleri hangi 6 kurumsal kalite sütununa ayrılmıştır ve bu sütunların eksiksizliği bir kurumsal SOC/DFIR altyapısında neden zorunlu kabul kriteridir?

### Derinlemesine Teknik Analiz
Ağ trafiği analizi tek bir araç veya tek bir katmandan ibaret değildir; ISO/OSI modelinin 2. katmanından (Veri Bağı) 7. katmanına (Uygulama) kadar tüm iletişim dinamiklerini kapsar. Aşama 3 motorumuz şu 6 kalite sütununu denetler:
1. **Paket Yakalama ve Ekran Filtreleri (Gün 51-57):** PCAP dosyalarının libpcap standartlarına uygun ayrıştırılması, paket başlıklarının (magic bytes, link-layer header type) teyidi, Berkeley Packet Filter (BPF) ile Wireshark Display Filter ayrımı ve hiyerarşik uç nokta konuşma matrislerinin oluşturulması.
2. **TCP Akış Rekonstrüksiyonu ve Filtreleme Otomasyonu (Gün 58-60):** Dağınık, kayıp veya sıra dışı TCP segmentlerinin sequence ve ACK numaraları üzerinden sıralanıp çift yönlü oturum yükünün yeniden inşa edilmesi, Boole mantığıyla adli filtreleme ve hassas verilerden arındırılmış temiz PCAP üretimi.
3. **Temel L2-L4 Ağ Protokolleri Güvenliği (Gün 61-63):** Ağın omurgasını oluşturan ARP (Gratuitous ARP spoofing/zehirleme), ICMP (Echo, TTL manipülasyonu, Ping of Death), DHCP (Rogue DHCP Server tespiti, IP starvation) ve DNS çözümleme mekanizmalarının güvenlik zaafiyetlerinin adli tespiti.
4. **L7 Protokolleri, TLS Kriptografi ve Zaman Çizelgesi (Gün 64-65):** Açık metin L7 protokolleri (HTTP) ile modern şifreli trafiğin (TLS 1.3 ClientHello, SNI, Cipher Suites) adli izlerinin ayrıştırılması ve mikrosaniye hassasiyetli adli protokol zaman çizelgelerinin kurulması.
5. **Ağ Anomalileri, Tünelleme ve QoS Performansı (Gün 66-67):** Gelişmiş tehdit avcılığı modelleri; DGA algoritmalarının Shannon entropisi ($H \ge 3.4$) ve sessiz harf yoğunluğuyla tespiti, DNS tünelleme üzerinden veri sızdırma, HTTP Request Smuggling (CL.TE / TE.CL desync) ve RFC 3393/3550 tabanlı paket kaybı, gecikme ve jitter hesaplamaları.
6. **KVKK/GDPR Gizlilik, PII Maskeleme ve Adli Ağ Raporlaması (Gün 68-70):** Adli inceleme sırasında kişisel verilerin (IPv4 subnet, MAC, e-posta, TCKN, kredi kartı) tuzlu HMAC-SHA256 ve maskeleme yöntemleriyle arındırılması, Wireshark adli güvenlik skoru (0-100) ve kurumsal kabul kararının üretilmesi.

Bu sütunlardan tek bir tanesinin eksik veya hatalı olması, adli bilişim zincirinde delil bütünlüğünü sakatlar ve sistemin kör noktalara sahip olmasına yol açar.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Büyük ölçekli bir bankacılık ağında gerçekleşen bir veri ihlali soruşturmasında, adli ekipler saldırganın C2 (Komuta Kontrol) sunucusuyla DNS tünelleme üzerinden haberleştiğini ancak tünelin içerisine gömülen verilerin base64 ile şifrelendiğini fark eder. Eğer analiz ekibi yalnızca temel L2-L4 filtrelerine (Sütun 1 ve Sütun 3) odaklanıp Sütun 5'teki DGA/Tünelleme entropi analizörünü ve Sütun 2'deki akış birleştirme motorunu devreye sokmasaydı, giden DNS paketleri normal alan adı çözümlemesi sanılıp vaka gözden kaçırılacaktı.
**Pratik Çözüm:** `Asama3KaliteOzetiAnalizor` motorumuz tüm bu sütunları tek bir JSON denetiminde birleştirerek, 20 günün her birinde gerekli motorların ve testlerin eksiksiz bulunduğunu doğrular. Herhangi bir sütun eksik olduğunda `Asama3KaliteAuditError` fırlatarak aşama kabulünü derhal durdurur.

### Ustanın Çırağa Tavsiyesi
Çırak, tek bir protokolü iyi bilmek seni ağ uzmanı yapmaz. Bir saldırgan L2'de ARP ile araya girer, L4'te TCP penceresini küçülterek servisi tıkar, L7'de ise HTTP Smuggling ile arka uç sunucuya sızar. Güvenlik, zincirin en zayıf halkası kadar güçlüdür. 6 sütunun her birine eşit derecede titizlikle yaklaşmalısın.

---

## G070-SC2: Adli Ağ Kabul Süreçlerinde Pozitif Testler ve Negatif Sınır Kontrollerinin Matematiksel Güvencesi

### Soru Başlığı ve Tanımı
Aşama 3 kalite kabul motorunda 280 pozitif birim testin yanında 180 negatif sınır kontrolünün (Negative Boundary Controls) icra edilmesi neden zorunludur ve bu testlerin hata yakalama mimarisi sisteme nasıl bir matematiksel güvence sağlar?

### Derinlemesine Teknik Analiz
Yazılım ve adli analiz sistemlerinde "Happy Path" (başarılı senaryolar) denetimin yalnızca yarısını oluşturur. Bir motorun geçerli pcap veya metrik dosyasını hatasız işlemesi, onun güvenilir olduğunu ispatlamaz; asıl güvenilirlik, bozuk, eksik, manipüle edilmiş veya yetkisiz girdiler karşısında sistemin nasıl tepki verdiğidir:
1. **Sıfır Tolerans İlkesi:** Aşama 3 denetim motorumuzda hiçbir gevşek doğrulamaya izin verilmez. Skorun 99 olması, test sayısının 13'te kalması veya tek bir günün yedeğinin teyit edilmemiş olması durumunda sistem koşulsuz olarak reddedilir (`PASS` kararı verilmez).
2. **Negatif Kontrol Kapsamı:** Aşama 3 boyunca icra edilen 180 negatif sınır kontrolü; tip uyuşmazlıkları (JSON array vs dict), aşama kimliği sapmaları, eksik gün sayıları, yetersiz test hacmi, doğrulanmamış yedekler ve özellikle açık kaynak lisans sızıntılarını (MIT, Apache, GPL vb.) sınar.
3. **Matematiksel Güvence:** Sistemde $N=20$ gün, her gün için $T_p \ge 14$ pozitif test ve $T_n \ge 9$ negatif kontrol olmak üzere:
   $$\text{Toplam Adli Önerme} = \sum_{i=51}^{70} (T_{p,i} + T_{n,i}) = 20 \times 14 + 20 \times 9 = 280 + 180 = 460$$
   Bu 460 önermenin her biri Python `unittest` koşucusu altında bağımsız olarak doğrulanır ve %100 doğrulama oranı elde edilir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir siber denetçi kuruma gelip "Ağ izleme yazılımınız tüm ihlalleri yakalıyor mu?" diye sorduğunda, sadece çalışan sistemleri göstermek yetersizdir. Denetçi, sisteme hatalı RFC paketleri, eksik TCP bayrakları veya manipüle edilmiş günlükler enjekte ettiğinde sistemin sessizce çökmesi ya da yanlışlıkla "Her şey yolunda" raporu üretmesi felakettir.
**Pratik Çözüm:** `invalid_asama_3_inputs.json` dosyasında tanımladığımız 9 negatif vaka (NEG_01'den NEG_09'a kadar), motorun her türlü sapmada doğru hata sınıfını (`Asama3KaliteAuditError`) fırlattığını ve güvenli başarısızlık (fail-safe) ilkesini koruduğunu kanıtlar.

### Ustanın Çırağa Tavsiyesi
Evlat, bir kodu sadece doğru çalıştığı için övme. Asıl ustalık, o kodun yanlış girdiyi gördüğü an hiç tereddüt etmeden kapıyı kilitlemesi ve alarm çalmasıdır. Negatif testler, savunma hattının çelik zırhıdır.

---

## G070-SC3: Kriptografik Kabul Sertifikasyonu ve Zero-Day Tehditlerine Karşı Aşama Değerlendirmesi

### Soru Başlığı ve Tanımı
Aşama 3 kabul sürecinde üretilen SHA-256 imzalı kriptografik kabul sertifikasının adli delil zincirindeki (Chain of Custody) önemi nedir ve bu altyapı bilinmeyen (Zero-Day) ağ tehditlerine karşı nasıl bir zemin hazırlar?

### Derinlemesine Teknik Analiz
Adli bilişimde (Digital Forensics) ve kurumsal siber denetimlerde bir raporun veya analiz sonucunun geçerli sayılabilmesi için "Zaman Damgası" (RFC 3161) ve "Kriptografik Bütünlük Karması" (Cryptographic Hash) zorunludur:
1. **Sertifika Üretim Mekanizması:** `Asama3KaliteOzetiAnalizor.generate_acceptance_certificate()` fonksiyonu; aşama ID'sini, gün aralığını, tam puanı (100.0), pozitif/negatif test sayılarını, üretilen eser hacmini, UTC tanzim zamanını ve özel lisans politikasını birleştirerek bir kanıt dizesi (payload) oluşturur.
2. **SHA-256 Adli Mühür:** Bu dize üzerinden tekil bir 64 karakterli onaltılık (hex) özet üretilir. Bu özet sayesinde, geriye dönük olarak 20 günden herhangi birinin bir tek biti bile değiştirilirse veya silinirse sertifika geçersiz hale gelir.
3. **Zero-Day Zemin Hazırlığı:** Ağ analizi aşamasında kurulan derin paket inceleme (DPI), protokol ayrıştırma, entropi hesaplama ve anomali filtreleme yetenekleri; imza tabanlı (Snort/Suricata) tespitlerin çaresiz kaldığı bilinmeyen Zero-Day saldırılarında (örneğin henüz CVE'si yayınlanmamış yeni bir HTTP smuggling tekniği veya şifreli tünel varyantı) ağ mühendisine anomalileri yakalama ve adli kanıt üretme imkanı tanır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumda meydana gelen siber casusluk vakasında, mahkemeye sunulan ağ günlüklerinin ve analiz raporlarının savunma avukatları tarafından "Bu raporlar sonradan değiştirilmiş olabilir" iddiasıyla çürütülmeye çalışıldığı görülür.
**Pratik Çözüm:** Aşama 3 kabul motorumuzun ürettiği `CERT-STAGE03-2026-71755BCF938A` seri numaralı kriptografik sertifika ve SHA-256 adli imza, tanzim anındaki tüm metrikleri dondurur. Bu sayede delil zincirinin bozulmadığı matematiksel kesinlikle ispatlanır.

### Ustanın Çırağa Tavsiyesi
Çırak, dijital dünyada söz uçar, karma (hash) kalır! Bir işi bitirdiğinde arkanda kriptografik olarak mühürlenmiş adli bir imza bırakmıyorsan, o iş yarın bir gün tartışmaya açık hale gelir. İmzayı sağlam at ki, arkana baktığında şüpheye yer kalmasın.
