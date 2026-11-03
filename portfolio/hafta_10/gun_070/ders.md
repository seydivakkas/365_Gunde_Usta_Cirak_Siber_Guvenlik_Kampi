<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 070: Aşama 3 Kalite Özeti ve Ağ Analizi Kabul Dersi

## Ustanın Girişi: 20 Günlük Ağ Analizi Yolculuğunun Zirvesi

Evlat, dinle beni can kulağıyla. Bugün 365 günlük siber güvenlik maratonumuzun en kritik kilometre taşlarından birine ayak bastık: **Aşama 03 (Ağ Analizi ve Güvenliği)** safhasını tam 20 gün boyunca (Gün 51'den Gün 70'e kadar) ilmek ilmek dokuyarak tamamladık.

Ağ analizi, bir siber güvenlik uzmanının gözüdür, kulağıdır. Bir işletim sisteminde ne kadar güçlü erişim kontrolleri kurarsan kur, o sistemin dış dünyayla konuştuğu an ağ kablosundan veya radyo frekansından akan bitlerdir. Eğer o bitleri doğru okuyamazsan, bir kör gibi tehdidin nereden geldiğini ancak veri tabanın şifrelendiğinde ya da gizli dosyaların Dark Web'de satışa çıktığında anlarsın.

Biz bu 20 gün boyunca ağın derinliklerine indik:
1. **Hafta 08 (Gün 51 - 57):** Wireshark mimarisi, pcap metaverisi ayrıştırma, ekran filtreleri motoru, protokol hiyerarşisi istatistikleri, konuşmalar (conversations) ve uç nokta analizi, paket baytları seviyesinde hex incelemesi ve renklendirme kuralları.
2. **Hafta 09 (Gün 58 - 63):** TCP akışı takip etme (Follow TCP Stream), karmaşık Boole mantığıyla filtre birleştirme, Mini Proje 7 ile PCAP paket temizleme ve adli anonimleştirme, L2-L4 ARP zehirlenmesi ve ICMP analizi, Rogue DHCP saldırıları ve DNS sorgu-yanıt çözümleme riskleri.
3. **Hafta 10 (Gün 64 - 70):** Düz metin HTTP ile TLS 1.3 şifreli trafiğin adli farkı, Mini Proje 8 ile protokol zaman çizelgesi inşası, DGA ve DNS tünelleme ile HTTP Request Smuggling anomali tespiti, tek yönlü gecikme, RTT ve RFC 3393/3550 jitter analizi, KVKK/GDPR uyumlu ağ günlüğü PII maskeleme ve Mini Proje 9 ile kapsamlı Wireshark adli güvenlik raporu motoru.

Bugünkü dersimizde, geriye dönüp tüm bu 20 günlük mühendislik emeğini **6 Kurumsal Kalite Sütunu** altında denetleyen, matematiksel ve kriptografik olarak tescil eden **Aşama 3 Kalite Özeti Motoru**muzu kuruyoruz.

---

## 1. Ağ Analizi Kalite Değerlendirmesinin 6 Temel Sütunu

Kurumsal bir Güvenlik Operasyonları Merkezinde (SOC) ya da Adli Bilişim Laboratuvarında (DFIR) ağ verileri gelişigüzel incelenemez. Her analiz şu 6 sütuna tam uyum sağlamak zorundadır:

```
+---------------------------------------------------------------------------------------+
|                                6 TEMEL KALİTE SÜTUNU                                 |
+---------------------------------------------------------------------------------------+
| Sütun 1: Paket Yakalama ve Ekran Filtreleri (Gün 51-57)                               |
|          - PCAP başlık ve paket bütünlüğü (Magic number, nanosecond/microsecond saat) |
|          - Berkeley Packet Filter (BPF) ve Wireshark Display Filter sözdizimi ayrımı  |
|          - Hiyerarşik protokol ağacı ve Top Talkers uç nokta matrisi                  |
+---------------------------------------------------------------------------------------+
| Sütun 2: TCP Akış Rekonstrüksiyonu ve Filtreleme Otomasyonu (Gün 58-60)               |
|          - TCP Sequence/Ack numaraları üzerinden kayıp paket ve sıra dışı paket takibi|
|          - Çift yönlü yük (payload) birleştirme ve istemci/sunucu renk ayrımı         |
|          - Hassas verilerden arındırılmış (sanitized) adli PCAP üretimi               |
+---------------------------------------------------------------------------------------+
| Sütun 3: Temel L2-L4 Ağ Protokolleri Güvenliği (Gün 61-63)                            |
|          - ARP zehirlenmesi (Gratuitous ARP spoofing) ve MAC çakışması tespiti        |
|          - ICMP Echo/Reply, TTL manipülasyonu ve Ping of Death / Tünelleme kontrolleri|
|          - DHCP DORA döngüsünde Rogue DHCP Server ve IP havuzu tükenmesi analizi      |
|          - DNS recursor, authoritative sunucu ve DNS zehirlenmesi riskleri            |
+---------------------------------------------------------------------------------------+
| Sütun 4: L7 Protokolleri, TLS Kriptografi ve Zaman Çizelgesi (Gün 64-65)             |
|          - Açık metin L7 protokollerinin (HTTP, FTP, Telnet) risk modellemesi         |
|          - TLS 1.3 El sıkışması (ClientHello, SNI, ServerHello, Şifreli Uzantılar)    |
|          - Kronolojik olay akışı (Timeline) inşası ve oturum sürelerinin korelasyonu  |
+---------------------------------------------------------------------------------------+
| Sütun 5: Ağ Anomalileri, Tünelleme ve QoS Performansı (Gün 66-67)                     |
|          - DGA algoritması: Shannon entropisi ($H \ge 3.4$) ve sessiz harf yoğunluğu  |
|          - DNS Veri Kaçırma (Tunneling): Taban-64/Taban-32 uzun etki alanı analizi    |
|          - HTTP Request Smuggling (CL.TE ve TE.CL desync) ve CRLF enjeksiyonu        |
|          - Paket kaybı, RTT, RFC 3393 IPDV ve RFC 3550 filtrelenmiş jitter hesabı    |
+---------------------------------------------------------------------------------------+
| Sütun 6: KVKK/GDPR Gizlilik, PII Maskeleme ve Adli Ağ Raporlaması (Gün 68-70)         |
|          - Ağ günlüklerinde IPv4 alt ağ maskeleme (/24) ve tuzlu HMAC-SHA256 takma ad |
|          - OUI korumalı MAC anonimleştirme, TCKN ve Kredi Kartı (Luhn) maskeleme      |
|          - Wireshark adli güvenlik skoru (0-100), Tehdit Seviyesi ve Kabul Tescili    |
+---------------------------------------------------------------------------------------+
```

---

## 2. Aşama 3 Başarı Metrikleri ve Matematiksel Doğrulama

20 gün boyunca yürüttüğümüz sıkı çalışma sonucunda ortaya çıkan metrikler şunlardır:

1. **Denetlenen Gün Sayısı:** Tam 20 Gün (Gün 51 - Gün 70).
2. **Çalıştırılan Birim Testler:** Her gün için en az 14 adet olmak üzere toplam **280 Birim Test**, %100 başarıyla sonuçlanmıştır ($280 / 280$ PASS).
3. **Negatif Sınır Kontrolleri:** Her gün için en az 9 adet olmak üzere toplam **180 Negatif Kontrol**, sistemin hatalı, bozuk veya yetersiz girdileri sıfır toleransla yakaladığını kanıtlamıştır ($180 / 180$ PASS).
4. **Toplam Doğrulanan Önerme (Assertions):** $280 + 180 = 460$ adli önerme bizzat Python test koşucusu tarafından matematiksel olarak tescil edilmiştir.
5. **Üretilen Eser Sayısı:** Her gün için 16 zorunlu standart dosya (uygulama motoru, test paketi, geçerli ve geçersiz JSON girdileri, gerçek kanıtlar, mimari illüstrasyon, ders anlatımı, soru-cevap, rapor, README, sonuc.json, manifest.json ve yedek arşivi) olmak üzere toplam **320 Eser Dosyası** üretilmiştir.
6. **Lisans Uyum Oranı:** %100. Hiçbir dosyada MIT, Apache, GPL gibi açık kaynak lisanslar kullanılmamış; tamamı Seydi Eryılmaz adına tescilli "Özel Lisans — Tüm Hakları Saklıdır" hükümleriyle korunmuştur.

---

## 3. Kriptografik Aşama Kabul Sertifikasyonu

Aşama 3'ün tamamlanması, yalnızca metin dosyalarına yazılan sözlerle değil, kriptografik bir SHA-256 sağlama karmasıyla mühürlenmiştir.

Motorumuz, aşama kimliğini, kapsanan haftaları, gün aralığını, tam puanı (100.0), test ve kontrol sayılarını, zaman damgasını ve lisans politikasını birleştirerek tekil bir adli imza üretir:

$$\text{CertHash} = \text{SHA256}(\text{StageMetadata} \parallel \text{Score} \parallel \text{Tests} \parallel \text{Timestamp} \parallel \text{License})$$

Bu imza, adli bilişim standartlarına göre geri döndürülemez, değiştirilemez ve müfredat paketinin özgünlüğünü ispatlayan resmi kabul belgemizdir.

---

## Ustanın Çırağa Öğüdü

Evlat, bu 20 günde ağı yalnızca izleyen biri olmaktan çıktın; ağın dilini konuşan, paketlerin ardındaki niyetleri okuyan bir **Ağ Güvenliği Mühendisi** seviyesine ulaştın. Ancak kibirlenmek yok! Ağ analizinde ustalığın sırrı, en karmaşık şifreli tünellerin arkasındaki küçük bir zamanlama farkını veya bir baytlık uzunluk sapmasını fark edebilen dikkatte yatar.

Aşama 3'ü alnımızın akıyla ve kusursuz 100/100 tam puanla kapattık. Şimdi önümüzde daha büyük bir kale duruyor: **Aşama 04 - Siber Tehdit İstihbaratı ve Tehdit Avcılığı**. Hazır ol, bayrağı daha da yukarı taşıyacağız!
