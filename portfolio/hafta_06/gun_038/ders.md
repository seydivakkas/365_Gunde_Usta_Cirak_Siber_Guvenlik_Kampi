<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 038 — Zaman Senkronizasyonu ve NTP Mimarisi

**Usta-Çırak / Hoca Dersi**  
*Aşama 02: Sistem ve Ağ Temelleri — Hafta 06: İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi*

---

## 1. Usta Girişi: Siber Güvenliğin Görünmez Omurgası: Zaman
Evlat, siber güvenlik dünyasına yeni adım atanların en sık düştüğü yanılgı, zaman senkronizasyonunu "sistem saatini doğru göstermekten ibaret önemsiz bir ayar" zannetmeleridir. 

Gerçek ise şudur: **Zaman senkronizasyonu, siber güvenliğin ve dağıtık sistemlerin görünmez omurgasıdır.** Zamanın doğru olmadığı bir bilişim altyapısında:
1. **Kimlik Doğrulama Çöker:** Kerberos protokolü anında kilitlenir; şirket çalışanları bilgisayarlarında etki alanı oturumu açamaz.
2. **Kriptografi İflas Eder:** Geçerli bir SSL/TLS web sertifikası "tarihi geçmiş" veya "henüz başlamamış" sayılarak tüm güvenli bağlantılar reddedilir.
3. **Olay Müdahalesi (Incident Response) Körleşir:** Saldırganın adımlarını analiz eden SOC analisti; önce sunucudan veri çalındığını, 10 dakika sonra ise sunucuya giriş yapıldığını görür! Neden-sonuç ilişkisi (causality) tersine döner ve adli bilişim mahkemede delil vasfını kaybeder.
4. **Dağıtık Veritabanları Kilitlenir:** ACID veya Spanner tipi dağıtık sistemlerde işlem sıralaması (transaction ordering) bozulur; veritabanı kilitlenir veya veri kirlenir.

Bugün seninle Network Time Protocol (NTP), Stratum mimarisi, saat kaymasının (offset/skew) matematiksel arka planı ve zaman tabanlı siber saldırı vektörlerini masaya yatıracağız.

---

## 2. Zamanın Fiziksel ve Ağ Katmanı: Stratum Hiyerarşisi
Zaman ağ üzerinden rastgele bir kaynaktan çekilmez; **Stratum** adı verilen katı bir hiyerarşiyle yönetilir:

```text
[ Stratum 0 ]  Atomik Saatler (Cesium Fountain), GPS/Galileo Uyduları (Doğrudan Donanım)
      │
      ▼ (PPS / Pulse Per Second, Seri Sinyal)
[ Stratum 1 ]  Birincil Zaman Sunucuları (Doğrudan Stratum 0'a bağlı makineler: time.nist.gov)
      │
      ▼ (Ağ Üzerinden NTPv4 / UDP 123)
[ Stratum 2 ]  İkincil Zaman Sunucuları (Kurumsal Domain Controller / Core NTP Sunucuları)
      │
      ▼ (LAN İçi NTP / Dağıtım)
[ Stratum 3 ]  Uygulama Sunucuları, Veritabanları, İstemci İş İstasyonları
      │
      ▼ (Zincir Devam Edebilir, Maksimum Stratum 15)
[ Stratum 16 ] SENKRONİZASYONSUZ (Free Running Clock — Senkronizasyon Kaybı / Hata Durumu)
```

- **Stratum 0:** Ağa doğrudan bağlı olmayan fiziksel donanımlardır. Atomik saatler, GPS alıcıları veya radyo saatleridir.
- **Stratum 1:** Bu atomik cihazlara donanımsal düzeyde (örneğin mikrosaniye hassasiyetli PPS - Pulse Per Second sinyaliyle) bağlı olan sunuculardır.
- **Stratum 2:** Ağ üzerinden Stratum 1 sunucularıyla senkronize olan sunuculardır. Kurumsal ağlarda genellikle Active Directory PDC Emulator veya merkezi Linux `chrony` sunucuları Stratum 2 olarak yapılandırılır.
- **Stratum 16:** Bir sistemin hiçbir zaman kaynağına bağlı olmadığını, saatinin serbestçe sürüklendiğini (free-running drift) ifade eden kritik alarm seviyesidir.

---

## 3. NTP Matematiksel Modeli: Dört Zaman Damgası (T1, T2, T3, T4)
NTP protokolü (RFC 5905), ağ gecikmesini hesaba katarak istemci saati ile sunucu saati arasındaki farkı mikrosaniyelik hassasiyetle hesaplamak için dahiyane bir dört zaman damgası mekanizması kullanır:

1. **T1 (Originate Timestamp):** İstemci NTP istek paketini gönderdiği andaki istemci yerel zamanı.
2. **T2 (Receive Timestamp):** NTP sunucusu isteği aldığı andaki sunucu yerel zamanı.
3. **T3 (Transmit Timestamp):** NTP sunucusu yanıtı gönderdiği andaki sunucu yerel zamanı.
4. **T4 (Destination Timestamp):** İstemci yanıt paketini aldığı andaki istemci yerel zamanı.

Bu dört değer üzerinden iki temel metrik hesaplanır:

### A) Gidiş-Dönüş Ağ Gecikmesi (Round-Trip Delay - $\theta$):
$$\theta = (T_4 - T_1) - (T_3 - T_2)$$
Paketin ağda havada kaldığı toplam süredir; sunucunun paketi işlerken harcadığı süre ($T_3 - T_2$) bu gecikmeden çıkarılır.

### B) Saat Kayması / Sapması (Clock Offset - $\Delta$):
$$\Delta = \frac{(T_2 - T_1) + (T_3 - T_4)}{2}$$
İstemci saatinin sunucu saatine göre ne kadar ileri (+) veya geri (-) olduğunu gösteren net değerdir. İstemci bu değeri kullanarak saatini adım adım (slewing - kademeli hızlandırma/yavaşlatma) veya sıçramalı (stepping) olarak eşitler.

---

## 4. Kritik Güvenlik Mekanizmaları ve Saat Kayması Eşikleri

### 4.1. Kerberos Protokolü ve 5 Dakika (300 Saniye) Kuralı
Active Directory ve modern kimlik doğrulama mimarilerinin temeli Kerberos v5'tir.
- Bir kullanıcı oturum açtığında, istemci KDC'ye (Key Distribution Center) zaman damgalı bir istek (AS-REQ) gönderir.
- **Replay Attack Savunması:** KDC, istekteki zaman damgası ile kendi saati arasındaki farkı ölçer. Eğer fark **5 dakikadan (300 saniye)** fazlaysa isteği doğrudan reddeder:
  ```text
  KRB_AP_ERR_SKEW (Clock skew too great)
  ```
- Eğer saldırgan ağ üzerinden geçerli bir Kerberos biletini kaydetmiş olsa bile, 5 dakika sonra bu bileti yeniden sunamaz.
- **Güvenlik Çöküşü:** Sunucunun veya istemcinin NTP servisi çöker ve saat 5 dakikadan fazla kayarsa, yasal kullanıcılar dahi oturum açamaz ve tüm etki alanı işlevsiz kalır.

### 4.2. TLS/X.509 Sertifika Doğrulaması
Her SSL/TLS sertifikasının iki katı tarihi vardır:
- `NotBefore` (Geçerlilik Başlangıcı)
- `NotAfter` (Son Geçerlilik Tarihi)

Eğer bir uç noktanın veya web sunucusunun saati geleceğe kaymışsa geçerli sertifikalar "süresi dolmuş" (Expired Certificate), geçmişe kaymışsa "henüz geçerli değil" (Certificate Not Yet Valid) hatası üretir. Güvenli API entegrasyonları, ödeme ağ geçitleri ve web trafiği anında kesilir.

### 4.3. SIEM Olay Zaman Çizelgesi ve Adli Bilişim (Forensics Timeline)
SOC operasyonlarında bir güvenlik olayını aydınlatırken farklı sistemlerden gelen loglar (Firewall, EDR, Web Sunucu, Veritabanı) tek bir zaman çizelgesinde birleştirilir.
- Eğer Web Sunucusunun saati Firewall'a göre 15 saniye ilerideyse; loglarda saldırganın veriyi çaldığı an, Firewall'dan geçiş anından önce görünür.
- Adli bilişimde zaman damgası tutarsızlığı (lack of temporal integrity), toplanan delillerin mahkemede geçerliliğini yitirmesine (chain of custody failure) neden olur.

---

## 5. Zaman Senkronizasyonu Saldırı Vektörleri ve Savunma

### 5.1. NTP Amplification (Yükseltme) DDoS Saldırısı (monlist Açığı)
NTPv3 ve eski NTPv4 sunucularında bulunan `monlist` (Mode 6) yönetim komutu:
- Saldırgan, kaynak IP adresini kurbanın IP'si olarak taklit eder (IP Spoofing).
- NTP sunucusuna küçük bir UDP paketi gönderir (~200 bayt).
- NTP sunucusu, son iletişim kurduğu 600 istemcinin listesini içeren devasa yanıt paketleri döner (~48.000 bayt).
- **Yükseltme Faktörü:** Saldırganın trafiği 200 kattan fazla büyür ve kurban sunucunun bant genişliği tamamen kilitlenir.
- **Savunma:** NTP yapılandırmasında `disable monitor` ve `noquery` kuralı uygulanmalıdır (`ntp.conf` veya `chrony.conf`).

### 5.2. Ortadaki Adam (MitM) ile Saat Saptırma ve NTS Çözümü
Geleneksel NTP (UDP 123) düz metindir (unencrypted). Yerel ağdaki bir saldırgan ARP Spoofing ile NTP paketlerini yakalayıp saati 1 yıl geriye alabilir (böylece süresi dolmuş zafiyetli TLS sertifikalarını geçerli kıldırabilir).
- **Savunma:** Modern **NTS (Network Time Security - RFC 8915)** mimarisiyle NTP paketleri TLS üzerinden kriptografik olarak imzalanmalı veya en azından simetrik anahtar (symmetric key authentication) kullanılmalıdır.

### 5.3. Bizans Hata Toleransı (Byzantine Fault Tolerance / Marzullo Algoritması)
Bir sistem tek bir NTP sunucusuna (`pool.ntp.org`) güveniyorsa o sunucu manipüle edildiğinde sistem de kandırılır.
- Marzullo algoritmasının hatalı veya yalancı bir zaman sunucusunu (false-ticker) tespit edebilmesi için en az **3, tercihen 4 bağımsız zaman kaynağı** tanımlanmalıdır.

---

## 6. Usta-Çırak Özeti
Çırak! Bir sunucuya adım attığında hemen şu kontrolleri yapacaksın:
1. `chronyc tracking` veya `w32tm /query /status` çalıştır; saat kaymasını (offset/skew) gör.
2. Stratum değerine bak; 16 görüyorsan saat serbest dönüyor, senkronizasyon ölmüş demektir!
3. Üst sunucu sayısını say; 1 taneyse "Tek hata noktası var, Marzullo algoritması çalışamaz!" de.
4. `monlist` açık mı kontrol et; açıksa sistemi bir DDoS silahı olmaktan kurtar!

Şimdi soru-cevap ve raporlama aşamasına geçip bu mimariyi kayda geçirelim.
