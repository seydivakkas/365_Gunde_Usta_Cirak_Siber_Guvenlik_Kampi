# GÜN 122: Savunma Derinliği (Defense-in-Depth) ve Güvenlik Kontrol Tipleri

## 1. Usta-Çırak Açılış Konuşması

**Usta:** Evlat, tarihin en büyük kalelerini düşün. Truva, Konstantinopolis, Elhamra... Hiçbir usta mimar kalesini tek bir yüksek surla korumadı. Önce hendek kazar, içine su doldururlar. Hendeği geçen ordu dış surlarla karşılaşır. Dış suru aşarlarsa iç surlar, demir kapılar, kuleler ve en son sığınak olan iç kale (citadel) vardır. Neden? Çünkü tek bir duvar ne kadar yüksek ve kalın olursa olsun, düşman o duvarda bir delik açtığı anda tüm şehir düşer!

İşte siber güvenlikteki en kadim kural budur: **Savunma Derinliği (Defense-in-Depth - DiD)**. Tek bir güvenlik teknolojisine —ister dünyanın en pahalı yeni nesil güvenlik duvarı (NGFW), ister en gelişmiş yapay zekalı EDR'ı olsun— bel bağlayan bir şirket, tek bir surun arkasında uyuyan ahmak bir krallığa benzer!

**Çırak:** Hocam, peki modern bir bilişim altyapısında bu surlar nelerdir? Kaç katmandan oluşur ve hangi kontrolleri nereye koymalıyız?

**Usta:** Dinle evlat, NSA ve NIST SP 800-53 standartları bize savunmanın **7 Temel Katmanını (7 Layers of Defense)** öğretir:
1. **Fiziksel Katman (Physical):** Veri merkezi kilitleri, biyometrik turnikeler, güvenlik kameraları, mantrap kapılar.
2. **Çevre ve Dış Ağ (Perimeter):** Dış güvenlik duvarları (Firewall), DDoS engelleme, VPN ağ geçitleri.
3. **İç Ağ ve Segmentasyon (Internal Network):** VLAN'lar, ZTNA (Zero Trust Network Access), mikro-segmentasyon, Doğu-Batı trafik izleyicileri.
4. **Uç Nokta ve Sunucu (Host / Endpoint):** EDR/XDR ajanları, antivirüs, FIM (Dosya Bütünlüğü İzleme), işletim sistemi sıkılaştırması.
5. **Uygulama ve API (Application):** WAF, API Gateway, girdi doğrulama, parametreli SQL sorguları.
6. **Veri ve Depolama (Data):** AES-256 durağan veri şifrelemesi (encryption-at-rest), TLS 1.3 iletim şifrelemesi, DLP ajanları, değiştirilemez yedekler.
7. **Kimlik ve İnsan (Identity & Governance):** Donanım tabanlı MFA, Least Privilege yetkilendirme, kullanıcı davranış analitiği (UEBA), farkındalık eğitimleri.

---

## 2. Güvenlik Kontrol Tipleri ve Fonksiyonel Ayrımı

Bir kontrolü mimariye yerleştirirken sadece "güvenlik aracı" demek yetmez. Her kontrolün icra ettiği bir fonksiyon vardır:

| Kontrol Tipi | Tanım ve Rolü | Örnek Güvenlik Mekanizması | Mimarideki Yeri |
|---|---|---|---|
| **Önleyici (Preventive)** | Tehdidin sisteme girmesini veya yetkisiz eylemi baştan bloke eder. | Donanım MFA, WAF kuralları, Firewall port kısıtı, Disk şifrelemesi. | Birinci savunma hattı; saldırıyı anında keser. |
| **Tespit Edici (Detective)** | Saldırı girişimini, ihlali veya anomalileri gerçek zamanlı yakalayıp alarm üretir. | SIEM log analizi, Zeek NIDS, Osquery/FIM dosya bütünlüğü, UEBA. | Önleyici kontrol aşıldığında alarm verir (Kör noktayı yok eder). |
| **Düzeltici (Corrective)** | Hasar oluştuktan sonra sistemi temizleyen, geri yükleyen ve normale döndüren adımlardır. | Değiştirilemez yedekten dönme (Immutable Backup), EDR otomatik karantina playbook'u. | Felaket anında iş sürekliliğini sağlar. |
| **Telafi Edici (Compensating)** | Asıl kontrolün teknik veya maliyet nedeniyle konulamadığı yerde riski hafifleten alternatif bariyerdir. | Eski sisteme yama atılamıyorsa önüne ters vekil (reverse proxy) veya sanal yama (virtual patch) koymak. | Geçici koruma sağlar. |
| **Caydırıcı (Deterrent)** | Saldırganı psikolojik veya hukuki olarak caydırmayı hedefler. | Oturum açma yasal uyarı banner'ları, izleme uyarı levhaları. | İhlal niyetini kırmaya yöneliktir. |

---

## 3. Katman Boşluğu (Defense Gap - CWE-653) ve Tek Hata Noktası (SPoF - CWE-1008)

Bir mimaride en sık rastlanan iki ölümcül hata şunlardır:

1. **Katman Boşluğu (CWE-653: Improper Compartmentalization):**
   Bir mimaride 7 katmandan biri bile tamamen korumasız bırakılırsa, saldırgan orayı bir "otoban" gibi kullanır. Örneğin çevre duvarını aşıp iç ağa giren bir fidye yazılımı (Ransomware), iç ağda hiçbir mikro-segmentasyon (VLAN/ZTNA) yoksa saniyeler içinde tüm sunucuları şifreler!
2. **Tek Hata Noktası (Single Point of Failure - CWE-1008):**
   Eğer SQL Injection saldırısına karşı mimarinizde sadece WAF varsa, WAF atlatıldığı (bypass) anda saldırgan doğrudan veritabanına ulaşır! Gerçek savunma derinliği; hem WAF (Uygulama Katmanı), hem parametreli sorgu (Uygulama Katmanı), hem veritabanı kullanıcı kısıtı (Kimlik Katmanı), hem de veritabanı disk şifrelemesi (Veri Katmanı) olmasını gerektirir. Biri aşılsa bile diğeri saldırganı durdurur!

---

## 4. Gözetimsiz Katman (Blind Spot) Tehlikesi

**Çırak:** Hocam, bir katmana sadece önleyici kontrol koysak yetmez mi? Zaten saldırıyı engelliyor!

**Usta:** Asla yetmez evlat! Eğer bir katmanda önleyici kontrol var ama tespit edici (Detective) kontrol yoksa, saldırgan o kontrolü atlatmak için yüzlerce deneme yapar ve senin ruhun bile duymaz! Bir gün kontrolü aştığında ise içeride cirit atar.
Her katmanda **en az bir Önleyici ve en az bir Tespit Edici kontrol çifti** bulunmak zorundadır:
- Önleyici kontrol kapıyı kilitler;
- Tespit edici kontrol ise kapının kilidini kurcalayan biri olduğunda alarm çalar!

---

## 5. Uygulama Mimarisi

Bugün geliştirdiğimiz `defense_in_depth_engine.py` modülü:
1. 7 savunma katmanını (`DefenseLayer`) eksiksiz modeller.
2. Kontrolleri 5 tipe (`ControlType`) göre sınıflandırır ve etkinlik oranlarını yönetir.
3. Mimariyi otomatik denetleyerek katman boşluklarını (CWE-653), gözetimsiz katmanları (Blind Spot) ve tek hata noktalarını (CWE-1008) tespit eder.
4. Kill Chain saldırı senaryolarını katman katman simüle eder; saldırının hangi katmanda önlendiğini, tespit edildiğini veya delindiğini raporlar.

Evlat, bu felsefeyi zihnine kazı: Hiçbir teknolojiye körü körüne güvenme; güvenliği katmanlara yay ve her katmanı gözün gibi izle!
