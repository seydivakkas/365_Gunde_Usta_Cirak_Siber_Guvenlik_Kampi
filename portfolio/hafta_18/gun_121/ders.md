# GÜN 121: Risk Skorlama, Kontrol Seçimi ve ROSI Analizi

## 1. Usta-Çırak Açılış Konuşması

**Usta:** Evlat, dünkü dersimizde bir sistemin tasarımındaki tehditleri STRIDE ile tek tek modelledik. Şimdi sana acı bir gerçeği söyleyeyim: Bir güvenlik uzmanının tespit ettiği her tehdidi kapatacak sınırsız bütçesi, zamanı veya insan kaynağı **asla yoktur!**

Güvenlik dünyasında başarı, "tüm açıkları kapatmak" değil; "en kritik riskleri en akılcı yatırımlarla yönetilebilir seviyeye indirmektir". İşte bugün siber güvenliğin en üst seviye yönetim disiplinine, yani **Risk Değerlendirme, Kontrol Seçimi ve ROSI (Return on Security Investment)** dünyasına adım atıyoruz.

**Çırak:** Hocam, riski nasıl sayısallaştırırız? Yönetim kuruluna gittiğimizde "Sistemimiz çok tehlikede" demek yerine onların anlayacağı dilde nasıl konuşabiliriz?

**Usta:** Aferin evlat! Yönetim kurulu "SQL Injection" veya "Buffer Overflow" kelimelerinden anlamaz; yönetim kurulu **Dolar, Euro ve TL**'den anlar! Finansal riskten anlar! Bir güvenlik lideri olarak iki ana yaklaşımı avucunun içi gibi bileceksin:
1. **Nitel Risk Analizi (Qualitative):** Risk = Olasılık (Likelihood: 1-5) $\times$ Etki (Impact: 1-5). Skoru 1 ile 25 arasında derecelendirir; Düşük, Orta, Yüksek ve Kritik olarak sınıflandırırsın.
2. **Nicel Finansal Risk Analizi (Quantitative):**
   - **Varlık Değeri (Asset Value - AV):** Korunan sistemin veya verinin maddi değeri.
   - **Maruz Kalma Faktörü (Exposure Factor - EF):** Bir olayda varlığın yüzde kaçının kaybedileceği (0.0 - 1.0).
   - **Tekil Kayıp Beklentisi (Single Loss Expectancy - SLE):** $SLE = AV \times EF$
   - **Yıllık Gerçekleşme Oranı (Annualized Rate of Occurrence - ARO):** Tehdidin bir yıl içinde gerçekleşme sıklığı.
   - **Yıllık Kayıp Beklentisi (Annualized Loss Expectancy - ALE):** $ALE = SLE \times ARO$

---

## 2. Risk Yanıt Stratejileri (Risk Treatment)

NIST SP 800-30 ve ISO 27005 standartları gereğince bir riski belirledikten sonra önünde 4 meşru strateji vardır:

| Strateji | Tanım | Örnek Uygulama | Güvenlik Kuralı |
|---|---|---|---|
| **1. Azaltma (Mitigate)** | Riski azaltacak güvenlik kontrolleri (WAF, MFA, EDR vb.) devreye alınır. | Müşteri veritabanına MFA ve PAM kontrolü atanması. | Kontrol atanmadan "Azaltıyorum" denilemez! |
| **2. Kaçınma (Avoid)** | Riski doğuran iş süreci, özellik veya sunucu tamamen kapatılır / kaldırılır. | Güvensiz eski bir FTP servisini kullanımdan kaldırmak. | Artık ALE ve risk skoru sıfırlanır. |
| **3. Devretme (Transfer)** | Risk üçüncü bir tarafa (Siber Risk Sigortası, bulut SLA) aktarılır. | DDoS saldırısı riskini Cloudflare ve sigorta poliçesine bağlamak. | Finansal kaybın büyük kısmı tazmin edilir. |
| **4. Kabul Etme (Accept)** | Riski mevcut haliyle üstlenmek (Hiçbir kontrol uygulamamak). | 2 ay sonra kapatılacak bir test sunucusundaki düşük riski kabullenmek. | **Risk İştahını aşıyorsa C-Level onaysız KABUL EDİLEMEZ (CWE-1025)!** |

---

## 3. Kontrol Tipleri ve Standart Eşleştirmesi

Kontroller sadece "yazılım kurmak" değildir. NIST SP 800-53 Rev 5 ve CIS Controls v8 kontrol tiplerini işlevine göre ayırır:
1. **Önleyici (Preventive):** Saldırının gerçekleşmesini baştan engeller (MFA, Güvenlik Duvarı, Yetkilendirme).
2. **Tespit Edici (Detective):** Saldırı başladığında veya gerçekleştiğinde alarm üretir (EDR, SIEM, IDS, Günlük Denetimi).
3. **Düzeltici (Corrective):** Zarar oluştuktan sonra sistemi normale döndürür (Yedekten dönme, İmaj yenileme).
4. **Telafi Edici (Compensating):** Asıl kontrolün teknik olarak uygulanamadığı yerde geçici bariyer sağlar (Eski sistemin önüne ters vekil koymak).

Birden fazla kontrol uygulandığında birleşik etkinlik formülü bağımsız olasılıklar kuralına dayanır:
$$\text{Toplam Etkinlik} = 1 - \prod_{i=1}^{n} (1 - e_i)$$

Örneğin, %85 etkili bir MFA ve %75 etkili bir WAF birlikte uygulandığında:
$$\text{Kalan Risk} = (1 - 0.85) \times (1 - 0.75) = 0.15 \times 0.25 = 0.0375 \implies \text{Etkinlik} = \%96.25$$

---

## 4. Güvenlik Yatırımı Getirisi (ROSI)

**Çırak:** Hocam, peki bir kontrolün parasal olarak mantıklı olup olmadığını nasıl hesaplarız?

**Usta:** İşte bu formül seni bir sistem yöneticisinden bir CISO (Chief Information Security Officer) yapar:

$$\text{ROSI} = \frac{(\text{Inherent ALE} - \text{Residual ALE}) - \text{Kontrol Yıllık Maliyeti}}{\text{Kontrol Yıllık Maliyeti}} \times 100$$

- Eğer kontrolün önlediği yıllık kayıp, kontrolün yıllık lisans ve işletme masrafından büyükse **ROSI pozitiftir** (Yatırım şirkete para kazandırır/tasarruf ettirir).
- Eğer $10,000\$'lık bir riski önlemek için yılda $50,000\$ harcıyorsan, ROSI negatif çıkar ve o kontrol finansal bir hezeyandır!

---

## 5. Kurumsal Yönetişim ve Risk İştahı (CWE-1025)

Bir kurumun yönetim kurulu bir **Risk İştahı (Risk Appetite)** belirler. Örneğin: "Kurumumuzda nitel skoru 10'un üzerinde hiçbir risk kabul edilemez, yıllık finansal kayıp beklentisi 50.000$'ı aşamaz."

Eğer bir mühendis:
- Kritik bir riski (Skor: 20-25) üst yönetimden resmi onay (Executive Sign-Off) almadan "Kabul Ediyorum" diye kayıtlara geçerse,
- Veya "Azaltıyorum" diyerek hiçbir kontrol atamazsa,

Bu durum **CWE-1025 (Comparison Using Wrong Factors)** güvenlik zaafiyetidir! Bugün yazdığımız `risk_control_engine.py`, işte bu yönetişim ihlallerini matematiksel olarak yakalayıp reddeden kurumsal bir motordur.
