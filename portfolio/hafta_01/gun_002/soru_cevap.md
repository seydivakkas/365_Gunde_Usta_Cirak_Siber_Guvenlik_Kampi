<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 002: Soru ve Cevap Odası
## Tehdit, Zafiyet, Olay ve Risk — Matematiksel Analiz ve Mühendislik İlkeleri

---

### Soru 1 (G002-SC1): Tehdit, zafiyet, olay ve risk: Temel mekanizmayı ve güvenlik önemini açıkla.

- **1. Yanıt:** Tehdit potansiyel tehlike unsurudur, zafiyet bu tehlikenin istismar edebileceği eksikliktir, güvenlik olayı zafiyetin tetiklenmesidir, risk ise bu olayın meydana gelme olasılığı ile yaratacağı etkinin bileşimidir ($\text{Risk} = \text{Olasılık} \times \text{Etki}$).
- **2. Teknik Gerekçe:** Tehdit aktörünün motivasyonu, yeteneği ve fırsatı zafiyetle (örn. yamasız yazılım, zayıf parola) buluştuğunda güvenlik olayı (incident) tetiklenir. Kurumlar bütçe ve savunma kalkanlarını rastgele değil; 5x5 matrisi üzerinden elde edilen risk puanlarına (Kritik, Yüksek, Orta, Düşük) göre tahsis eder.
- **3. Yaygın Hata:** Tehdit ile zafiyeti birbirine karıştırmak. "Sistemde SQL Injection tehdidi var" demek teknik bir hatadır; SQL Injection bir **zafiyettir**, o açığı arayan botnet veya saldırgan ise **tehdittir**.
- **4. Standart ve Kaynak:** NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments) | ISO/IEC 27005:2022.

---

### Soru 2 (G002-SC2): Tehdit, zafiyet, olay ve risk: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

- **1. Yanıt:** Gün 002 laboratuvarı ([`risk_matrix_evaluator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/uygulama/risk_matrix_evaluator.py)), 3 gerçekçi senaryoyu (Hastane, E-Ticaret, Muhasebe) matematiksel risk formülü ve artık risk hesaplamasıyla doğrular.
- **2. Teknik Gerekçe:**
  - *Girdi:* [`senaryolar.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/ornek_veri/senaryolar.json) dosyasındaki varlık, tehdit, zafiyet, etki, olasılık ve önlem parametreleri.
  - *İşlem:* 5x5 matris skoru hesaplama ($Olasılık \times Etki$), önlem sonrası artık risk (residual risk) ve azalma yüzdesinin formüle edilmesi.
  - *Beklenen Sonuç:* SCN-01 için risk 20'den 2'ye (%90 azalma), SCN-02 için 25'ten 4'e (%84 azalma), SCN-03 için 16'dan 2'ye (%87.5 azalma) inmesi.
- **3. Yaygın Hata (Negatif Kontrol):** "Bir güvenlik önlemi aldık, artık riskimiz 0 oldu" şeklindeki ölümcül yanılgı. Kodumuz `UnrealisticSecurityClaimError` fırlatarak bu iddiayı engeller; ayrıca aralık dışı (örn. olasılık=6) parametreleri `InvalidRiskParameterError` ile durdurur.
- **4. Standart ve Kaynak:** ISO 31000:2018 (Risk Management Guidelines) | NIST CSF Identify (ID.RA Risk Assessment).

---

### Soru 3 (G002-SC3): 'Tehdit, zafiyet, olay ve risk' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

- **1. Yanıt:** Risk; korunmaya değer bir varlığın zafiyeti ile onu hedef alabilecek yetenekteki tehdit aktörünün aynı düzlemde kesişmesiyle oluşur.
- **2. Teknik Gerekçe:**
  - *Oluşumu:* Varlık yoksa risk yoktur; zafiyet yoksa tehdit içeri sızamaz; tehdit yoksa zafiyet tek başına zarar vermez. Üç bileşen birleşince risk doğar.
  - *Tespiti:* Zafiyet tarayıcıları (Nessus/OpenVAS), Tehdit İstihbaratı (CTI), sızma testleri ve İş Etki Analizi (BIA) ile belirlenir.
  - *Önlenmesi:* Risk 4 stratejiyle yönetilir: Azaltma (Mitigation: yama/WAF), Kaçınma (Avoidance: riskli servisi kapatma), Devretme (Transfer: siber sigorta) ve Kabul Etme (Acceptance: artık riski izleme).
- **3. Yaygın Hata:** Sistemde bir açık çıktığında hemen panikleyip sistemin batacağını sanmak. Açık izole bir test ağındaysa ve internete kapalıysa risk seviyesi düşüktür; bağlam hesaba katılmalıdır.
- **4. Standart ve Kaynak:** OWASP Risk Rating Methodology | FAIR (Factor Analysis of Information Risk) Framework.
