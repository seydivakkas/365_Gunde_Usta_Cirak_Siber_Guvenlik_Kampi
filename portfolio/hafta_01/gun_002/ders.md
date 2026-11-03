<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 002: Tehdit, Zafiyet, Olay ve Risk
## Tehlike Kavramlarının Ayrımı, 5x5 Risk Matrisi ve Artık Risk Felsefesi

---

### 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Selam evlat. Dün seninle güvenliğin 3 kutsal direğini — Gizlilik, Bütünlük ve Erişilebilirlik (CIA) — konuştuk. Bugün siber güvenlik sektöründe çalışanların bile %80'inin birbiriyle karıştırdığı, birbirinin yerine rastgele kullandığı dört temel kavramın ameliyatını yapacağız: **Tehdit, Zafiyet, Olay ve Risk.**

Sana bir soru: "Kapısı açık bir ev tehlikede midir?"
Düşün bakalım. 
Eğer o ev, kimsenin yaşamadığı, haritada bile görünmeyen ıssız bir çölün ortasındaysa kapısının açık olması seni korkutur mu? Hayır.
Peki o ev, şehrin en azılı hırsız çetelerinin cirit attığı bir sokaktaysa ve içinde külçe altınlar varsa? İşte o zaman uykun kaçar!

Buradaki zihinsel modeli hemen yerine oturtalım:
- **Zafiyet (Vulnerability):** Evin kapısının kilitlenmemiş, açık bırakılmış olmasıdır. Yani sistemdeki eksiklik, zayıflık.
- **Tehdit (Threat):** Sokakta elinde maymuncukla gezen hırsızdır. Yani potansiyel tehlike unsuru.
- **Güvenlik Olayı (Incident):** Hırsızın o açık kapıyı görüp içeri girmesi, altınları çantaya doldurması anıdır. Yani zafiyetin istismar edilmesi.
- **Risk (Risk):** "Bu hırsızın bu sokağa gelme ihtimali nedir ve kapıyı açıp girerse benim kaybım ne olur?" sorusunun matematiksel karşılığıdır.

Unutma evlat: Zafiyet tek başına felaket değildir. Tehdit de tek başına içeri giremez. Felaket, zafiyet ile tehdidin aynı noktada buluştuğu anda kopar!

---

### 2. Sıfırdan Başlayan Kristal Netliğinde Teori (0'dan Uzmanlığa Derinlik)

Kavramları cerrah titizliğiyle ayrıştıralım:

```
+-----------------------------------------------------------------------------------+
| TEHDİT (Threat)       : Potansiyel zarar verme kapasitesine sahip aktör / doğa olayı|
| ZAFİYET (Vulnerability): Tehdidin içeri sızabileceği açık, hata veya eksiklik      |
| İSTİSMAR (Exploit)    : Zafiyeti tetikleyen kod, araç veya yöntem                 |
| GÜVENLİK OLAYI (Inc.) : İstismarın başarıya ulaşması ve sistem dengesinin bozulması|
| RİSK (Risk)           : Olayın meydana gelme olasılığı ile yaratacağı etkinin çarpımı|
+-----------------------------------------------------------------------------------+
```

#### A. Tehdit Türleri ve Sınıflandırması
1. **Dış Tehditler (External Threats):** Şirket sınırları dışından gelen saldırganlar; devlet destekli siber casuslar (APTs), organize fidye çeteleri, hacktivistler, script kiddie'ler.
2. **İç Tehditler (Insider Threats):** En tehlikeli tehdit türüdür! Yetkili şirket çalışanı, sistem yöneticisi, kovulmaktan korkan mutsuz bir personel veya kandırılan bir sekreter. Zaten sistemin içinde oldukları için güvenlik duvarları onları durduramaz.
3. **Çevresel ve Doğal Tehditler:** Deprem, su baskını, elektrik kesintisi. Siber güvenlik sadece hackerları değil, donanımın sürekliliğini de kapsar.

#### B. Zafiyet (Vulnerability) ve CVE Mekanizması
Zafiyetler gökten zembille inmez; insan hatasından doğar:
- **Yazılımsal Hatalar:** Bellek taşması (Buffer Overflow), girdi doğrulama eksikliği (SQL Injection), mantıksal yetkilendirme açıkları (IDOR).
- **Yapılandırma Hataları (Misconfiguration):** Varsayılan şifrelerin (`admin / admin`) değiştirilmemesi, portların internete gereksiz açılması, yetkisiz dosya izinleri (`chmod 777`).
- **İnsan Zafiyetleri:** Güvenlik farkındalığı olmayan, gelen her e-postadaki linke tıklayan personel.

#### C. Risk Analizinin Matematiği (NIST CSF & ISO 27005)
Uluslararası standartlarda risk şu formülle hesaplanır:
$$\text{Risk Skoru} = \text{Olasılık (Likelihood: 1-5)} \times \text{Etki (Impact: 1-5)}$$

| Skor Aralığı | Risk Seviyesi | Alınması Gereken Aksiyon |
| :--- | :--- | :--- |
| **1 – 4** | **DÜŞÜK** | Kabul edilebilir; rutin izleme yeterlidir. |
| **5 – 9** | **ORTA** | Planlı iyileştirme; bir sonraki güncelleme döngüsünde kapatılır. |
| **10 – 16** | **YÜKSEK** | Acil önlem planı; en kısa sürede kapatılmalı, ek kontroller konmalı. |
| **17 – 25** | **KRİTİK** | Derhal müdahale! Gerekirse sistem izole edilmeli, kriz masası toplanmalıdır. |

#### D. Doğal Risk (Inherent) vs Artık Risk (Residual)
- **Doğal Risk (Inherent Risk):** Hiçbir güvenlik önlemi alınmadığı zamanki çıplak risk seviyesidir.
- **Önlem / Kontrol (Security Controls):** Riski düşürmek için koyduğumuz kalkanlardır (şifreleme, güvenlik duvarı, eğitim).
- **Artık Risk (Residual Risk):** Önlemler uygulandıktan sonra geriye kalan kaçınılmaz risktir. **Sıfır risk diye bir şey yoktur.**

---

### 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

| Rol | Odak Noktası | Düşünce Biçimi |
| :--- | :--- | :--- |
| **Saldırgan (Offensive)** | Sistemdeki **en zayıf halkayı** arar. | "Bu şirketin 100 sunucusu var, 99 tanesi tamamen güncel. Ama muhasebedeki eski bir test sunucusunu unutmuşlar. O tek zafiyet içeri girmem için yeterli!" |
| **Savunmacı (Defensive)** | Tüm sistemi **bütünsel bir savunma hattıyla (Defense-in-Depth)** donatır. | "Saldırganın tek bir açığı bulabileceğini kabul ediyorum. Bu yüzden içeri girse bile ilerleyemesin diye ağı segmentlere ayırıyorum, veriyi şifreliyorum ve EDR ile her hareketini izliyorum." |

---

### 4. Hocayla Birlikte Canlı Laboratuvar (Adım Adım Gerçek Kod ve Komutlar)

Bugün geliştirdiğimiz profesyonel risk motorunu masaya yatırıyoruz.

#### Adım 1: Senaryolar Verimizi İnceleyelim
Veri dosyamız: [`senaryolar.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/ornek_veri/senaryolar.json)
Dosyamızda 3 kritik senaryo tanımlandı:
1. Hastane Veritabanı ve Şifresiz Disk
2. E-Ticaret Web Sunucusunda Yamasız RCE Açığı
3. Muhasebeye Yönelik Oltalama (Phishing)

#### Adım 2: Laboratuvar Kodunu Çalıştırma
Aşağıdaki komutla tüm senaryoları doğrulayıp 5x5 matrisini hesaplatalım:
```powershell
python portfolio/hafta_01/gun_002/uygulama/risk_matrix_evaluator.py --eval
```

**Konsol Çıktısı Analizi:**
- **SCN-01 (Hastane):** Doğal risk skoru $4 \times 5 = 20$ (KRİTİK). BitLocker şifreleme ve biyometrik kasa önlemi sonrasında risk $1 \times 2 = 2$'ye (DÜŞÜK) indi. Risk azalması: %90!
- **SCN-02 (E-Ticaret):** Doğal risk skoru $5 \times 5 = 25$ (KRİTİK). Otomatik yama ve WAF önlemleri sonrası risk $2 \times 2 = 4$'e (DÜŞÜK) indi. Risk azalması: %84!
- **SCN-03 (Muhasebe):** Doğal risk skoru $4 \times 4 = 16$ (YÜKSEK). Çift onay (4-eyes) ve DMARC kuralları sonrası risk $1 \times 2 = 2$'ye (DÜŞÜK) indi. Risk azalması: %87.5!

#### Adım 3: Negatif Kontrolün Sınanması
Eğer birisi sistemde "Biz öyle bir güvenlik önlemi aldık ki artık riskimiz 0 oldu!" derse ne olur?
Kodumuzdaki `UnrealisticSecurityClaimError` devreye girer ve bu iddiayı doğrudan reddeder! Çünkü siber güvenlikte hiçbir varlığın riski sıfır olamaz.

---

### 5. Hocanın "Ölümcül Hatalar ve Mülakat Tuzakları" Notu

> [!WARNING]
> **Ölümcül Hata: "Sistemde zafiyet buldum, o halde şirket batmak üzere!"**
> Zafiyetin varlığı otomatikman yüksek risk anlamına gelmez. Eğer o zafiyet internete kapalı, izole edilmiş, içinde hiçbir hassas veri bulunmayan bir geliştirme sunucusundaysa risk düşüktür. Varlık değerini ve tehdidin erişebilirliğini hesaba katmadan çıkarılan panik raporları güvenlik ekiplerinin güvenilirliğini yok eder.

> [!NOTE]
> **Mülakat Sorusu: "Zafiyet (Vulnerability) ile Tehdit (Threat) arasındaki temel farkı tek bir cümleyle nasıl özetlersin?"**
> **Doğru Yanıt:** "Tehdit, sistemi vurmak isteyen dış veya iç potansiyel aktördür; zafiyet ise sistemin kendi bünyesinde barındırdığı ve tehdidin içeri girmesine izin veren açık veya zayıflıktır."

---

### 6. Günün Pratik Görevi (Challenge & Walkthrough)

**Müfredat Görevi:** Üç gerçek hayat senaryosunu Tehdit, Zafiyet, Etki ve Önlem sütunlarına ayır:

| Senaryo No | Varlık | Tehdit (Threat) | Zafiyet (Vulnerability) | Etki (Impact) | Uygulanacak Önlem (Control) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SCN-01** | 50.000 Hastanın Sağlık Kayıtları | Taşeron personel / Fiziksel hırsız | Şifresiz harici disk, kilitlenmeyen arşiv dolabı | KVKK cezası, mahremiyet ifşası, tazminat davaları | AES-256 BitLocker disk şifreleme, biyometrik kasa |
| **SCN-02** | Canlı Ödeme ve Sipariş Web Sunucusu | Otomatik botnetler / Ransomware çeteleri | 6 aydır yamanmamış Log4j / RCE kütüphanesi | Sunucunun ele geçirilmesi, web sitesinin çökmesi, ciro kaybı | Haftalık otomatik yama yönetimi, WAF kural seti, EDR ajanı |
| **SCN-03** | Şirket Banka Mevduat Hesapları | CEO Sahteciliği (BEC) yapan siber çete | Personelde farkındalık eksikliği, tek yetkili EFT süreci | 250.000 TL doğrudan mali kayıp | DMARC/SPF e-posta koruması, çift imza (4-eyes) kuralı |

---

### 7. Hocanın Soru Odası (Excel Soru Bankası Detaylı Yanıtları)

#### Soru 1 (G002-SC1): Tehdit, zafiyet, olay ve risk: Temel mekanizmayı ve güvenlik önemini açıkla.
- **1. Yanıt:** Tehdit potansiyel tehlike unsurudur, zafiyet bu tehlikenin istismar edebileceği eksikliktir, güvenlik olayı zafiyetin tetiklenmesidir, risk ise bu olayın meydana gelme olasılığı ile yaratacağı etkinin bileşimidir ($\text{Risk} = \text{Olasılık} \times \text{Etki}$).
- **2. Teknik Gerekçe:** Tehdit aktörünün motivasyonu, yeteneği ve fırsatı zafiyetle buluştuğunda güvenlik olayı tetiklenir. Kurumlar bütçe ve savunma kalkanlarını 5x5 risk matrisi puanlarına (Kritik, Yüksek, Orta, Düşük) göre tahsis eder.
- **3. Yaygın Hata:** Tehdit ile zafiyeti birbirine karıştırmak. SQL Injection bir zafiyettir; o açığı arayan botnet veya saldırgan ise tehdittir.
- **4. Standart ve Kaynak:** NIST SP 800-30 Rev. 1 | ISO/IEC 27005:2022.

#### Soru 2 (G002-SC2): Tehdit, zafiyet, olay ve risk: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
- **1. Yanıt:** Gün 002 laboratuvarı (`risk_matrix_evaluator.py`), 3 gerçekçi senaryoyu (Hastane, E-Ticaret, Muhasebe) matematiksel risk formülü ve artık risk hesaplamasıyla doğrular.
- **2. Teknik Gerekçe:** Girdi: `senaryolar.json` dosyasındaki senaryo parametreleri. İşlem: 5x5 matris skoru hesaplama ($Olasılık \times Etki$), önlem sonrası artık risk (residual risk) ve azalma yüzdesinin formüle edilmesi. Beklenen Sonuç: SCN-01 için risk 20'den 2'ye (%90), SCN-02 için 25'ten 4'e (%84), SCN-03 için 16'dan 2'ye (%87.5) indirilmesi.
- **3. Yaygın Hata (Negatif Kontrol):** "Önlem aldık, risk sıfır oldu" iddiası. Kodumuz `UnrealisticSecurityClaimError` fırlatarak bu iddiayı engeller; ayrıca aralık dışı (örn. olasılık=6) parametreleri `InvalidRiskParameterError` ile durdurur.
- **4. Standart ve Kaynak:** ISO 31000:2018 (Risk Management Guidelines) | NIST CSF (ID.RA).

#### Soru 3 (G002-SC3): 'Tehdit, zafiyet, olay ve risk' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
- **1. Yanıt:** Risk; korunmaya değer bir varlığın zafiyeti ile onu hedef alabilecek yetenekteki tehdit aktörünün aynı düzlemde kesişmesiyle oluşur.
- **2. Teknik Gerekçe:** Varlık yoksa risk yoktur; zafiyet yoksa tehdit içeri sızamaz; tehdit yoksa zafiyet tek başına zarar vermez. Zafiyet tarayıcıları, CTI ve BIA ile tespit edilir. 4 stratejiyle yönetilir: Azaltma (Mitigation), Kaçınma (Avoidance), Devretme (Transfer) ve Kabul Etme (Acceptance).
- **3. Yaygın Hata:** Açık bulunan her sistemin batacağını sanmak. Açık izole geliştirme ortamındaysa risk düşüktür; bağlam hesaba katılmalıdır.
- **4. Standart ve Kaynak:** OWASP Risk Rating Methodology | FAIR Framework.
