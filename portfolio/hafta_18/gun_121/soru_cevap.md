# GÜN 121: Risk Skorlama ve Kontrol Seçimi Soru - Cevap Dokümanı

## SORU 1: Siber Güvenlikte Nitel (Qualitative) ve Nicel (Quantitative) Risk Analizi Arasındaki Farklar Nelerdir ve Ne Zaman Birlikte Kullanılmalıdır?

### 1. Soru Başlığı ve Tanımı
Risk analizinde 5x5 matris tabanlı nitel (qualitative) yöntem ile SLE/ARO/ALE tabanlı nicel (quantitative) yöntem arasındaki temel farklar nelerdir; kurumsal güvenlik karar mekanizmasında bu iki yaklaşım nasıl hibritleştirilir?

### 2. Derinlemesine Teknik Analiz
1. **Nitel Risk Analizi (Qualitative Analysis):**
   - **Girdiler:** Subjektif veya tecrübeye dayalı skalalar (Olasılık: 1-Çok Düşük'ten 5-Çok Yüksek'e; Etki: 1-Önemsiz'den 5-Felaket Seviyesine).
   - **Çıktı:** 1 ile 25 arasında skor ve renk kodlu seviyeler (Düşük, Orta, Yüksek, Kritik).
   - **Avantajı:** Hızlıdır, karmaşık finansal veri gerektirmez, operasyonel ekipler ve teknik uzmanlar için anlaması kolaydır.
   - **Dezavantajı:** Subjektiftir; kişiden kişiye değişir ve bütçe onaylarında yönetim kuruluna somut finansal gerekçe sunamaz.
2. **Nicel Risk Analizi (Quantitative Analysis):**
   - **Girdiler:** Parasal varlık değeri ($AV$), hasar oranı ($EF$), yıllık gerçekleşme frekansı ($ARO$).
   - **Formüller:** $SLE = AV \times EF$, $ALE = SLE \times ARO$.
   - **Çıktı:** Yıllık beklenen ortalama parasal kayıp ($ALE$) ve yatırımın geri dönüş oranı ($ROSI$).
   - **Avantajı:** Yönetim kurulunun anlayacağı dildedir (ROI / Maliyet analizi yapılabilir).
   - **Dezavantajı:** Doğru veri toplamak zordur; maruz kalma faktörünü veya sıklığı tahmin etmek istatistiksel uzmanlık ister.
3. **Hibrit Yaklaşım (Modern Entegrasyon):**
   Önce tüm sistem varlıkları nitel 5x5 matris ile hızlıca taranır. 12 puanın üzerindeki (Yüksek ve Kritik) riskler nicel finansal analiz havuzuna alınır; kontrol seçiminde ALE ve ROSI hesaplanarak yönetim onayına sunulur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir holding bünyesindeki finansal teknoloji şirketinde güvenlik yöneticisi, 50.000$'lık bir PAM (Privileged Access Management) yazılımı satın almak istemiş ancak CFO "Zaten firewall ve antivirüsümüz var, buna gerek yok" diyerek bütçeyi reddetmiştir.

**Pratik Çözüm:**
1. **Nitel Tutanak:** Yönetici, Domain Controller ve DB sunucularına doğrudan admin girişi riskini Olasılık=4, Etki=5 (Skor: 20 - Kritik) olarak belirler.
2. **Nicel Hesaplama:**
   - Varlık Değeri (DB): $1,000,000.
   - Exposure Factor (EF): %60 (fidye yazılımı + veri sızıntısı).
   - SLE: $1,000,000 \times 0.60 = \$600,000.
   - ARO: 0.5 (2 yılda bir gerçekleşme olasılığı).
   - Doğal ALE: $\$600,000 \times 0.5 = \$300,000$ yıllık beklenen kayıp!
   - PAM Kontrolü Yıllık Maliyeti: $50,000. Etkinlik: %90.
   - Artık ALE: $\$300,000 \times 0.10 = \$30,000$.
   - Önlenen Kayıp: $\$270,000$.
   - Net Kazanç: $\$270,000 - \$50,000 = \$220,000$.
   - $ROSI = (\$220,000 / \$50,000) \times 100 = \%440$.
3. **Sonuç:** CFO bu finansal raporu gördüğünde riskin büyüklüğünü ve kontrolün şirkete her yıl 220.000$ tasarruf sağlayacağını anlayarak bütçeyi aynı gün onaylar.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, yönetim kurulunun karşısına çıkıp teknik jargona boğulursan bütçe alamazsın. 'Admin şifresi kırılabilir' demek mühendis dilidir; 'Bu açık kapatılmazsa şirketin yıllık beklenen kaybı 300 bin dolardır, 50 bin dolarlık bu kontrol bize yüzde 440 getiri sağlar' demek lider dilidir. Güvenlik mühendisliğini finansal akılla taçlandırmayan uzman yarım uzmandır."

---

## SORU 2: 'Risk Kabulü' (Risk Acceptance) Stratejisinde CWE-1025 Açığı Nasıl Ortaya Çıkar ve Kurumsal Risk İştahı ile Nasıl Engellenir?

### 1. Soru Başlığı ve Tanımı
Bir güvenlik riskini "Kabul Edildi" (Accept) olarak işaretlemek neden en çok istismar edilen yönetişim zaafiyetidir ve CWE-1025 (Hatalı Faktörlerle Karşılaştırma / Uygunsuz Risk Kararı) çerçevesinde bu açık nasıl önlenir?

### 2. Derinlemesine Teknik Analiz
Yazılım ve sistem yaşam döngülerinde ekipler çoğu zaman teslim tarihlerine yetişebilmek, bütçe aşımından kaçınmak veya ek iş yükü almamak için açıkta duran zafiyetleri "Biz bu riski biliyoruz ve kabul ediyoruz" diyerek kapatırlar.

Bu durum şu teknik açıkları doğurur:
1. **Yetkisiz Risk Kararı (Improper Privilege in Decision Making):** Bir geliştirici veya sistem yöneticisi kendi yetkisini aşarak şirketin geleceğini tehlikeye atacak bir riski tek başına "kabul" edemez (CWE-250 / CWE-285).
2. **Risk İştahı İhlali (Appetite Breach):** Kurum yönetim kurulunun onayladığı risk iştahı politikası örneğin azami 10 puan iken, 20 puanlık kritik bir açığın kabul edilmesi doğrudan kurumsal politika ihlalidir.
3. **CWE-1025 Karşılığı:** Karşılaştırma faktörlerinin çarpıtılmasıdır. "Yama geçersek servis 1 saat durur" gerekçesiyle "Servisin tamamen ele geçirilmesi ve 1 milyon $ ceza kesilmesi" riski karşılaştırılıp küçük maliyetten kaçınmak için devasa risk kabul edilir.

Çözüm: Risk yönetim motorunda programatik **Executive Sign-Off (C-Level Resmi Onay)** zorunluluğudur. Eğer risk puanı veya ALE kurumsal risk iştahını aşıyorsa, sistem CEO/CISO imzası olmadan o riskin statüsünü asla 'KABUL_EDİLDİ' yapmaz ve üretime geçişi bloklar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sağlık teknolojisi firmasında, hasta verilerini tutan API sunucusunda TLS 1.0/1.1 eski şifreleme protokolleri açık kalmıştır. Yazılım lideri, eski bazı medikal cihazların bağlantısı kopmasın diye bu açığı üst yönetime haber vermeden "Düşük öncelik - Risk kabul edildi" olarak işaretlemiştir. İki ay sonra hastane ağı dinlenerek 50.000 hastanın sağlık verisi sızdırılmış ve regülatör kurum firmaya 5 milyon € ceza kesmiştir.

**Pratik Çözüm:**
1. **Motor Tabanlı Yönetişim Denetimi:** `risk_control_engine.py` içinde `enforce_readiness()` kuralı devreye alınır.
2. **Otomatik İstisna Engeli:** Doğal skoru veya artık skoru 10'u aşan hiçbir risk, `executive_sign_off=True` olmadan kabul edilemez; `RiskAppetiteExceededError` fırlatılır.
3. **Denetim İzi (Audit Log):** Her onay, imzayı atan yöneticinin adı, tarihi ve gerekçesiyle birlikte değiştirilemez günlüğe kaydedilir.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, 'Risk kabul edildi' demek 'Ben yangın alarmını kapattım, içerisi yanarsa sorumluluk bende değil' demek değildir! Eğer o riski alan kişi şirket battığında hesabını verebilecek C-Level bir yönetici değilse, o kabul hükümsüzdür. İmzası olmayan kabul, ihmaldir; ihmal ise suçtur. Sistemine öyle bir kod yaz ki, hiçbir mühendis kendi kafasına göre kritik riski halının altına süpüremesin."

---

## SORU 3: Çoklu Güvenlik Kontrolleri Uygulandığında (Savunma Derinliği) Birleşik Etkinlik Neden Basitçe Toplanamaz ve Bağımsız Çarpımsal Model Nasıl İşler?

### 1. Soru Başlığı ve Tanımı
Bir güvenlik riski için %80 etkili bir EDR ve %70 etkili bir WAF seçildiğinde, toplam etkinlik neden $\%80 + \%70 = \%150$ olamaz; bağımsız olasılıklar tabanlı artık risk modeli nasıl çalışır?

### 2. Derinlemesine Teknik Analiz
Güvenlik kontrollerinin etkinliği matematiksel olarak **Olasılık Kuramı (Probability Theory)** çerçevesinde değerlendirilir:
1. **Doğrusal Toplama İmkansızlığı:** Hiçbir güvenlik kontrolünün etkinliği %100'ü aşamaz. İki kontrolün basitçe toplanması matematiksel bir saçmalıktır ($0.80 + 0.70 = 1.50$).
2. **Seri Bağlı Güvenlik Bariyerleri (Defense-in-Depth):**
   - Bir saldırgan birinci bariyere (örn. WAF) çarptığında, WAF saldırıların %75'ini engeller ($e_1 = 0.75$).
   - WAF'tan sızabilen açıkta kalan risk oranı $1 - e_1 = 0.25$ (%25)'tir.
   - İkinci bariyer (EDR), yalnızca WAF'ı aşabilen bu %25'lik artık saldırı hacmiyle karşılaşır.
   - EDR bu kalan kısmın %80'ini engeller ($e_2 = 0.80$).
   - Her iki engeli de aşmayı başaran nihai artık risk oranı:
     $$\text{Kalan Risk Oranı} = (1 - e_1) \times (1 - e_2) = 0.25 \times 0.20 = 0.05 \implies \%5$$
   - Dolayısıyla iki kontrolün birleşik etkinliği:
     $$\text{Birleşik Etkinlik} = 1 - 0.05 = 0.95 \implies \%95$$
3. **Mutlak Güvenlik Sınırı (Cap Factor):**
   Gerçek dünyada hiçbir zaman %100 güvenlik olmaz; sıfır gün (zero-day) zafiyetleri ve insan faktörü nedeniyle kurumsal risk motorumuz birleşik etkinliğe daima %98'lik bir tavan sınırı (`min(0.98, total_eff)`) uygular.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kamu kurumunda sistem yöneticisi, sunuculara hem Antivirüs (%60), hem Host Tabanlı IPS (%50) hem de Uygulama Beyaz Listesi (%70) kurmuş ve yönetime "Sistemimiz yüzde 180 korunmaktadır, bize hacker sızamaz" raporu vermiştir. Kurum müfettişleri bu raporu teknik olarak geçersiz saymış ve gerçek koruma oranının hesaplanmasını istemiştir.

**Pratik Çözüm:**
1. **Bağımsız Çarpımsal Model Uygulaması:**
   $$\text{Kalan Risk} = (1 - 0.60) \times (1 - 0.50) \times (1 - 0.70) = 0.40 \times 0.50 \times 0.30 = 0.06$$
2. **Gerçek Koruma Oranı:** $1 - 0.06 = 0.94 \implies \%94$.
3. **Artık Risk Hesaplaması:** Sistem %94 oranında korunmaktadır; %6'lık artık risk için ise veri yedekleme ve siber sigorta (Transfer) devreye alınmalıdır.

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, üst üste üç zırh giysen bile zırhların birleşim yerlerinde daima küçük bir boşluk kalır. 'Yüzde yüz güvendeyiz' diyen biriyle karşılaşırsan bil ki ya matematikten anlamıyordur ya da sana yalan söylüyordur. Siber güvenlikte mutlak sıfır risk yoktur; sadece titizlikle hesaplanmış, kabul edilebilir seviyeye indirilmiş ve sürekli izlenen artık risk vardır."
