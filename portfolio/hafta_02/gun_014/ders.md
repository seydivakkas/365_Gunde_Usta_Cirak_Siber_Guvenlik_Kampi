# GÜN 014: Aşama 1 Kalite Özeti ve Güvenlik Temelleri Kabulü (Mini Proje 2)
**Aşama 01: Temel Güvenlik ve Altyapı | Hafta 02 Bitiş Kilometre Taşı**

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 🧭 1. Hocanın Giriş Sohbeti & Zihinsel Model

Evlat, bugün arkana yaslan ve derin bir nefes al. Çünkü bugün, siber güvenlik yolculuğumuzun ilk büyük kalesini fethettiğimiz gün: **Aşama 1 (Temel Güvenlik ve Altyapı) Kapanış ve Kalite Kabul Projesi!**

Şimdi gözlerini kapat ve şu analojiyi kafanda canlandır:
Devasa bir gökdelen inşa eden bir başmühendissin. Toprağı kazdın, temele tonlarca çelik yerleştirdin, özel beton döktün. Gökdelenin 50. katına çıkmadan önce, inşaat denetim komisyonu gelir ve o temelin her bir santimetresini ultrasonik testlerle, basınç testleriyle inceler. Eğer temelde tek bir çatlak varsa, yukarıya tek bir tuğla bile koymana izin vermezler! Çünkü çürük temel üzerine inşa edilen bir bina en ufak bir sarsıntıda yerle bir olur.

İşte siber güvenlikte de böyledir!  
Son 13 gün boyunca sıfırdan başlayarak bir siber güvenlik uzmanının sahip olması gereken en sağlam temelleri nakış gibi işledik:
- **Hafta 1:** CIA Üçlüsü'nün felsefesini, Tehdit-Açıklık-Risk matrisini, yasal ve etik kırmızı çizgileri (RoE), NIST CSF 2.0 çerçevesini, Varlık Envanteri tutmayı, STRIDE tehdit modellemesini ve Güvenli Laboratuvar Sözleşmesi'ni inşa ettik.
- **Hafta 2:** Sanallaştırmanın güvenlikteki rolünü, hypervisor izolasyonunu, Windows ve Linux sanal makinelerini CIS Benchmark taban çizgisiyle sertleştirmeyi, VLAN ve mikro-segmentasyonla ağ sınırları çizmeyi, durum takipli conntrack güvenlik duvarlarını, DNS sinkhole kalkanını, snapshot ile yedek arasındaki ölümcül farkı ve CRAAP kaynak doğrulama disiplinini öğrendik.

Bugün bu 13 günün tüm parçalarını tek bir masaya yatırıyoruz ve kurumsal bir **Kanıt Zinciri (Chain of Evidence)** oluşturuyoruz. Bugün masamızdaki soru şudur:  
*"Kurduğumuz başlangıç laboratuvarı, gerçek bir siber saldırı simülasyonunu güvenle karşılayabilecek, etik sınırları aşmayacak ve tek bir güvenlik önlemine körlemesine güvenme tuzağına düşmeyecek kadar olgun mu?"*  
Bugün bu sorunun cevabını bilimsel kriterlerle vereceğiz ve Aşama 1 Kabul Sertifikamızı mühürleyeceğiz.

---

## 🔬 2. Sıfırdan Kristal Netliğinde Teori (Under the Hood)

Siber güvenlikte "Aşama Kabulü", parçaların toplamından daha büyük bir anlam ifade eder. Bir laboratuvarın kabul edilebilmesi için şu 5 temel sütunun tek bir kanıt zincirine bağlanması şarttır:

```
+-------------------------------------------------------------------------------+
|         AŞAMA 1 SİBER GÜVENLİK TEMELLERİ KANIT ZİNCİRİ (CHAIN OF EVIDENCE)    |
+-------------------------------------------------------------------------------+

  [1. ETİK ROE SÖZLEŞMESİ] ──► Yazılı İzin, Hedef IP Sınırı, Üretim Sistemlerine 0 Temas
               │
               ▼
  [2. VARLIK ENVANTERİ]   ──► Donanım, Sanal Makine ve Veri Sınıflandırması
               │
               ▼
  [3. NIST CSF 2.0 ALTI TEMEL İŞLEVİ]
        ├── GOVERN   (Yönetişim)  ──► Kurumsal Güvenlik Politikası ve Rol Dağılımı
        ├── IDENTIFY (Tanımlama)  ──► Risk Matrisi ve STRIDE Tehdit Modellemesi
        ├── PROTECT  (Koruma)     ──► CIS Seviye 1, SSH Anahtar Auth, Mikro-Segmentasyon
        ├── DETECT   (Tespit)     ──► Event ID 4688, Merkezi Syslog ve Conntrack
        ├── RESPOND  (Müdahale)   ──► Olay Müdahale Planı ve İzolasyon Protokolü
        └── RECOVER  (Kurtarma)   ──► 3-2-1-1-0 WORM Yedek ve Rollback Tatbikatı
               │
               ▼
  [4. SANALLAŞTIRMA & İZOLASYON] ──► Hyper-V/KVM İzolasyonu, 4 VLAN Bölgesi, DNS Sinkhole
               │
               ▼
  [5. KAYNAK DOĞRULAMA (CRAAP)] ──► Resmî NVD Bültenleri, Çapraz Teyit, Zehirli PoC Taraması
               │
               ▼
  [AŞAMA 1 KABUL SERTİFİKASI] ──► SHA-256 Kriptografik Bütünlük İmzası (PASS - 100/100)
```

### A. NIST CSF 2.0'ın 6 Temel İşlevi ve Bütünleşik Anlamı
NIST CSF 2.0 (2024 Güncellemesi), siber güvenliği yalnızca teknik bir koruma (firewall/antivirüs) olarak görmez; 6 temel fonksiyonun kusursuz bir uyum içinde çalışmasını şart koşar:
1. **Govern (Yönetişim):** Güvenlik stratejisi kimin onayında? Yasal ve etik sınırlar tanımlandı mı?
2. **Identify (Tanımlama):** Hangi varlıkları koruyoruz? Bu varlıkların tehditleri (STRIDE) ve risk skorları nelerdir?
3. **Protect (Koruma):** Kimlik doğrulama, CIS sertleştirmesi, ağ mikro-segmentasyonu ve veri şifrelemesi aktif mi?
4. **Detect (Tespit):** Saldırgan sızarsa onu nasıl göreceğiz? Event Log 4688, Syslog ve ağ conntrack kayıtları tutuluyor mu?
5. **Respond (Müdahale):** Alarm çaldığında ne yapılacak? Kurban makine karantina VLAN'ına nasıl çekilecek?
6. **Recover (Kurtarma):** Sistem çökerse veya fidye yazılımı bulaşırsa altın duruma nasıl dönülecek? (WORM yedek ve rollback).

### B. "Bir Güvenlik Önlemini Tek Başına Eksiksiz Savunma Sanma" Yanılgısı (Single Measure Fallacy)
Bu tuzak, siber güvenlik dünyasındaki en yaygın ve en ölümcül hastalıktır.  
- **Örnek 1:** Bir kurum milyonlarca liralık yeni nesil güvenlik duvarı (Next-Gen Firewall - Protect) satın alır. Ancak varlık envanteri (Identify) tutulmamıştır; ağda unutulmuş 10 yıllık zafiyetli bir test sunucusu vardır. Saldırgan o sunucu üzerinden içeri sızar.
- **Örnek 2:** Şirket son teknoloji EDR (Detect) kurmuştur; ancak değişmez çevrimdışı yedekleme (Recover) yapmamıştır. Fidye yazılımı EDR'ı atlatıp dosyaları şifrelediğinde şirket iflas eder.  
**Usta-Çırak Kuralı:** Güvenlik bir zincirdir. Zincir en kalın halkası kadar değil, en zayıf halkası kadar güçlüdür!

---

## ⚔️ 3. İki Yönlü Bakış: Saldırganın Gözü vs Savunmacının Kalkanı

### 🔴 Saldırganın Gözü (Offensive Perspective)
Bir sisteme veya laboratuvara saldıran siber tehdit aktörü, savunmacının en güçlü olduğu yere (örneğin güçlü şifrelenmiş ana giriş kapısına) saldırmaz. Saldırganın aradığı şey **"bütünlük çatlaklarıdır"**:
1. **Unutulmuş Varlıklar:** Kurumun varlık envanterinde yer almayan, güncellenmemiş, varsayılan şifreli geliştirme sunucuları.
2. **Kapsam ve Ağ Sızıntıları:** Düz (flat) ağlarda bir kez içeri girdikten sonra diğer tüm kritik sunuculara engelsizce sıçrama (lateral movement).
3. **Kurtarma Zaafiyeti:** Sisteme sızdığında ilk olarak yedekleme sunucusunu ve VSS gölge kopyalarını hedef alma; kurbanı fidye ödemeye mecbur bırakma.
4. **Zehirli Yemler:** Savunmacının araştırma yaparken indirebileceği sahte istismar kodlarına (Trojanized PoC) arka kapı yerleştirme.

### 🔵 Savunmacının Kalkanı (Defensive Perspective)
1. **Çok Katmanlı Derinlemesine Savunma (Defense-in-Depth):**  
   Güvenlik duvarı aşılsa bile mikro-segmentasyon saldırganı durdurur; makine ele geçirilse bile sınırlı yetkili hesap (PoLP) yetki yükseltmeyi engeller; sistem şifrelense bile WORM kilitli değişmez yedekten 15 dakikada geri dönülür.
2. **Resmî Kalite Kabul Denetimi:**  
   Her laboratuvar ve üretim ortamı; etik RoE, varlık envanteri, NIST CSF 2.0'ın 6 işlevi ve CRAAP standartları üzerinden matematiksel olarak denetlenir. 80 puanın altındaki sistemler canlıya alınmaz.
3. **Kriptografik Kanıt Zinciri:**  
   Laboratuvarın kabul raporu ve konfigürasyonları SHA-256 ile özetlenerek mühürlenir. Yapılan her test denetlenebilir ve geriye dönük doğrulanabilir kılınır.

---

## 🛠️ 4. Hocayla Birlikte Canlı Laboratuvar

Aşama 1'in büyük finalinde, geliştirdiğimiz `stage1_security_auditor.py` motoru ile laboratuvar projelerimizin kalite kabul denetimini icra edeceğiz.

### Adım 1: Tüm Laboratuvar Projelerinin Toplu Kabul Denetimi
Terminalimizde şu komutu çalıştırarak laboratuvar dosyalarımızı denetliyoruz:

```bash
python portfolio/hafta_02/gun_014/uygulama/stage1_security_auditor.py --dosya portfolio/hafta_02/gun_014/ornek_veri/asama_01_laboratuvar_dosyasi.json --tumunu-denetle
```

**Beklenen Ekran Çıktısı:**
```text
[*] Tüm Aşama 1 Laboratuvar Projeleri Denetleniyor...
    - Proje: LAB-SEC-GOLDEN-01 -> Puan: 100.0 | Durum: ASAMA_1_KABUL_PASS | Kabul: True
    - Proje: LAB-SEC-DEFECTIVE-99 -> Puan: 0.0 | Durum: REDDEDILDI_TEHLIKELI | Kabul: False
```

### Adım 2: Altın Kabul Laboratuvarının (LAB-SEC-GOLDEN-01) Derinlemesine İncelenmesi
```bash
python portfolio/hafta_02/gun_014/uygulama/stage1_security_auditor.py --dosya portfolio/hafta_02/gun_014/ornek_veri/asama_01_laboratuvar_dosyasi.json --proje-id LAB-SEC-GOLDEN-01 --denetle
```

**Beklenen Çıktı Analizi:**
- Denetim Skoru: **100.0 / 100.0 (ASAMA_1_KABUL_PASS)**
- Etik RoE: Yazılı onay tam, hedef `192.168.100.0/24`, dış temas 0.
- Varlık Envanteri: 4 kritik varlık kayıtlı ve sahipleri atanmış.
- NIST CSF 2.0: 6 Fonksiyonun tamamı (Govern, Identify, Protect, Detect, Respond, Recover) eksiksiz.
- Kaynak Güvenilirliği: CRAAP skoru 95.0, resmî NVD ve üretici bültenleri kullanılmış.
- Kriptografik Sertifika: Deterministik SHA-256 özeti üretildi.

### Adım 3: Kusurlu Laboratuvarın (LAB-SEC-DEFECTIVE-99) Hatalarının Analizi
```bash
python portfolio/hafta_02/gun_014/uygulama/stage1_security_auditor.py --dosya portfolio/hafta_02/gun_014/ornek_veri/asama_01_laboratuvar_dosyasi.json --proje-id LAB-SEC-DEFECTIVE-99 --denetle
```

**Saptanan Ölümcül Bulgular:**
- `CRIT-01-ETIK-ROE-IHLALI`: Yazılı izin yok, hedef `0.0.0.0/0` (tüm internet), üretim sistemleriyle etkileşim var (-40 puan)!
- `WARN-02-EKSIK-VARLIK-ENVANTERI`: Varlık sayısı 0, sahiplik yok (-15 puan)!
- `WARN-03-NIST-CSF-EKSIK-ISLEVLER`: 6 temel işlevin tamamı eksik (-40 puan)!
- `WARN-05-DOGRULANMAMIS-KAYNAK-KULLANIMI`: CRAAP skoru 20.0 (-10 puan)!
- Sonuç: **0.0 / 100.0 (REDDEDILDI_TEHLIKELI)**.

---

## ⚠️ 5. Hocanın "Ölümcül Hatalar" Notu

1. **"Biz Güvenlik Duvarı Aldık, Güvendeyiz" Demek:**  
   Siber güvenlikte tek bir önleme güvenmek intihardır. Güvenlik duvarı yalnızca bir kapıdır; içeride kimlik yönetimi, log izleme ve değişmez yedek yoksa kapıyı aşan saldırgan tüm evi yakar.
2. **Yazılı İzin (RoE) Olmadan Test Başlatmak:**  
   "Ben sadece test ediyordum, kötü niyetim yoktu" cümlesi Türk Ceza Kanunu Madde 243 (Bilişim Sistemine Hukuka Aykırı Müdahale) karşısında hiçbir hukuki geçerliliğe sahip değildir. İzin yoksa yapılan her eylem suçtur.
3. **Kurtarma ve Geri Dönüş Tatbikatı Yapmamak:**  
   Geri dönüşü test edilmemiş bir laboratuvarda zararlı yazılım çalıştırmak, yangın söndürme tüpü olmayan bir odada ateşle oynamaktır.
4. **Kaynak Doğrulamadan Kod Çalıştırmak:**  
   İnternetten bulunan istismar veya test kodlarını sandbox dışına çıkarmak, bizzat saldırganın truva atı haline gelmektir.

---

## 🎯 6. Günün Pratik Görevi + Çözüm Yürüyüşü

### Pratik Görev Tanımı:
Aşama 1 başlangıç laboratuvarının amaç, kapsam, varlık ve geri dönüş belgelerini tek bir kanıt zincirine bağlamak; etik sınırlar ve NIST CSF 2.0'ın altı işlevi (Govern, Identify, Protect, Detect, Respond, Recover) için uygulamalı kontrol listesi üretmek; "Bir güvenlik önlemini tek başına eksiksiz savunma sanmak" hatasını olumsuz test senaryosuyla denetlemek ve 100/100 tam kabul raporu oluşturmak.

### Adım Adım Çözüm Yürüyüşü:
1. **Girdi Dosyasının İncelenmesi:** `ornek_veri/asama_01_laboratuvar_dosyasi.json` ve `csf_2_0_denetim_rubrigi.json` yüklendi.
2. **5 Sütunlu Denetim Modeli:**
   - Sütun 1: RoE yazılı izni ve IP sınırları (20 puan).
   - Sütun 2: Varlık envanteri ve kritiklik etiketleri (15 puan).
   - Sütun 3: NIST CSF 2.0 6 fonksiyonu (40 puan).
   - Sütun 4: Sanallaştırma izolasyonu ve WORM geri dönüş (15 puan).
   - Sütun 5: CRAAP kaynak güvenilirliği (10 puan).
3. **Olumsuz Test ve Sınır Kontrolü:** `LAB-TEST-SINGLE-MEASURE` senaryosunda yalnızca Protect aktif edilip Recover/Detect kapatıldığında `CRIT-04-TEK-ONLEME-GUVENME-YANILGISI` felaket cezası başarıyla tetiklendi.
4. **Kriptografik Sertifika:** Altın proje için SHA-256 kabul özeti hesaplandı.
5. **Birim Test Kapsamı:** 14 test ile pozitif kabul ve negatif ret durumları 0.006 saniyede %100 doğrulandı.

---

## ❓ 7. Hocanın Soru Odası

### Soru 1 (G014-SC1): Aşama 1 kabul: güvenlik temelleri: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Net ve Doğrudan Yanıt
Aşama 1 kabul mekanizması; başlangıç laboratuvarının amaç, etik kapsam (RoE), varlık envanteri, NIST CSF 2.0 altı işlevi ve geri dönüş belgelerini birbirinden kopuk bağımsız adımlar yerine tek ve kırılmaz bir kanıt zincirine (chain of evidence) bağlama sürecidir. Güvenlik önemi; laboratuvarın kontrolsüz bir tehdit kaynağına dönüşmesini engellemek ve siber güvenlik eğitiminin sağlam, doğrulanmış ve yasal bir temel üzerine oturmasını teminat altına almaktır.

#### 2. Derin Teknik Gerekçe ve Mantık
Bir siber güvenlik laboratuvarı; içinde gerçek zaafiyetlerin barındırıldığı, zararlı yazılımların incelendiği ve sızma testlerinin simüle edildiği potansiyel olarak tehlikeli bir sahadır. Eğer bu laboratuvarın amacı net tanımlanmamışsa, yazılı etik kapsamı (RoE) yoksa, varlıkları envanterlenmemişse ve bir felaket anında sistemi dakikalar içinde temiz duruma döndürecek bağımsız WORM geri dönüş (rollback) mekanizması bulunmuyorsa; laboratuvardaki bir zararlı yazılım veya saldırı trafiği kurumsal ağa ya da internete sızabilir (spillover / VM escape). Bu belgelerin tek bir kanıt zincirine bağlanması; hem teknik izolasyonu (VLAN, conntrack, hypervisor) hem de idari yönetişimi (NIST CSF 2.0 Govern/Identify) zorunlu kılar.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En büyük hata, "Laboratuvarı kurdum, sanal makine açılıyor, demek ki hazırım" yanılgısıdır. Sanal makinenin açılması yalnızca teknik bir çalıştırmadır; onun izole olması, loglarının tutulması, varlıklarının etiketlenmesi ve geri dönüşünün doğrulanması olmadan o laboratuvar bir eğitim ortamı değil, potansiyel bir saatli bombadır.

#### 4. Resmî Standart ve Kaynak
- **NIST CSF 2.0 (2024):** *Govern (GV) and Identify (ID) Functions*.
- **NIST SP 800-115:** *Technical Guide to Information Security Testing and Assessment* (Bölüm 2: Fundamental Security Principles & Testing Authorization).

---

### Soru 2 (G014-SC2): Aşama 1 kabul: güvenlik temelleri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Net ve Doğrudan Yanıt
Laboratuvarın girdisi; Aşama 1 projelerinin amaç, RoE, varlık ve CSF kriterlerini içeren laboratuvar dosyası (`asama_01_laboratuvar_dosyasi.json`) ve denetim rubriğidir (`csf_2_0_denetim_rubrigi.json`). İşlemi; 5 temel sütunun (RoE, Varlık, NIST CSF 6 işlevi, İzolasyon, CRAAP) denetlenmesi ve kriptografik sertifikalandırılmasıdır. Beklenen sonucu; tüm standartları karşılayan altın projenin 100/100 tam puanla `ASAMA_1_KABUL_PASS` almasıdır. Negatif kontrolü ise; etik izin eksikliğinde durdurma (`CRIT-01`), eksik varlıkta ceza (`WARN-02`) ve yalnızca tek bir önleme güvenildiğinde felaket cezası (`CRIT-04`) verilerek projenin reddedilmesidir.

#### 2. Derin Teknik Gerekçe ve Mantık
Laboratuvar motoru (`stage1_security_auditor.py`), girdileri deterministik bir süzgeçten geçirir. Pozitif akışta `LAB-SEC-GOLDEN-01` projesi tüm NIST CSF 2.0 işlevlerini (Govern'den Recover'a kadar) sağladığı için kabul edilir. Negatif kontrollerde ise:
1. `LAB-SEC-DEFECTIVE-99` projesinde hedef IP `0.0.0.0/0` ve yazılı izin False olduğundan doğrudan etik ihlal cezası kesilir.
2. `LAB-TEST-SINGLE-MEASURE` projesinde yalnızca güvenlik duvarı (Protect) açıkken kurtarma (Recover) ve loglama (Detect) kapalı olduğu için "Tek Önleme Güvenme Yanılgısı" yakalanır.
3. Kriptografik SHA-256 sertifikası ile kabul kararı tahrifata karşı mühürlenir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
Laboratuvarda negatif kontrolü test etmeden "ben her şeyi doğru yaptım" demek, bilimsel güvenlik denetimi felsefesine aykırıdır. Negatif kontrol; sistemin kusurlu, eksik veya tehlikeli bir yapılandırma karşısında doğru tepkiyi verip vermediğini (reddetme refleksini) kanıtlayan mihenk taşıdır.

#### 4. Resmî Standart ve Kaynak
- **NIST NICE Framework:** *Work Role: Systems Security Integration (OM-NET-001) & Cyber Defense Analyst (PR-CDA-001)*.
- **CIS Critical Security Controls v8:** *Control 1: Inventory and Control of Enterprise Assets & Control 11: Data Recovery*.

---

### Soru 3 (G014-SC3): 'Aşama 1 kabul: güvenlik temelleri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Net ve Doğrudan Yanıt
Risk; kurumun veya analistin güvenlik önlemlerinden yalnızca birine (örneğin sadece güvenlik duvarına veya sadece antivirüse) körlemesine güvenmesi, varlık envanterini ihmal etmesi ve geri dönüş planı yapmamasıyla oluşur. Tespit; NIST CSF 2.0 denetim matrisinde eksik fonksiyonların (özellikle Detect ve Recover) saptanması, yetkisiz IP taraması alarmları ve eksik varlık kayıtlarıyla yapılır. Önleme ise; bütüncül derinlemesine savunma (Defense-in-Depth), yazılı RoE kapsam sözleşmesi, 3-2-1-1-0 değişmez yedekleme ve Aşama 1 kabul kalite kontrol listesiyle sağlanır.

#### 2. Derin Teknik Gerekçe ve Mantık
- **Risk Mekanizması:** Savunmacı tek bir güvenlik kalkanını (örneğin çevre güvenlik duvarı) eksiksiz savunma sandığında, saldırgan o kalkanı basit bir oltalama (phishing) veya zafiyetli bir dış kütüphane ile aştığı anda içeride hiçbir engelle karşılaşmaz. Varlık envanteri yoksa saldırganın hangi sunucuda olduğu anlaşılamaz; tespit (detect) mekanizması yoksa saldırgan aylarca fark edilmez; geri dönüş (recover) planı yoksa fidye yazılımı karşısında tüm veriler kaybedilir.
- **Tespit Mekanizması:**
  - *Risk ve Uyumluluk Matrisi Denetimi:* NIST CSF 2.0 altı işlevinin her bir alt kategorisinin denetlenmesi; boş veya "uygulanmadı" işaretli kategorilerin risk olarak raporlanması.
  - *Olay Günlüğü Taraması:* Yetkisiz dış IP erişimleri, port taramaları ve vssadmin komutlarının izlenmesi.
- **Önleme Kontrolleri:**
  - *Kanıt Zinciri Şartı:* Başlangıç laboratuvarında amaç belgesi, yazılı RoE, varlık envanteri ve geri dönüş planı eksiksiz olmadan hiçbir saldırı simülasyonuna izin verilmemesi.
  - *Derinlemesine Savunma (Defense-in-Depth):* Ağ izolasyonu, mikro-segmentasyon, en az yetki prensibi (PoLP) ve WORM yedeklemenin birlikte işletilmesi.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En büyük yanılgı; "Siber güvenlik bir ürün satın almaktır" düşüncesidir. Güvenlik bir ürün değil, bir süreç ve kültürdür. Dünyanın en pahalı güvenlik yazılımını alsanız dahi, CSF 2.0'ın Identify ve Recover işlevlerini yerine getirmiyorsanız sisteminiz her zaman saldırıya açıktır.

#### 4. Resmî Standart ve Kaynak
- **ISO/IEC 27001:2022:** *Clause 6.1: Actions to address risks and opportunities & Annex A.8: Technological Controls*.
- **MITRE ATT&CK Framework:** *Mitigation M1047: Audit & M1053: Data Backup*.
