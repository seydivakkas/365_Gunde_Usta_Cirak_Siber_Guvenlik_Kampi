# GÜN 014: Soru-Cevap Odası (Derinlemesine Teknik Analiz)
**Konu:** Aşama 1 Kabul: Güvenlik Temelleri ve Kalite Özeti (NIST CSF 2.0 & RoE)  
**Tarih:** 2026-10-27  

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

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
