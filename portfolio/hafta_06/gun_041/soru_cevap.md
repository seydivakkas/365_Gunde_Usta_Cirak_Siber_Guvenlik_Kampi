# G041 — Mini Proje 5: Windows ve Linux Karşılaştırmalı Güvenlik Raporu Soru ve Çözümleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## [G041-SC1] İşletim Sistemi Güvenlik Duruşunun Nesnelleştirilmesi: Karşılaştırmalı Analiz Mekanizması

### Temel Kavram ve Güvenlik Mekanizması
Kurumsal ortamlarda güvenlik kararları kişisel tercihler veya önyargılarla alınamaz. Bir kurumda hem Microsoft Windows ekosistemi (etki alanı sunucuları, Exchange, SQL Server, kullanıcı iş istasyonları) hem de Linux dağıtımları (web sunucuları, konteyner kümeleme düğümleri, veritabanları) birlikte yaşar.

Farklı mimarilere sahip iki işletim sisteminin güvenlik seviyesini objektif olarak karşılaştırabilmenin tek yolu, **aynı güvenlik ölçütlerini (security metrics) ve fonksiyonel gereksinimleri** ortak bir standart altında toplamaktır. Bu yaklaşım, NIST Siber Güvenlik Çerçevesi (CSF) ve Center for Internet Security (CIS) Benchmarks ilkeleriyle tam uyumludur. Kimlik doğrulama, erişim kontrolü, çekirdek koruması, servis izolasyonu ve olay denetimi gibi ortak fonksiyonlar tanımlandığında, her iki sistemin de zayıf ve güçlü yanları matematiksel olarak ölçülebilir hale gelir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Windows ve Linux gibi mimari açıdan tamamen farklı iki işletim sistemini karşılaştırırken "İki işletim sistemi için aynı güvenlik ölçütlerini toplamak karşılaştırmayı nesnelleştirir" ilkesi neden esastır? Tek taraflı metrik kullanmanın (örneğin sadece antivirüs imza sayısı veya sadece açık port sayısı) yol açacağı yanılgılar nelerdir?

**Didaktik Çözüm:**  
- **Nesnellik İhtiyacı:** Eğer karşılaştırma sadece tek bir işletim sisteminin güçlü olduğu bir alana odaklanırsa analiz taraflı ve yanıltıcı olur. Örneğin, Windows'ta gelişmiş bir uç nokta koruyucusu olan Microsoft Defender ve AMSI entegrasyonu bulunurken; Linux'ta varsayılan bir masaüstü antivirüsü bulunmaz. Ancak Linux'ta `systemd` kum havuzlama (`ProtectSystem`, `PrivateTmp`) ve AppArmor zorunlu erişim denetimi ile servislerin saldırı yüzeyi zaten çekirdek düzeyinde kısıtlanmıştır.
- **Bütüncül 10 Gösterge Yaklaşımı:** Karşılaştırma motorumuz kimlik, yetkilendirme, ayrıcalık yönetimi, bellek koruması, kum havuzlama, ağ filtreleme, disk şifreleme, olay günlükleme, yama yönetimi ve EDR savunması olmak üzere 10 farklı boyutu eşit ağırlıkla değerlendirir. Böylece bir sistemin belirli bir alandaki açığı diğer alandaki gücüyle örtülmez; her bileşen net olarak görünür.

---

### Savunma ve Tespit Kılavuzu
- **Ölçümleme Metodolojisi:**
  1. **Fonksiyonel Eşleme:** Her iki platformda eşdeğer güvenlik kontrolleri tanımlanır (Örn: Windows GPO Parola İlkesi <-> Linux `/etc/security/pwquality.conf`).
  2. **Puanlama Normalizasyonu:** Her gösterge 0-10 arasında puanlanır; 10 göstergenin toplamı 100 üzerinden normalize edilir.
  3. **Risk Sınıflandırması:** Toplam puan üzerinden kurumsal duruş sınıflandırılır (>=85 Düşük Risk, 70-84 Orta Risk, 50-69 Yüksek Risk, <50 Kritik Risk).
- **Tespit ve Denetim Süreci:**
  - Güvenlik denetçileri periyodik olarak her iki işletim sistemi üzerinde çalışan otomatik betiklerle yapılandırma durumlarını çeker ve merkezi karşılaştırma matrisine girdi olarak besler.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bir yöneticiye 'Linux daha güvenli çünkü öyle hissediyorum' dersen bütçe alamazsın. Ama önüne 10 göstergeli matrisi koyup; 'Bakın efendim, Windows sunucumuzda VBS ve Defender sayesinde uç nokta puanımız 9/10, ancak servis izolasyonumuzda üçüncü taraf servisler SYSTEM ile çalıştığı için puanımız 7/10'dur; Linux tarafında ise systemd sandboxing 9/10 iken EDR tarafımız 7/10'dur' dersen, profesyonel bir güvenlik mühendisi gibi konuşmuş olursun."*

---

## [G041-SC2] 10 Göstergeli Sistem Güvenlik Envanteri Raporu ve Doğrulama Döngüsü

### Temel Kavram ve Güvenlik Mekanizması
Güvenlik denetim yazılımlarında **Doğrulama Döngüsü (Validation Loop)**; kontrollü girdi (controlled input), deterministik işlem (deterministic processing), gözlenebilir çıktı (observable output), olumlu/olumsuz testler (positive/negative testing) ve etik sınırlardan (ethical boundaries) meydana gelir.

Bu mini projede geliştirilen `windows_linux_security_comparator.py` motoru, bir güvenlik laboratuvarının ihtiyaç duyduğu tüm doğrulama standartlarını bünyesinde barındırır:
- **Girdi:** 10 göstergeli yapılandırılmış JSON matrisi.
- **İşlem:** Tip denetimi, aralık kontrolü, ağırlıklı puanlama, normalizasyon ve risk seviyesi sınıflandırması.
- **Çıktı:** Markdown karşılaştırma raporu, makine tarafından okunabilir JSON özeti ve konsol çıktıları.
- **Negatif Kontrol:** Hatalı tip, eksik gösterge, taşan puan ve bozuk JSON verilerinin yakalanıp zararsız şekilde raporlanması.

---

### Soru ve Didaktik Çözüm
**Soru:**  
10 göstergeli sistem güvenlik envanteri raporunu üreten bir denetim motoru için bağımsız laboratuvarın girdisi, işlemi, beklenen çıktısı ve negatif kontrol adımları nelerdir? Önceki günlerin dosyalarına bağımlılık neden yasaktır?

**Didaktik Çözüm:**  
- **Laboratuvar Girdisi:** `baseline_windows_linux_10_indicators.json` dosyası. İçerisinde Windows Server 2022 ve Ubuntu 22.04 LTS için 10 adet gösterge (IND-01'den IND-10'a kadar) yer alır.
- **Laboratuvar İşlemi:** Motor her bir göstergeyi `validate_indicator_node()` ile doğrular, puanları toplar (Windows için 81.0/100, Linux için 85.0/100), risk seviyelerini atar (Windows: MEDIUM, Linux: LOW) ve aradaki 4.0 puanlık farkı hesaplar.
- **Beklenen Çıktı:** `kanit/gercek/windows_linux_karsilastirma_raporu.txt` ve `kanit/gercek/komut_ve_cikis.txt` dosyaları.
- **Negatif Kontroller:** 14 adet unittest (`test_windows_linux_security_comparator.py`) ile test edilir:
  - 10 yerine 9 gösterge verilirse `SecurityIndicatorError` ("en az 10 gösterge").
  - Puan 15 verilirse `SecurityIndicatorError` ("0-10 aralığında olmalıdır").
  - Puan negatif (-4) verilirse hata yakalanır.
  - Puan string ("mukemmel") verilirse tip istisnası fırlatılır.
  - Puan boolean `True` verilirse reddedilir.
  - JSON sentaksı bozulursa sistem çökmeden `SecurityIndicatorError` üretilir.
- **Bağımsızlık İlkesi:** Müfredat kuralı gereği her günün çalışması tek başına çalışır. Önceki günün kod veya veri bağımlılığı zincirleme kırılmaları önlemek ve modülerliği korumak için kesinlikle yasaklanmıştır.

---

### Savunma ve Tespit Kılavuzu
- **Otomasyon ve Sürekli Entegrasyon (CI):**
  - Bu karşılaştırma motoru GitHub Actions veya GitLab CI süreçlerine eklenerek, altyapı kodunda (Terraform, Ansible) yapılan değişikliklerin güvenlik puanını düşürüp düşürmediği otomatik denetlenebilir (Security Regression Testing).
- **Eşik Değeri Kontrolü (Threshold Gates):**
  - Eğer herhangi bir işletim sisteminin toplam puanı %80'in altına düşerse CI/CD derleme süreci başarısız kılınarak (build break) üretime güvensiz sistem çıkışı engellenir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, negatif kontrol bir güvenlik mühendisinin dürüstlük testidir. Sadece çalışan kodu göstermek marifet değildir; yanlış veri geldiğinde, kullanıcı bir göstergeyi unuttuğunda ya da puan yerine harf yazdığında sistemin nasıl tepki verdiğidir önemli olan. Bugün yazdığımız 14 testin 8 tanesi negatif kontroldür. Bir kod hatalı veriyi zarifçe karşılayıp reddediyorsa, o kod üretime hazırdır."*

---

## [G041-SC3] Çoklu İşletim Sistemi Ortamlarında Risk Analizi: İzin, Servis ve Yapılandırma Sapmaları (Configuration Drift)

### Temel Kavram ve Güvenlik Mekanizması
Heterojen (Windows ve Linux bir arada) kurumsal ortamlarda güvenlik zafiyetlerinin ana kaynağı, zamanla sistemlerde meydana gelen **"Yapılandırma Sapmaları"dır (Configuration Drift)**. 

Bu bağlamdaki temel riskler şunlardır:
1. **Gereksiz İzinler:** Windows'ta Active Directory kullanıcılarının istemeden yerel `Administrators` grubuna eklenmesi veya Linux'ta `sudo` izinlerinin kısıtlanmaksızın (`ALL=(ALL) ALL`) dağıtılması.
2. **Yanlış ve Unutulmuş Servisler:** Hata ayıklama veya geçici bakım amacıyla açılan Telnet, şifresiz FTP, VNC servislerinin kapatılmaması; Windows'ta SMBv1 veya LLMNR gibi eski protokollerin aktif kalması.
3. **Yapılandırma Hataları:** Güvenlik duvarı kurallarının gevşetilmesi (`Allow All`), `sshd_config` içinde parola ile girişin açılması, UAC seviyesinin kapatılması.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Windows ve Linux karşılaştırmalı envanter raporlaması bağlamında "Gereksiz izin, yanlış servis ve yapılandırma" riski nasıl oluşur? Bu risk kullanıcı/izin/servis envanteri ve fark raporuyla nasıl tespit edilir? En az ayrıcalık ve geri alınabilir yapılandırma savunması nasıl işletilir?

**Didaktik Çözüm:**  
- **Riskin Oluşumu:** İşletim sistemleri canlı ortamda güncellendikçe, farklı ekipler (yazılım geliştiriciler, veri tabanı yöneticileri) işlerini kolaylaştırmak için izinleri genişletir veya varsayılan portları dışarı açar. Bu durum işletim sisteminin "Onaylı Güvenlik Taban Çizgisinden" (Golden Baseline) uzaklaşmasına neden olur.
- **Envanter ve Fark Raporu (Drift Report) ile Tespit:**
  - *Envanter Çıkarma:* Windows'ta PowerShell (`Get-Service`, `Get-LocalGroupMember Administrators`, `Get-NetFirewallRule`), Linux'ta kabuk araçları (`systemctl list-units`, `cat /etc/passwd`, `nft list ruleset`) ile mevcut durum anlık çekilir.
  - *Fark Analizi:* Elde edilen anlık durum, `baseline_windows_linux_10_indicators.json` referans matrisi ile otomatik karşılaştırılır. Yeni açılmış bir servis veya puanı düşüren bir izin tespit edildiğinde derhal fark raporu üretilir.
- **En Az Ayrıcalık ve Geri Alınabilir Yapılandırma:**
  - *En Az Ayrıcalık (Least Privilege):* Windows'ta LAPS v2 ve Just-In-Time (JIT) erişim; Linux'ta `sudo` komut kısıtlamaları ve AppArmor zorlaması uygulanır.
  - *Geri Alınabilirlik (Rollback):* Yapılandırma yönetimi Ansible, Puppet veya Desired State Configuration (DSC) gibi "Kod Olarak Altyapı" (IaC) araçlarıyla sürüm kontrolünde (Git) tutulur. Hatalı bir değişiklik anında `git revert` ile eski güvenli taban çizgisine geri döndürülür.

---

### Savunma ve Tespit Kılavuzu
- **Sıkılaştırma Eylem Planı:**
  - **Windows Tarafı:**
    - LLMNR ve NBT-NS'i devre dışı bırakın (GPO üzerinden).
    - LAPS v2'yi devreye alarak yerel yönetici parolalarını benzersiz kılın.
    - PowerShell Script Block Logging (Event ID 4104) ve Constrained Language Mode'u zorunlu tutun.
  - **Linux Tarafı:**
    - SSH üzerinde parola tabanlı kimlik doğrulamayı tamamen kapatın (`PasswordAuthentication no`).
    - systemd servis birimlerine `ProtectSystem=strict` ve `PrivateTmp=true` ekleyin.
    - auditd ile `/etc/shadow` ve `/etc/sudoers` üzerindeki değişiklikleri izleyin (`-w /etc/shadow -p wa -k identity_change`).

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bir sistem yöneticisi sana 'Ben bu ayarı geçici olarak yaptım, işim bitince düzelteceğim' dediğinde, bil ki o ayar sonsuza kadar orada kalacaktır! Siber güvenlikte 'geçici' diye bir şey yoktur. Eğer bir yetki açılacaksa, zaman sınırlı (örneğin 2 saatlik) olmalı ve süre bitince kendini otomatik imha etmelidir. Fark raporları ve otomatik denetim motorları bu yüzden hayati öneme sahiptir; insan unutur, ama denetim motoru unutmaz!"*
