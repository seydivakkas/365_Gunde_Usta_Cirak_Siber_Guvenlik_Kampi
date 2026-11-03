# GÜN 019: SORU-CEVAP VE SENARYO ANALİZLERİ
# Windows Dosya Sistemi ve NTFS Güvenlik Değerlendirmesi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu dosya ve içerikler yalnızca görüntüleme ve eğitim amaçlıdır. Ticari/gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

---

## SORU 1: [G019-SC1] Temel Mekanizma ve Güvenlik Önemi

### Soru ve Bağlam
*Windows dosya sistemi ve NTFS: Temel mekanizmayı ve güvenlik önemini açıkla.*  
NTFS dosya sisteminde erişim denetim listeleri (ACL/DACL) dosya erişimini nasıl düzenler? Dosya uzantısı neden tek başına bir içerik veya güvenlik özelliği değildir?

### Teknik Açıklama ve Mekanizma
1. **NTFS ACL Mekanizması:** NTFS üzerindeki her dosya ve dizin, Güvenlik Tanımlayıcısı (Security Descriptor) içerisinde bir **DACL (Discretionary Access Control List)** barındırır. DACL, Erişim Denetim Girdilerinden (ACE) oluşur. İşletim sistemi bir kullanıcı dosyaya erişmek istediğinde sırasıyla:
   - **Açıkça Reddet (Explicit Deny):** Kullanıcı veya grubu için "Deny" kuralı varsa derhal erişimi engeller.
   - **Açıkça İzin Ver (Explicit Allow):** Dosyaya doğrudan verilmiş izinleri doğrular.
   - **Miras Alınan İzinler (Inherited):** Üst dizinden devralınan kuralları değerlendirir.
   - Eşleşme yoksa varsayılan olarak reddeder (**Implicit Deny**).
2. **Dosya Uzantısı Yanılgısı:** Dosya uzantısı (örneğin `.pdf`, `.docx`, `.exe`), Windows kabuğu (Explorer) için dosyanın hangi varsayılan programla açılacağını bildiren yüzeysel bir metin dizesinden ibarettir. Dosya sisteminin veya işletim sistemi çekirdeğinin güvenlik katmanında hiçbir bağlayıcılığı yoktur.
   - Gerçek dosya türü, dosyanın ilk baytları olan **Sihirli Baytlar (Magic Bytes / File Signatures)** ile belirlenir. Örneğin `MZ` (`4D 5A`) baytları Windows PE (.exe) çalıştırılabilir dosyasını, `%PDF` (`25 50 44 46`) ise Adobe PDF belgesini temsil eder.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Saldırı Senaryosu (Extension Spoofing ve Oltalama):** Saldırgan, arka planda çalışan zararlı bir PE çalıştırılabilir dosyasını (`.exe`) hazırlar, ancak adını `2026_Mali_Rapor.pdf` yapar. E-posta güvenlik ağ geçidi yalnızca dosya uzantısını kontrol ediyorsa bu zararlıyı "zararsız PDF belgesi" sanarak içeri alır. Kullanıcı dosyayı açtığında veya güvenlik açığı barındıran bir ayrıştırıcıya iletildiğinde sistem ele geçirilir.
- **Savunma Senaryosu:** Kurumsal güvenlik kontrolleri (EDR, E-posta Ağ Geçitleri ve `NtfsSecurityAndAclAnalyzer`), dosya uzantısına değil dosyanın sihirli baytlarına bakar. Dosya `.pdf` uzantılı olmasına rağmen `4D 5A` (PE) imzası taşıyorsa derhal karantinaya alınır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `NtfsSecurityAndAclAnalyzer` sınıfının `inspect_magic_bytes_and_extension()` metodu dosya uzantısı ile dosya başlığını çapraz denetime tabi tutar.
- **Doğrulama:** `test_06_magic_bytes_spoofing_pe_executable_as_pdf` birim testi ile sahte PDF kılığına girmiş PE dosyası anında `KRITIK_MASKELEME_PE_SPOOFING` olarak tespit edilmiştir.
- **Çıkarılan Ders:** Bir dosyanın kimliğini adı değil, baytları belirler. Güvenlik politikaları asla uzantı kontrolü ile sınırlandırılamaz.

---

## SORU 2: [G019-SC2] Bağımsız Laboratuvar ve Test Mimarisi

### Soru ve Bağlam
*Windows dosya sistemi ve NTFS: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?*  
Kendi test klasöründe izinleri görüntüleyen, izin sertleştirmesi uygulayan ve önce/sonra farkını (Diff) kaydeden bağımsız laboratuvar kurgusu nasıl oluşturulur?

### Teknik Açıklama ve Mekanizma
Laboratuvarımız `ntfs_security_and_acl_analyzer.py` modülü üzerinden 4 aşamada yürütülür:
1. **Kontrollü Girdi (Input):**
   - Canlı sistem için yerel işletim sistemi dizini (`C:\Users\...\Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi`).
   - ACL sertleştirme deneyi için `ornek_veri/ntfs_file_samples.json` içerisindeki `klasor_acl_once_sonra_senaryosu` veri seti:
     - Önceki Durum: `Everyone:FullControl:Allow`, `BUILTIN\Users:Write:Allow` (Gevşek, zafiyetli durum).
     - Sonraki Durum: `BUILTIN\Administrators:FullControl:Allow`, `NT AUTHORITY\SYSTEM:FullControl:Allow`, `Everyone:Write:Deny` (Sertleştirilmiş durum).
2. **Laboratuvar İşlemi (Process):**
   - `get_live_directory_acls()` ile canlı dizin izinleri `icacls` üzerinden sorgulanır.
   - `compare_acl_diff()` fonksiyonu ile önceki ve sonraki izin kümeleri kıyaslanır, kaldırılan ve eklenen kurallar hesaplanır.
   - İyileştirme notları (Everyone FullControl iptali, Explicit Deny kuralı eklenmesi) üretilir.
3. **Beklenen Sonuç (Expected Output):**
   - Canlı sistemde icacls çıktısının başarıyla yakalanması (SYSTEM, Administrators ve geçerli kullanıcı izinleri).
   - Fark analizinde `guvenlik_iyilestirmesi_var_mi = True` sonucunun üretilmesi ve Everyone tam yetkisinin kaldırıldığının kanıtlanması.
4. **Negatif Kontrol (Negative Control):**
   - Bir dosyanın DACL'inde `Everyone:FullControl:Allow` bırakıldığı durumda analizörün `audit_ntfs_file_security()` ile bu durumu `KRİTİK` güvenlik açığı (`RULE-NTFS-003`) olarak bayraklaması.
   - Dosya içine gizlenmiş tehlikeli bir Alternatif Veri Akışı (ADS - örn: `hidden_payload.ps1`) tespit edildiğinde `RULE-NTFS-002` kural ihlalinin tetiklenmesi.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Zayıf ACL İstismarı:** `Everyone` grubuna tam denetim verilmiş bir klasörde içerideki herhangi bir kullanıcı veya zararlı yazılım, şirketin tüm yedeklerini tek bir komutla silebilir veya üzerine fidye notu yazabilir.
- **Savunma:** İzin fark analizimizle doğrulandığı gibi, `Everyone` yetkisi kaldırılmış ve açıkça reddetme (`Explicit Deny`) uygulanarak en az ayrıcalık güvenceye alınmıştır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `compare_acl_diff` metodu izin değişikliklerini matematiksel küme farkı olarak hesaplar.
- **Doğrulama:** `test_10_acl_once_sonra_diff_everyone_kaldirilmasi`, `test_11_acl_once_sonra_diff_explicit_deny_eklenmesi` ve `test_12_dacl_everyone_full_control_kritik_risk_tespiti` testleri 14/14 başarıyla doğrulanmıştır.
- **Çıkarılan Ders:** Erişim denetim listelerindeki değişiklikler rastgele yapılmamalı; her izin sıkılaştırması öncesi ve sonrasıyla adli olarak belgelenmelidir.

---

## SORU 3: [G019-SC3] Risk Oluşumu, Tespit ve Savunma Kontrolleri

### Soru ve Bağlam
*'Windows dosya sistemi ve NTFS' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?*  
NTFS dosya yapısında, Alternatif Veri Akışlarında (ADS) ve izin mirasında kurumsal riskler nasıl oluşur, güvenlik operasyonlarında nasıl tespit edilir ve CIS/NIST kontrolleriyle nasıl engellenir?

### Teknik Açıklama ve Mekanizma
1. **Risk Oluşumu:**
   - **Gevşek Miras ve Yetki Yayılması:** Üst dizinlerdeki izinlerin kontrolsüzce alt klasörlere miras bırakılması veya Everyone grubuna aşırı yetki tanınması.
   - **ADS ile Kalıcılık ve Gizleme (T1564.004):** Saldırganların meşru metin dosyalarının veya sistem dosyalarının arkasına `dosya.txt:zararli.exe` şeklinde ikincil akışlar ekleyerek antivirüs taramalarından kaçması.
   - **Zaman Damgası Sahteciliği (Timestomping):** Saldırganların `$STANDARD_INFORMATION` niteliğindeki $MACE zaman damgalarını değiştirerek adli bilişim incelemelerini yanıltması.
2. **Tespit Mekanizmaları:**
   - **icacls ve PowerShell ACL Taramaları:** `Get-Acl` ile sistemdeki zayıf DACL girdilerinin periyodik taranması.
   - **ADS Taraması:** `dir /r` komutu veya `Get-Item * -Stream *` ile gizli akışların listelenmesi.
   - **MFT Adli Analizi:** `$MFT` dosyasının adli bilişim araçlarıyla (FTK Imager, MFTECmd) taranarak `$STANDARD_INFORMATION` ile `$FILE_NAME` zaman damgaları arasındaki tutarsızlıkların (Timestomping tespiti) ortaya çıkarılması.
3. **Savunma ve Önleme Kontrolleri:**
   - **CIS Benchmark (NTFS Hardening):** Kök sürücülerde ve kurumsal paylaşımlarda Everyone grubunun FullControl/Write izinlerinden arındırılması.
   - **SACL Denetimi:** Windows Olay Günlüğü `Event ID 4663` (Nesneye erişim girişimi) ve `Event ID 4670` (İzinlerin değiştirilmesi) günlüklerinin SIEM üzerinde korelasyonu.
   - **AppLocker ve WDAC:** ADS üzerinden kod yürütülmesini engellemek için yürütülebilir kuralların sıkılaştırılması.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Senaryo:** Saldırgan sunucuya sızdıktan sonra `C:\Windows\Temp\not.txt:svchost.exe` adıyla bir ADS akışı oluşturur ve bir zamanlanmış görevle bu akışı çalıştırarak kalıcılık (persistence) sağlar. Standart antivirüs yalnızca `not.txt`'yi tarar ve temiz rapor verir.
- **Önleme:** Güvenlik analizörümüzün `RULE-NTFS-002` kuralı devrede olduğunda, dosyadaki tüm ikincil akışlar taranarak gizli yürütülebilir kod tespit edilir ve saldırganın gizlenme girişimi boşa çıkarılır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `audit_ntfs_file_security` ve `inspect_alternate_data_streams` metotları tüm bu dosya sistemi tehditlerini tek bir çatıda raporlar.
- **Doğrulama:** `test_09_ads_gizli_powershell_tehlikeli_akis_tespiti` ile senaryo doğrulanmıştır.
- **Çıkarılan Ders:** NTFS güçlü bir dosya sistemidir; ancak içindeki ADS ve zengin ACL yetenekleri bilinçli yapılandırılmadığında savunucudan çok saldırganın işine yarayan bir gizlenme kalesine dönüşür.
