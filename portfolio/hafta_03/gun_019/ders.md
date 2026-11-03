# GÜN 019: DERS NOTLARI
# Windows Dosya Sistemi ve NTFS: Ana Dosya Tablosu (MFT), ACL Hiyerarşisi, Alternatif Veri Akışları (ADS) ve Sihirli Baytlar

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim  
> amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez,  
> satılamaz veya tersine mühendislik yapılamaz.

---

## BÖLÜM 1: Giriş ve Kavramsal Çerçeve

Kurumsal işletim sistemlerinde dosya sistemi yalnızca verilerin diske yazıldığı bir depolama formatı değil, doğrudan **erişim denetiminin (Access Control)** ve **adli kanıt bütünlüğünün (Forensic Integrity)** omurgasıdır. DOS ve erken Windows dönemlerindeki FAT/FAT32 dosya sistemlerinde dosya seviyesinde güvenlik izinleri (izin verme, engelleme, kullanıcı bazlı kısıtlama) bulunmuyordu; diske fiziksel erişimi olan herkes her dosyayı okuyabiliyordu.

Microsoft, kurumsal gereksinimleri karşılamak amacıyla 1993 yılında Windows NT ile birlikte **NTFS (New Technology File System)** mimarisini geliştirdi. NTFS'i modern kurumsal güvenlik standardı yapan temel unsurlar şunlardır:
1. **İnce Taneli Erişim Denetim Listeleri (DACL - Discretionary Access Control Lists):** Her dosya ve klasör için kullanıcı ve grup bazlı mikro izinler.
2. **Güvenlik Olayı Denetimi (SACL - System Access Control Lists):** Dosyalara kimin, ne zaman eriştiğini veya erişmeye çalışıp başarısız olduğunu Windows Güvenlik Günlüğü'ne kaydeden mekanizma.
3. **Alternatif Veri Akışları (ADS - Alternate Data Streams):** Bir dosya kimliği altında birden fazla veri akışını barındırabilme yeteneği.
4. **İşlem Günlüğü (Journaling - `$LogFile`):** Güç kesintisi veya çökme anında dosya sistemi metaverilerinin tutarlılığını garanti eden atomik işlem kaydı.

---

## BÖLÜM 2: NTFS Mimarisi ve Ana Dosya Tablosu (MFT)

### 2.1. Ana Dosya Tablosu ($MFT - Master File Table)

NTFS birimindeki her şey—dosyalar, klasörler, metaveriler ve hatta $MFT tablosunun kendisi—birer "dosyadır". Bir NTFS biriminin kalbinde **$MFT** yer alır:
- MFT, sabit boyutlu (genellikle **1024 bayt**) kayıtlardan oluşan devasa bir yapılandırılmış dizidir.
- Diskteki her dosya ve dizin MFT içerisinde en az bir kayda (Record) sahiptir.
- Dosya boyutu çok küçükse (örneğin ~700 bayttan küçük), dosyanın gerçek içeriği doğrudan MFT kaydının içine yazılır. Buna **Yerleşik Veri (Resident Data)** denir. Dosya büyüdüğünde harici kümelere (clusters) taşınır (**Non-Resident Data**).

### 2.2. MFT Nitelikleri (Attributes)

1024 baytlık bir MFT kaydı, standartlaştırılmış nitelik bloklarından (Attributes) oluşur:
- **`$STANDARD_INFORMATION` (Tip 0x10):** Dosyanın temel zaman damgalarını (**$MACE**: Modification, Access, Creation, Entry Modified) ve salt-okunur, gizli gibi temel bayrakları barındırır.
- **`$FILE_NAME` (Tip 0x30):** Dosyanın adını, ebeveyn dizin göstericisini ve dosyanın ikinci bir zaman damgası kopyasını saklar (Adli bilişimde $STANDARD_INFORMATION üzerindeki Timestomping sahtecilikleri bu nitelikle kıyaslanarak çözülür).
- **`$SECURITY_DESCRIPTOR` (Tip 0x50):** Dosyanın sahibini (Owner SID) ve erişim izinlerini (DACL/SACL) tutar.
- **`$DATA` (Tip 0x80):** Dosyanın asıl içeriğini barındıran veri akışıdır.

---

## BÖLÜM 3: Erişim Denetimi: DACL, SACL ve Değerlendirme Algoritması

### 3.1. Güvenlik Tanımlayıcısı (Security Descriptor - SD) Anatomisi

Her NTFS nesnesi bir Güvenlik Tanımlayıcısına sahiptir:
- **Owner SID:** Dosyanın yasal sahibi (örn: `S-1-5-21-...-1001`). Sahip, dosyaya erişim hakkı olmasa dahi DACL izinlerini değiştirme hakkına sahiptir.
- **DACL (Discretionary Access Control List):** Kimin dosyayı okuyabileceğini, yazabileceğini veya sileceğini belirleyen Erişim Denetim Girdileri (**ACE - Access Control Entry**) listesidir.
- **SACL (System Access Control List):** Hangi kullanıcıların erişim denemelerinin denetim günlüğü (`Event ID 4663`) üreteceğini belirler.

### 3.2. Windows DACL Değerlendirme Algoritması (Altın Kural)

Bir kullanıcı bir dosyayı açmak istediğinde Windows Güvenlik Referans İzleyicisi (SRM), kullanıcının kimlik belirtecindeki (Token) SID'leri dosyanın DACL girdileriyle **katı bir hiyerarşik sırada** karşılaştırır:
1. **Açıkça Reddet (Explicit Deny):** Eğer kullanıcının veya üyesi olduğu gruplardan birinin karşısında "Deny" yazıyorsa, arama **DERHAL DURUR** ve erişim kesinlikle reddedilir! (Deny, her zaman Allow'u ezer).
2. **Açıkça İzin Ver (Explicit Allow):** Dosyaya doğrudan verilmiş "Allow" izinleri kontrol edilir. Talep edilen tüm izinler karşılandıysa erişim onaylanır.
3. **Miras Alınan Reddet (Inherited Deny):** Üst klasörden miras kalmış reddetme kuralları değerlendirilir.
4. **Miras Alınan İzin Ver (Inherited Allow):** Üst klasörden miras kalmış izin kuralları değerlendirilir.
5. **Örtük Reddetme (Implicit Deny):** Eğer DACL listesi boş değilse ancak kullanıcının SID'si hiçbir kuralla eşleşmediyse erişim varsayılan olarak reddedilir.
*(İstisna: DACL tamamen NULL ise herkes tam yetkilidir; bu durum büyük bir güvenlik açığıdır).*

---

## BÖLÜM 4: Alternatif Veri Akışları (ADS - Alternate Data Streams)

NTFS'te bir dosya yalnızca tek bir veri kümesinden ibaret olmak zorunda değildir. Varsayılan olarak her dosya adsız bir `$DATA` akışına sahiptir:
`belge.txt` $\equiv$ `belge.txt::$DATA`

Ancak bir dosyaya iki nokta üst üste (`:`) sözdizimi kullanılarak ikincil veri akışları eklenebilir:
```powershell
# Dosya Gezgini'nde 0 bayt görünen bir metin dosyasına gizli yük ekleme:
echo "Toplantı Notu" > masum.txt
notepad masum.txt:gizli_akis.ps1
```

### 4.1. Güvenlik Etkileri ve Tehdit Modeli (MITRE ATT&CK T1564.004)
- **Zararlı Yazılım Saklama:** Saldırganlar yürütülebilir dosyaları (`.exe`, `.ps1`) ADS içine gizleyebilir. Standart `dir` komutu veya Windows Dosya Gezgini ADS akışlarını göstermez ve dosya boyutunu yalnızca birincil akış kadar raporlar.
- **Mark-of-the-Web (Zone.Identifier):** Windows, internetten indirilen tüm dosyaların arkasına otomatik olarak bir ADS ekler: `dosya.exe:Zone.Identifier`. Bu akışın içinde `ZoneId=3` (Internet Zone) yazar. Microsoft Office ve SmartScreen bu akışı okuyarak "Korumalı Görünüm" veya "Bu dosya internetten indirildi, çalıştırmak istiyor musunuz?" uyarısını tetikler.

ADS Tespiti:
- Komut satırında: `dir /r`
- PowerShell'de: `Get-Item dosya.txt -Stream *`

---

## BÖLÜM 5: Dosya Uzantısı Yanılgısı ve Sihirli Baytlar (Magic Bytes)

Siber güvenlikteki en ilkel ancak en sık düşülen hatalardan biri, **dosya uzantısına güvenmektir**:
- Windows kabuğunda bir dosyanın adının sonuna `.pdf` yazılması, o dosyanın bir PDF belgesi olduğunu **kanıtlamaz!** Uzantı, yalnızca işletim sisteminin o dosyayı çift tıklandığında hangi varsayılan uygulamayla (Adobe Acrobat mı, Chrome mu) açacağını belirleyen görsel bir ipucudur.
- Saldırganlar e-posta filtrelerini veya dosya yükleme portallarını atlatmak için Windows PE çalıştırılabilir ikili dosyasını (`.exe`) alıp adını `fatura.pdf` veya Unicode sağdan sola geçersiz kılma (RTLO) karakteriyle gizlerler.

### 5.1. Sihirli Baytlar (File Signatures / Magic Bytes)

Bir dosyanın gerçek türü, dosyanın en başındaki ilk birkaç bayt (File Header / Magic Bytes) okunarak doğrulanır:
- **Windows PE Executable (.EXE, .DLL, .SYS):** İlk iki bayt her zaman `0x4D 0x5A` (`MZ` - Mark Zbikowski'nin baş harfleri).
- **Adobe PDF:** İlk dört bayt `0x25 0x50 0x44 0x46` (`%PDF`).
- **PNG Resim:** İlk sekiz bayt `0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A` (`.PNG....`).
- **JPEG Resim:** İlk üç bayt `0xFF 0xD8 0xFF`.
- **ZIP Arşivi / Modern Office (.DOCX, .XLSX):** İlk dört bayt `0x50 0x4B 0x03 0x04` (`PK..`).

Eğer bir dosyanın uzantısı `.pdf` iken ilk baytları `4D 5A` ise, bu durum tartışmasız bir **Kritik Dosya Maskeleme (Extension Spoofing - MITRE T1036)** saldırı girişimidir!

---

## BÖLÜM 6: Uygulama Mimarisi, Testler ve Laboratuvar Doğrulaması

Bu modülde inşa ettiğimiz `portfolio/hafta_03/gun_019/uygulama/ntfs_security_and_acl_analyzer.py` analizörü şu yetenekleri icra eder:

1. `get_live_directory_acls(target_dir)`:
   - Yerel dizinin canlı NTFS izinlerini `icacls` aracıyla doğrudan Windows çekirdeğinden sorgular ve ham ACE kayıtlarını yapılandırır.
2. `compare_acl_diff(before_acls, after_acls)`:
   - G019-SC2 gereksinimini tam karşılayarak, bir test klasörünün önceki ve sonraki izin durumunu kıyaslar. `Everyone:FullControl` kaldırılmasını ve `Explicit Deny` eklenmesini başarıyla belgeler.
3. `inspect_magic_bytes_and_extension(filename, header_hex, baseline)`:
   - Dosya uzantısı ile dosya başlığındaki sihirli baytları karşılaştırır; PE maskelemelerini yakalar.
4. `inspect_alternate_data_streams(ads_list)`:
   - Meşru `Zone.Identifier` ile gizli `.ps1` / `.exe` yüklerini birbirinden ayırır.

Test paketimiz (`tests/test_ntfs_security_and_acl_analyzer.py`) 14 adet birim testinden oluşur ve **14/14 PASS (%100 Başarı)** ile doğrulanmıştır.

---

## BÖLÜM 7: Usta Çırak Nasihatleri ve Saha Tecrübeleri

1. **"Everyone" İznini Asla Kullanmayın:**
   - Kurumsal dosya paylaşımlarında veya yerel klasörlerde `Everyone` grubuna `Full Control` vermek, içerideki bir stajyerin veya ele geçirilen bir hizmet hesabının tüm kurumsal verileri fidye yazılımı gibi şifrelemesine veya silmesine davetiye çıkarmaktır. Her zaman `Authenticated Users` ve belirli güvenlik gruplarını kullanın.
2. **Web Yüklemelerinde MIME Type ve Uzantıya Güvenmeyin:**
   - Bir web uygulaması yazarken kullanıcının yüklediği profil fotoğrafının uzantısına veya HTTP `Content-Type` başlığına asla güvenmeyin. Dosyanın ilk 16 baytını doğrudan bellekten okuyun; `4D 5A` (PE) veya `<?php` görüyorsanız işlemi anında engelleyip güvenlik uyarısı verin.
3. **Zone.Identifier Akışını Denetimlerde İzleyin:**
   - Bir kullanıcı masaüstündeki bir dosyaya çift tıkladığında "Bilinmeyen Yayıncı" uyarısı çıkmıyorsa, saldırgan o dosyanın `Zone.Identifier` akışını silmiş (`Unblock-File`) demektir. Bu adli bilişimde bilinçli bir saldırı adımı olarak değerlendirilir.
