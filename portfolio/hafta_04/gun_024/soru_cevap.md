# GÜN 024: Soru Bankası ve Çözüm Rehberi (RWX ve İzin Yönetimi)

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## SENARYO 1 (G024-SC1): Linux Dosya İzinleri RWX Temel Mekanizması ve Güvenlik Önemi

### 1. Soru Metni ve Açıklaması
**Soru:** Linux dosya izinleri rwx: Temel mekanizmayı ve güvenlik önemini açıkla. (Okuma, yazma ve çalıştırma izinleri kullanıcı, grup ve diğerleri için ayrı değerlendirilir.)

**Açıklama:** Linux işletim sisteminde İsteğe Bağlı Erişim Denetimi (Discretionary Access Control - DAC) modelinin temel yapı taşını oluşturan izin blokları, çok kullanıcılı ortamlarda sistem bütünlüğünü, veri gizliliğini ve süreç izolasyonunu sağlar. Bu soruda aktör ayrımı, sayısal/sembolik karşılıklar ve yetki aşımının neden olduğu güvenlik riskleri incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap
Linux dosya izinleri, her dosya ve dizinin inode meta verisinde saklanan 12 bitlik bir izin maskesine dayanır. Bu maske üç ana aktör kümesine (`User`, `Group`, `Other`) bölünmüştür ve her küme üç bağımsız izin biti içerir:

1. **Aktör Hiyerarşisi:**
   - **Kullanıcı / Sahip (User - `u`):** Dosyanın doğrudan sahibi olan kullanıcı hesabıdır. Dosyanın sahibi izinleri `chmod` ile serbestçe değiştirebilir.
   - **Grup (Group - `g`):** Dosyanın ait olduğu işletim sistemi grubudur. Bu gruptaki tüm yerel kullanıcılar grup izin kümesine tabidir.
   - **Diğerleri (Others / World - `o`):** Dosyanın sahibi olmayan ve ilgili gruba dahil bulunmayan sistemdeki tüm diğer yerel hesaplar (ve bu hesaplar altında çalışan arka plan servisleri).

2. **İzin Bitleri ve Sayısal Ağırlıkları:**
   - **Okuma (`r` - Read, Oktal: 4, İkili: `100`):** Dosyalar için içeriği okuma yetkisi; dizinler için dizin içindeki dosya adlarını listeleme (`ls`) yetkisidir.
   - **Yazma (`w` - Write, Oktal: 2, İkili: `010`):** Dosyalar için dosya içeriğini değiştirme, silme veya üzerine yazma yetkisi; dizinler için yeni dosya/klasör oluşturma ve var olan dosyaları silme yetkisidir.
   - **Çalıştırma (`x` - Execute, Oktal: 1, İkili: `001`):** Dosyalar için dosyanın bir program/betik olarak hafızaya yüklenip çalıştırılması; dizinler için dizin içerisine girme (`cd`) ve dizin altındaki bilinen dosyaların inode'larına erişebilme yetkisidir.

3. **Güvenlik Önemi:**
   - **Gizlilik (Confidentiality):** `/etc/shadow`, özel SSH anahtarları (`~/.ssh/id_rsa`) veya veritabanı bağlantı dize dosyaları diğerleri (`o`) için okuma hakkına sahip olduğunda, düşük yetkili bir kullanıcı sunucudaki tüm kritik verileri ifşa edebilir.
   - **Bütünlük (Integrity):** Sistem dosyalarına (`/etc/passwd`, `/etc/crontab`, `/bin/bash`) dünya çapında yazma (`o+w`) izni verilirse (CWE-732), saldırgan doğrudan sahte root kullanıcısı ekleyebilir veya zararlı cron işi tanımlayarak sistemi ele geçirebilir.
   - **Kullanılabilirlik (Availability):** Paylaşımlı dizinlerde (`/tmp`) izinlerin ve yapışkan bitin (sticky bit `1777`) doğru tanımlanmaması durumunda kötü niyetli kullanıcılar servislerin kilit dosyalarını silerek hizmet kesintisi yaratabilir.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Mülakatlarda sıkça şu tuzak soru sorulur: *"Bir kullanıcının bir dosyayı silebilmesi için o dosya üzerinde yazma (`w`) izni olması şart mıdır?"*  
**Cevap:** Kesinlikle HAYIR! Linux dosya sisteminde dosya silme operasyonu dosyanın kendisine değil, dosyanın yer aldığı **üst dizinin (parent directory)** meta verilerine yazma işlemidir. Bir kullanıcının dosya üzerinde hiçbir izni olmasa dahi (örn: `0000`), eğer dosyanın bulunduğu dizinde yazma (`w`) ve çalıştırma (`x`) hakkı varsa o dosyayı silebilir! Bu nedenle dizin izinleri en az dosya izinleri kadar kritiktir.

### 4. Gerçek Hayat / Sektör Senaryosu
Büyük bir e-ticaret şirketinde ödeme geçidi mikroservisi çalıştıran bir sunucuda, yeni başlayan bir junior sistem yöneticisi API loglarının servis tarafından yazılamadığını fark eder. Hızlı çözüm bulmak amacıyla `/var/log/payment/` dizinine ve altındaki tüm dosyalara `chmod -R 777` verir. İki hafta sonra sunucudaki bir WordPress eklentisi üzerinden kısıtlı `www-data` yetkisi elde eden bir saldırgan, `/var/log/payment/` altındaki logların dünya çapında yazılabilir ve okunabilir olduğunu keşfeder. Saldırgan hem müşterilerin ham kart işlem loglarını çalar hem de log dosyalarını tahrif ederek adli bilişim (forensics) incelemesini sabote eder.

---

## SENARYO 2 (G024-SC2): Bağımsız Laboratuvar: Kontrollü Girdi, Chmod Değişikliği ve Geri Alma (Rollback)

### 1. Soru Metni ve Açıklaması
**Soru:** Linux dosya izinleri rwx: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir? (Örnek uygulama: Sahip olduğun test dosyasında chmod değişikliklerini gözlemle ve geri al. Doğrulama: kontrollü girdi, gözlenebilir çıktı, olumlu/olumsuz test ve etik sınır. Önceki günün dosyası gerekmez.)

**Açıklama:** Güvenlik operasyonlarında yapılan her yetkilendirme ve sıkılaştırma adımı kontrollü, ölçülebilir ve gerektiğinde kesintisiz biçimde geri alınabilir (reversibility / rollback) olmalıdır. Bu soruda izole bir test dosyası üzerinde izin değişikliği, işlem günlüğü (journaling) ve geri alma döngüsü test metodolojisiyle tanımlanmaktadır.

### 2. Kapsamlı ve Detaylı Cevap
Bağımsız laboratuvar deneyimiz şu dört ana eksende yapılandırılmıştır:

1. **Kontrollü Girdi (Controlled Input):**
   - Deney ortamında herhangi bir sistem dosyasına zarar vermemek adına etik sınır gözetilerek yalnızca analistin tam sahipliğinde bulunan izole bir test dosyası kullanılır: `portfolio/hafta_04/gun_024/ornek_veri/lab_test_dosyasi.txt`.
   - Başlangıç durumu kontrollü bir izin ile (`0666` veya `0600`) oluşturulur.
   - Geri alma günlüğü (`chmod_journal.json`) başlatılır.

2. **İşlem Adımları (Operation):**
   - **Adım 1:** Test dosyası güvenli sıkılaştırma senaryosu gereği `0600` (`-rw-------`) iznine çekilir. Uygulama modülü (`linux_permission_rwx_auditor.py --modify`) eski izni (`0666`), yeni izni (`0600`), işlem zaman damgasını, operatör kimliğini ve gerekçeyi günlüğe atomik olarak kaydeder.
   - **Adım 2:** Geçici bir bakım/okuma ihtiyacı simüle edilerek dosya izni `0644` (`-rw-r--r--`) yapılır ve bu ikinci işlem de günlüğe kaydedilir.
   - **Adım 3:** Bakım tamamlandıktan sonra `--rollback` komutu tetiklenerek günlüğün en son işlemi baz alınır ve dosya izni önceki güvenli durumuna (`0600`) tek komutla döndürülür.

3. **Beklenen Sonuç (Observable Output):**
   - Gözlenebilir çıktı olarak konsolda ve `chmod_degisiklik_ve_geri_alma_kaydi.txt` kanıtında her aşamanın işlem kimliği (`TX-...`), eski ve yeni oktal/sembolik izinleri net bir şekilde görüntülenir.
   - Rollback sonrası dosyanın fiziksel dosya sistemi izinleri teyit edildiğinde orijinal izin moduna başarıyla döndüğü (`BASARIYLA_GERI_ALINDI`) doğrulanır.

4. **Negatif Kontrol ve Hata Yönetimi (Negative Control):**
   - **Senaryo A:** Günlük dosyası mevcut olmadığında sistemin kontrolsüz çökmek yerine `FileNotFoundError` fırlatması ve açıklayıcı hata mesajı vermesi (`test_13`).
   - **Senaryo B:** Günlük dosyasının boş olması durumunda `ValueError` ile geri alınacak işlem bulunamadığının bildirilmesi.
   - **Senaryo C:** Hedef dosyanın diskten silinmiş olması halinde dosya yok hatasının raporlanması.

5. **Etik Sınır (Ethical Boundary):**
   - Deneyde asla `/etc/shadow`, `/etc/sudoers` gibi canlı sistem dosyaları doğrudan değiştirilmez; sadece sahip olunan laboratuvar test dosyası üzerinde çalışılır.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Kurumsal DevOps ve DevSecOps mülakatlarında *"İzinleri sertleştirmek için bir betik yazdınız ve production sunucusunda çalıştırdınız. Ancak kritik bir veritabanı servisi erişim hatası vererek durdu. Ne yaparsınız?"* sorusu sorulur.  
**Usta Yanıtı:** *"Sertleştirme betiğimi yazarken işlemlerin öncesinde atomik bir 'state snapshot' (durum günlüğü/journal) kaydı alacak şekilde tasarlarım. Beklenmeyen bir servis kesintisinde tek bir `--rollback` parametresi ile tüm dosyaların orijinal izinlerini saniyeler içinde geri yüklerim. Geri alma planı (contingency/rollback plan) test edilmemiş hiçbir güvenlik sıkılaştırması canlı ortama uygulanmaz."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir finans kuruluşunun Linux altyapısında PCI-DSS denetimi öncesi dosya sıkılaştırma çalışması yapılır. Güvenlik mühendisi `/var/lib/mysql` dizinindeki yetkileri kısıtlarken yanlışlıkla MySQL servis kullanıcısının (`mysql:mysql`) soket dosyasına yazma yetkisini kaldırır. Eğer mühendis değişiklikleri bir geri alma günlüğü tutmadan doğrudan kör `chmod` ile yaptıysa, MySQL servisi ayağa kalkamaz, işlemler durur ve ciddi bir finansal kayıp yaşanır. Ancak geri alma günlüğü kullanan bir orkestrasyon aracı ile mühendis 10 saniye içinde rollback yaparak servisi tekrar faal hale getirir ve ardından doğru yetkilendirme kuralını revize eder.

---

## SENARYO 3 (G024-SC3): Linux Dosya İzinleri Risk Analizi, Tespit ve Savunma Mekanizmaları

### 1. Soru Metni ve Açıklaması
**Soru:** 'Linux dosya izinleri rwx' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir? (Risk: Gereksiz izin, yanlış servis ve yapılandırma. Konuya uyarlama: Linux dosya izinleri rwx. Tespit: Kullanıcı/izin/servis envanteri ve fark raporu. Savunma: En az ayrıcalık ve geri alınabilir yapılandırma.)

**Açıklama:** Kurumsal sistemlerde dosya izinlerinin güvenlik temellerinden sapması (permission drift) zamanla kaçınılmaz hale gelir. Bu soruda riskin doğuşu, otomatik envanter ve fark (diff) analiziyle tespiti ve En Az Ayrıcalık (Least Privilege) ilkesine dayalı savunma kontrolleri ele alınmaktadır.

### 2. Kapsamlı ve Detaylı Cevap
Dosya izinleri güvenliği üç aşamalı bir yaşam döngüsüyle yönetilir:

1. **Riskin Oluşumu (Threat Vector & Root Cause):**
   - **Gereksiz İzinler (Over-Permissioning):** Kurulum kılavuzlarında veya aceleyle yazılmış dağıtım betiklerinde yer alan `chmod 777` veya `chmod -R a+rwx` komutları.
   - **Yanlış Umask Yapılandırması:** Sistem genelinde (`/etc/login.defs` veya `/etc/profile`) umask değerinin `000` veya `002` bırakılması sonucu oluşturulan tüm yeni dosya ve dizinlerin dünyaya yazılabilir hale gelmesi.
   - **Yetkisiz SUID/SGID İkilileri:** Sistem yöneticisinin bir betiğe veya ikiliye (`nmap`, `find`, `vim`, `bash`) kolaylık olsun diye SUID root (`4755`) vermesi, yerel yetki yükseltme (Local Privilege Escalation - LPE) için altın kapı aralar (GTFOBins vektörleri).
   - **Servis Yapılandırma Hataları:** Web sunucusunun (Nginx/Apache) veya Docker konteynerinin dosyaları `root` kullanıcısı ile yazması ve diğer kullanıcıların bu dosyalara erişebilmesi.

2. **Riskin Tespiti (Detection & Difference Reporting):**
   - **Otomatik Envanter Taraması:** Sistemdeki tüm kritik dosya ve dizinlerin mevcut sahiplik, grup ve oktal modlarının taranması (`linux_permission_rwx_auditor.py --audit`).
   - **Kural Temeli (Baseline) Karşılaştırması:** Taranan envanter, CIS Benchmark ve NIST SP 800-53 AC-6 standartlarına göre hazırlanmış kural seti (`permission_baseline_rules.json`) ile bit düzeyinde karşılaştırılır.
   - **Fark Raporu (Difference Report):** İzin aşımı (drift) yaşanan nesneler listelenir; CWE-732 world-writable dosyalar, aşırı izinli SSH anahtarları ve eksik sticky bit durumları severity (Kritik, Yüksek, Orta) bazında sınıflandırılır.

3. **Savunma ve Önleme Kontrolleri (Remediation & Defense-in-Depth):**
   - **En Az Ayrıcalık (Principle of Least Privilege - PoLP):** Her dosya ve dizin yalnızca meşru fonksiyonunu icra edebileceği asgari izinle donatılır:
     - `/etc/shadow`: `0600` veya `0640` (root:shadow).
     - `/etc/passwd`: `0644` (root:root) - kesinlikle yazma kapalı.
     - `~/.ssh/id_rsa`: `0600` (kullanıcı:kullanıcı) - gruba ve dünyaya sıfır erişim.
     - `/tmp`: `1777` (root:root) - zorunlu sticky bit.
   - **Sistem Genelinde Katı Umask:** Kurumsal sunucularda varsayılan umask `027` olarak kilitlenir; böylece oluşturulan hiçbir dosya diğer kullanıcılar tarafından okunamaz veya değiştirilemez.
   - **Geri Alınabilir Yapılandırma (Reversible Configuration):** Uygulanan tüm sertleştirme betikleri bir `journal` tutarak geriye dönük hatasız restorasyon garantisi verir.
   - **Zorunlu Erişim Denetimi (MAC):** DAC izinlerini aşabilecek olası açıklara karşı SELinux veya AppArmor profilleri aktif tutularak süreçlerin erişebileceği dosyalar ek güvenlik katmanıyla sınırlandırılır.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Güvenlik mimarisi mülakatlarında şu soruyla karşılaşırsınız: *"DAC (rwx) ile MAC (SELinux/AppArmor) arasındaki fark nedir ve neden tek başına rwx yetersizdir?"*  
**Cevap:** DAC modelinde dosyanın sahibi (`user`), dosya üzerindeki izinleri dilediği gibi gevşetebilir (`chmod 777`). Bir saldırgan kullanıcının hesabını ele geçirdiğinde o kullanıcının tüm dosyalarını dünyaya açabilir. Oysa Zorunlu Erişim Denetiminde (MAC - Mandatory Access Control), dosya izinleri 777 olsa dahi çekirdek seviyesindeki SELinux güvenlik politikası ilgili sürecin o dosyaya erişmesine izin vermiyorsa erişim engellenir. Bu nedenle savunmada derinlik (defense-in-depth) ilkesi gereği hem DAC hem MAC birlikte kullanılmalıdır.

### 4. Gerçek Hayat / Sektör Senaryosu
Bir fintech şirketi Linux sunucularında her gece otomatik uyumluluk tarayıcısı (compliance auditor) koşturmaktadır. Bir gece tarayıcı `/etc/shadow` dosyasının izninin `0644`'e değiştiğini (fark raporu / permission drift) tespit eder ve SIEM sistemine kritik alarm üretir. Güvenlik Operasyon Merkezi (SOC) hemen inceleme başlatır: Saat 23:14'te sisteme sızan bir saldırganın kısıtlı bir sudo yetkisini istismar ederek `/etc/shadow` dosyasını okunabilir hale getirdiğini ve parolaları kırmak üzere dışarı sızdırmaya çalıştığını belirler. Otomatik iyileştirme kuralı anında devreye girerek dosyayı `0600` moduna çeker, saldırganın oturumunu sonlandırır ve olay büyümeden bertaraf edilir.
