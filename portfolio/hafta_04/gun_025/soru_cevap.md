# GÜN 025: Soru Bankası ve Çözüm Rehberi (Kullanıcı, Grup ve Oturum)

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## SENARYO 1 (G025-SC1): Kullanıcı, Grup ve Oturum Temel Mekanizması ve Güvenlik Önemi

### 1. Soru Metni ve Açıklaması
**Soru:** Kullanıcı, grup ve oturum: Temel mekanizmayı ve güvenlik önemini açıkla. (Kimlik ve etkin oturum ayrıdır; ortak hesap izlenebilirliği zayıflatır.)

**Açıklama:** İşletim sistemlerinde kullanıcı hesapları, gruplar ve oturumlar erişim denetiminin ve olay izleme (audit logging) mekanizmalarının temelini oluşturur. Bu soruda kimlik (authentication) ile etkin oturum (session authorization) ayrımı ve ortak hesap kullanımının inkâr edilemezlik (non-repudiation) ilkesi üzerindeki yıkıcı etkisi incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap
Kullanıcı, grup ve oturum üçlüsü işletim sisteminin güvenliğini şu mekanizmalarla sağlar:

1. **Kimlik ile Etkin Oturum Ayrımı:**
   - **Statik Kimlik (Identity):** Bir hesabın `/etc/passwd` veya Active Directory üzerindeki kalıcı tanımıdır (kullanıcı adı, UID, SID, birincil/ikincil gruplar). Kimlik yalnızca bir varoluş ve potansiyel yetki beyanıdır.
   - **Dinamik Etkin Oturum (Active Session):** Başarılı bir kimlik doğrulama sonrasında (PAM, Kerberos, SSH handshake) işletim sistemi çekirdeğinin tahsis ettiği geçici yürütme bağlamıdır. Oturum; bir Terminal (TTY/PTS), Oturum Belirteci (Session Token), Gerçek/Etkin UID (RUID/EUID), işlem ortam değişkenleri (`$PATH`, `$USER`) ve süreç ağacından oluşur.
   - **Güvenlik Anlamı:** Kimlik doğrulaması yapılmış olsa dahi, bir oturum çalınabilir (Session Hijacking), boşta açık bırakılabilir veya yetkileri süreç düzeyinde manipüle edilebilir. Dolayısıyla güvenlik sadece girişte değil, oturumun tüm yaşam döngüsü boyunca denetlenmelidir.

2. **Grup Yönetimi ve Rol Tabanlı Erişim:**
   - Kullanıcıların tek tek yetkilendirilmesi yerine ortak görev tanımına sahip kullanıcılar mantıksal gruplara (`secops`, `developers`, `database_admins`) dahil edilir.
   - İdari yetkiler (`sudo`, `wheel`, `Administrators`) gruplar üzerinden sınırlandırılır ve En Az Ayrıcalık (Principle of Least Privilege) ilkesi hayata geçirilir.

3. **Ortak Hesap Anti-Paterni ve İzlenebilirlik Kaybı:**
   - Birden fazla kişinin aynı hesabı (örn: `root`, `administrator`, `db_admin`) ortak parola veya SSH anahtarıyla paylaşması kurumsal siber güvenliğin en büyük zaafıdır.
   - **İnkâr Edilemezlik (Non-Repudiation) Yok Oluşu:** Sistemde kritik bir güvenlik olayı (veri silinmesi, yapılandırma tahrifatı, veri sızıntısı) yaşandığında, log kayıtlarında sadece ortak hesabın adı görünür. Hangi gerçek kişinin (Ali mi, Veli mi, yoksa hesabı ele geçiren bir saldırgan mı) bu eylemi yaptığı adli bilişim (forensics) açısından kanıtlanamaz.
   - Ortak hesaplar aynı zamanda parola rotasyonunu imkansız hale getirir; bir kişi işten ayrıldığında ortak şifreyi değiştirmek operasyonel kaosa yol açar.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Mülakatlarda sıkça sorulur: *"Sunucularımıza doğrudan root olarak SSH ile girişe neden izin vermemeliyiz (PermitRootLogin no)?"*  
**Usta Yanıtı:** *"Doğrudan root girişi iki temel zafiyet yaratır: Birincisi, saldırganlar kullanıcı adını tahmin etmekle uğraşmaz, doğrudan root üzerine kaba kuvvet (brute-force) yapar. İkincisi ve en önemlisi, doğrudan root girişi inkâr edilemezliği (non-repudiation) yok eder. Her yönetici kendi kişisel hesabıyla (`ad.soyad`) SSH yapmalı, ardından gerçekleştireceği idari işlemleri `sudo` ile yapmalıdır. Böylece `/var/log/auth.log` dosyasında 'Hangi kullanıcı, saat kaçta, hangi komutu root yetkisiyle çalıştırdı?' sorusunun cevabı adli bilişim standartlarında mühürlenmiş olur."*

### 4. Gerçek Hayat / Sektör Senaryosu
Uluslararası bir bankanın altyapı ekibinde 8 sistem mühendisi üretim sunucularında ortak bir `svc_admin` hesabı kullanmaktadır. Bir gece saat 03:00'te üretim veritabanı kümesinde tüm replikasyon konfigürasyonunu bozan ve 4 saatlik hizmet kesintisine yol açan bir komut çalıştırılır. Teftiş kurulu ve SOC ekibi logları incelediğinde komutun `svc_admin` tarafından çalıştırıldığını görür. Ancak 8 mühendis de o saatte komutu kendisinin çalıştırmadığını iddia eder. Hangi personelin hata yaptığını tespit etmek imkansız hale gelir ve banka BDDK denetiminde "Erişim Kontrolü ve İzlenebilirlik Yetersizliği" gerekçesiyle ağır para cezasına çarptırılır.

---

## SENARYO 2 (G025-SC2): Bağımsız Laboratuvar: Kendi Oturumunu Belgeleme ve Negatif Kontrol

### 1. Soru Metni ve Açıklaması
**Soru:** Kullanıcı, grup ve oturum: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir? (Örnek uygulama: whoami, id veya Windows hesap komutlarıyla kendi oturumunu belgele. Doğrulama: kontrollü girdi, gözlenebilir çıktı, olumlu/olumsuz test ve etik sınır. Önceki günün dosyası gerekmez.)

**Açıklama:** Güvenlik analistinin ilk adımı, üzerinde çalıştığı sistemde hangi kimlikle, hangi yetkilerle ve hangi ortamda bulunduğunu (situational awareness) doğrulamaktır. Bu soruda yerel canlı oturumun keşfi, parametrik ayrıştırılması ve negatif kontrollerle güvenli hata yönetiminin test metodolojisi incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap
Laboratuvar çalışmamızın metodolojisi ve adımları:

1. **Kontrollü Girdi (Controlled Input):**
   - Çalışma ortamındaki mevcut işletim sistemi oturumunun kimlik meta verileri, ortam değişkenleri ve süreç belirteçleri.
   - Deney için önceki günün hiçbir dosyasına bağımlılık yoktur; sıfırdan bağımsız yerel girdi kullanılır.

2. **İşlem Adımları (Operation):**
   - **Adım 1 (Uygulama Motoru):** `user_group_session_auditor.py --live-session` komutu çalıştırılarak `getpass.getuser()`, `platform.node()`, `os.getpid()` ve platforma özgü oturum parametreleri taranır.
   - **Adım 2 (İşletim Sistemi Seviyesi):** Windows ortamında `whoami`, `whoami /user` (SID keşfi) ve `whoami /priv` (atanmış ayrıcalıklar); Linux ortamında `id`, `w`, `who` komutları icra edilir.
   - **Adım 3 (Kanıt Kaydı):** Tüm gözlenebilir çıktılar `kanit/gercek/yerel_oturum_belgeleme.txt` dosyasına eksiksiz yazılır.

3. **Beklenen Sonuç (Observable Output):**
   - Konsolda ve kanıt dosyasında kullanıcı kimliği (`seydieryilmaz`), makine adı (`SeydiV`), işletim sistemi (`Windows`), süreç PID'si (`5216`), kullanıcı SID'si (`S-1-5-21-4251509839-2239028382-1546434742-1006`) ve aktif ayrıcalıklar (örn: `SeChangeNotifyPrivilege Enabled`) açık ve doğrulanabilir formatta listelenir.

4. **Negatif Kontrol ve İstisna Yönetimi (Negative Control):**
   - **Test 12:** CLI arayüzüne var olmayan bir envanter dosya yolu verildiğinde (`--inventory olmayan_dosya.json`), sistemin çökmeden `FileNotFoundError` fırlatması ve sıfırdan farklı bir çıkış kodu üretmesi teyit edilmiştir.
   - **Test 13:** Kural dosyası bozuk veya geçersiz JSON içerdiğinde sistemin `json.JSONDecodeError` fırlatarak işlemi güvenle reddetmesi doğrulanmıştır.

5. **Etik Sınır (Ethical Boundary):**
   - Yalnızca analistin kendi oturum açtığı kullanıcı hesabı ve süreç alanı sorgulanmıştır; diğer kullanıcıların özel verilerine veya sistem kısıtlamalarına yetkisiz müdahalede bulunulmamıştır.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Sızma testi (penetration testing) ve adli bilişim mülakatlarında şu soru sıkça gelir: *"Bir sunucuya sızdığınızda (veya bir analist olarak incelemeye başladığınızda) ilk çalıştıracağınız 3 komut nedir ve neden?"*  
**Cevap:** *"1. `whoami` (Kimim?), 2. `id` / `whoami /priv` (Hangi gruplara ve yetkilere sahibim?), 3. `w` / `last` (Bu sunucuda şu an başka kimler var ve en son kimler girmiş?). Bu komutlar durumsal farkındalık (situational awareness) sağlar. Kim olduğunuzu ve mevcut oturumun yetki sınırlarını bilmeden atılacak her adım ya sistemin çökmesine ya da güvenlik savunmalarına (EDR/SIEM) yakalanmanıza yol açar."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir siber güvenlik analisti şüpheli bir sunucuda ters kabuk (reverse shell) bağlantısı aldığında, hemen `whoami` çalıştırır ve çıktıda `www-data` görür. Ardından `id` çalıştırdığında kullanıcının beklenmedik biçimde `sudo` ve `docker` gruplarına üye olduğunu fark eder. Bu oturum belgelemesi analiste sistemin web servisi üzerinde gereksiz yüksek ayrıcalıklar tanımlandığını (CWE-250) ve saldırganın bu oturumu kullanarak birkaç saniye içinde kök yetkilerine (root) sıçrayabileceğini anında gösterir.

---

## SENARYO 3 (G025-SC3): Kullanıcı, Grup ve Oturum Risk Analizi, Tespiti ve Savunma Kontrolleri

### 1. Soru Metni ve Açıklaması
**Soru:** 'Kullanıcı, grup ve oturum' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir? (Risk: Gereksiz izin, yanlış servis ve yapılandırma. Konuya uyarlama: Kullanıcı, grup ve oturum. Tespit: Kullanıcı/izin/servis envanteri ve fark raporu. Savunma: En az ayrıcalık ve geri alınabilir yapılandırma.)

**Açıklama:** Kurumsal altyapılarda kullanıcı hesaplarının yaşam döngüsü, servis hesaplarının ayrıcalıkları ve oturum parametreleri zamanla gevşer. Bu soruda riskin kaynakları, otomatik denetimle tespiti ve savunma mimarisi incelenmektedir.

### 2. Kapsamlı ve Detaylı Cevap

1. **Riskin Doğuşu (Threat & Root Cause):**
   - **Servis Hesaplarına Etkileşimli Kabuk Verilmesi (CWE-250):** `www-data`, `nginx` veya `postgres` gibi arka plan servis hesaplarına varsayılan olarak `/bin/bash` atanması. Bir web zafiyetinde saldırgan doğrudan tam donanımlı etkileşimli kabuğa sahip olur.
   - **Servis Hesaplarına İdari Grup Yetkisi Verilmesi:** Yedekleme veya izleme servislerinin kolaylık olsun diye `sudo` veya `wheel` grubuna eklenmesi. Servisin ele geçirilmesi tüm sunucunun ele geçirilmesiyle sonuçlanır.
   - **Atıl / Yetim Hesaplar (Dormant Accounts - CWE-262):** Şirketten ayrılmış veya rolü değişmiş personelin hesaplarının kapatılmaması. Saldırganların kalıcı erişim (persistence) sağlamak için en sevdiği vektördür.
   - **Ortak İdari Oturumlar (Shared Sessions):** Root veya admin hesabına birden fazla eşzamanlı oturum açılması. İzlenebilirlik yok olur, oturum sızıntısı riski katlanır.
   - **Sonsuz Oturum Süreleri (Session Timeout Yokluğu - CWE-613):** Boşta kalan terminallerin otomatik kapanmaması.

2. **Riskin Tespiti (Detection via Inventory & Difference Reporting):**
   - **Otomatik Envanter Taraması:** `user_group_session_auditor.py --audit` aracı ile sistemdeki tüm kullanıcı hesapları, kabukları, grup üyelikleri ve açık oturumlar taranır.
   - **Kural Tabanı ile Karşılaştırma:** Taranan veriler `system_users_groups_baseline.json` güvenlik kurallarıyla kıyaslanır.
   - **Fark Raporu (Difference Report):** Tespit edilen sapmalar severity seviyesine göre ayrıştırılır:
     - *Kritik:* Servis hesabında `/bin/bash` kabuğu tespiti.
     - *Kritik:* Ortak idari hesapta farklı IP'lerden eşzamanlı aktif oturum tespiti.
     - *Yüksek:* Servis hesabının `sudo` grubuna üye olması.
     - *Orta:* 90 günden uzun süredir atıl duran aktif kullanıcı hesabı.
     - *Orta:* 15 dakikadan uzun süredir boşta bekleyen açık oturum.

3. **Savunma ve Önleme Kontrolleri (Remediation & Defense Controls):**
   - **En Az Ayrıcalık İlkesi (PoLP):** Servis hesaplarının kabukları `/usr/sbin/nologin` yapılır (`usermod -s /usr/sbin/nologin <user>`), yetkisiz grup üyelikleri temizlenir (`gpasswd -d <user> <group>`).
   - **Merkezi Kimlik Yönetimi ve IAM Entegrasyonu:** LDAP/Active Directory ve PAM modülleri ile tekil kimlik doğrulama, MFA zorunluluğu ve rol tabanlı erişim (RBAC).
   - **Otomatik Hesap Kapatma (Account Deprovisioning):** İK sistemleri ile entegre IAM sistemleri sayesinde işten ayrılan personelin hesapları anında dondurulur (`usermod -L <user>`).
   - **Oturum Güvenliği ve Zaman Aşımı:** `/etc/profile` altında `TMOUT=900` tanımlanır; `/etc/security/limits.conf` ile idari hesaplar için `maxlogins 1` uygulanır.

### 3. Mülakat / Sınav İpucu (Usta Notu)
Denetim ve sertifikasyon mülakatlarında şu soru sorulur: *"CIS Benchmark denetiminde bir Linux sunucuda 'UID 0 olan birden fazla kullanıcı olmamalıdır' kuralı neden vardır?"*  
**Cevap:** *"Linux çekirdeği yetki denetimini kullanıcı ismine göre değil, UID değerine göre yapar. Bir saldırgan veya kötü niyetli sistemci `/etc/passwd` dosyasına `toor:x:0:0::/root:/bin/bash` satırını eklerse, ismi farklı olsa da `toor` kullanıcısı tam yetkili bir root hesabıdır. Bu bir arka kapıdır (backdoor). Bu nedenle güvenlik denetimlerinde mutlaka `awk -F: '($3 == 0) {print $1}' /etc/passwd` çalıştırılarak UID 0 olan tek hesabın 'root' olduğu teyit edilmelidir."*

### 4. Gerçek Hayat / Sektör Senaryosu
Bir sağlık teknolojileri şirketinde SOC analistleri, mesai saatleri dışında saat 02:30'da 4 aydır pasif olan `eski_muhasebeci` hesabının VPN üzerinden başarılı bir oturum açtığını ve iç ağda port taraması yaptığını tespit eder. İncelemede, personelin ayrılırken hesabının silinmediği ve parolasının zayıf olması sebebiyle ele geçirildiği anlaşılır. Otomatik kural motoru devreye girerek oturumu anında sonlandırır (`pkill -u eski_muhasebeci`), hesabı kilitler ve SOC ekibine incident ticket'ı açar. Altyapı ekibi derhal atıl hesap tespit otomasyonunu devreye alarak 90 günü aşan tüm hesapları kilitler.
