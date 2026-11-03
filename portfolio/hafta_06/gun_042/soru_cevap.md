# G042 — Aşama 2 Kalite Özeti ve Kabul Soru ve Çözüm Analizleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## [G042-SC1] Aşama 2 Kabul Kriterleri: Salt-Okunur Deliller ve Asgari Yeterlilik İlkesi

### Temel Kavram ve Güvenlik Mekanizması
İşletim sistemi temelleri aşamasının başarıyla tamamlandığını (Aşama 2 Kabulü) tescil etmek için sübjektif iddialar veya yalnızca teorik açıklamalar yetersizdir. Siber güvenlik denetim standardında bir sistemin hazır ve güvenli olduğunu kanıtlamak, **"Salt-Okunur Kanıt" (Read-Only Evidence)** ilkesine dayanır.

Bu ilke uyarınca denetçi, canlı sistemin bütünlüğünü bozmadan (non-intrusive) şu 6 kritik bileşeni doğrudan sistemden veya doğrulanmış envanterden okuyarak belgelemelidir:
1. Süreç listesi ve ayrıcalıksız servis çalıştırma kanıtları.
2. Kritik dosya izinleri (`/etc/shadow`, `/etc/sudoers`) ve sistem umask doğrulaması.
3. Kalıcı ve merkezi günlükleme (journald, auditd, SIEM) durumu.
4. Kritik ikililerin ve yapılandırmaların kriptografik SHA-256 bütünlük karmaları.
5. 3-2-1 kuralına uygun doğrulanmış yedekleme kayıtları ve restore test sonucu.
6. Miras güvensiz servislerin kapalı olduğuna ve SSH sıkılaştırmasına dair konfigürasyon kayıtları.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"Aşama 2 kabul: işletim sistemi temelleri" kapsamında temel mekanizmayı ve güvenlik önemini açıkla. Neden bir sistem yöneticisinin "ben tüm ayarları yaptım" demesi yeterli değildir ve süreç, dosya izni, günlük, hash, yedek ve servisleri salt-okunur kanıtla göstermek asgari yeterlilik şartıdır?

**Didaktik Çözüm:**  
- **Beyan ile Kanıt Arasındaki Fark:** İnsan beyanı unutkanlığa, yanlış anlamaya veya kasıtsız hatalara açıktır. Bir sistem yöneticisi SSH'ta root girişini kapattığını zannedebilir; ancak `/etc/ssh/sshd_config.d/` altındaki başka bir geçersiz dosya `PermitRootLogin yes` ayarını ezmiş (override) olabilir.
- **Asgari Yeterlilik Standartları:** Salt-okunur kanıt, sistemin anlık gerçek durumunun dijital parmak izidir. Geliştirdiğimiz denetim motoru (`stage2_os_foundations_auditor.py`), sisteme müdahale etmeden sadece okuma yapar; süreçlerin PID'lerini ve yetkilerini, dosyaların izin bitlerini (0640, 0440), log servislerinin durumunu ve 3-2-1 yedek kayıtlarını doğrular. Bu veriler inkâr edilemez, tekrarlanabilir ve bağımsız denetçiler tarafından doğrulanabilir olduğu için asgari yeterlilik kabul edilir.

---

### Savunma ve Tespit Kılavuzu
- **Salt-Okunur Denetim Komutları:**
  - Süreç hijyeni: `ps -eo pid,user,args --forest`
  - Kritik dosya izinleri: `stat -c "%a %n %U:%G" /etc/shadow /etc/sudoers /etc/passwd`
  - Günlükleme: `systemctl is-active auditd systemd-journald`
  - Bütünlük kontrolü: `sha256sum /bin/login /usr/bin/sudo`
  - Servis durumu: `ss -tulpn` ve `systemctl list-unit-files --state=enabled`
- **Savunma Entegrasyonu:**
  - Bu kontroller haftalık olarak salt-okunur bir hizmet hesabı (service account) aracılığıyla otomasyona bağlanmalı ve raporlar merkezi SIEM'e gönderilmelidir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, siber güvenlikte 'Söz uçar, log ve hash kalır.' Bana güvenli olduğunu anlatma, bana `/etc/shadow` dosyasının izin çıktısını göster. Bana 'yedek alıyoruz' deme, son başarılı geri yükleme testinin log kaydını göster. Bir güvenlik denetçisi ancak salt-okunur delili gözüyle gördüğü ve kriptografik hash'i doğruladığı zaman 'PASS' imzasını atar."*

---

## [G042-SC2] Yeni Sanal Makine için Kör Kontrol Listesi ve Bağımsız Doğrulama Döngüsü

### Temel Kavram ve Güvenlik Mekanizması
Bir sanal makinenin (VM) güvenliğini test ederken en tehlikeli yaklaşım, o makineyi kuran kişinin kendi hazırladığı kontrol listesine göre test yapmasıdır. Bu durum "Doğrulama Yanlılığına" (Confirmation Bias) yol açar.

Bunun önüne geçmek için **"Kör Kontrol Listesi" (Blind Checklist)** metodolojisi kullanılır:
- Denetçi veya denetim motoru, sistemin nasıl kurulduğuna dair hiçbir ön bilgiye (önceki günlerin kodlarına, geçici notlara) bakmaz.
- Standart bir güvenlik matrisi üzerinden sistemi bağımsız bir gözle inceler.
- Girdi kontrollüdür, işlem deterministiktir, çıktı gözlenebilir ve doğrulanabilirdir; olumlu senaryolar kadar negatif sınır kontrolleri de test edilir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Yeni hazırlanmış bir VM için kör kontrol listesiyle envanter ve raporlama sürecinde bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir? Önceki günün dosyalarına bağımlılık neden kesinlikle yasaktır?

**Didaktik Çözüm:**  
- **Laboratuvar Girdisi:** `stage2_acceptance_inventory.json` dosyası. İçerisinde süreçler, izinler, loglar, hash'ler, yedekler ve servisler olmak üzere 6 sütun yer alır.
- **Laboratuvar İşlemi:** Motor her bir sütunu doğrular, puanlar (her sütun 100 üzerinden değerlendirilir), ortalama puanı alır (100.0/100) ve `STAGE_02_PASS` kararını üretir.
- **Beklenen Sonuç:** `kanit/gercek/stage2_kalite_kabul_raporu.txt` ve `kanit/gercek/komut_ve_cikis.txt` dosyaları.
- **Negatif Kontroller:** 14 adet unittest (`test_stage2_os_foundations_auditor.py`) ile doğrulanır:
  - 6 sütundan biri eksik olursa `Stage2AuditError` fırlatılır.
  - Geçersiz dosya izni (`0999`) reddedilir.
  - Bozuk SHA-256 karması yakalanır.
  - Negatif PID (-99) reddedilir.
  - Bozuk JSON sentaksı güvenle yakalanır.
- **Bağımsızlık Şartı:** Önceki günün dosyalarına bağımlılık yasaktır; çünkü her günün modülü bağımsız bir laboratuvar çıktısıdır. Eğer bugünkü kod dünkü dosyaya bağımlı olursa, tekil bir hata tüm müfredat zincirini kırar.

---

### Savunma ve Tespit Kılavuzu
- **Kör Denetim Uygulama Adımları:**
  1. Hedef sistemin imajını (snapshot) alın.
  2. Denetim motorunu salt-okunur parametrelerle çalıştırın.
  3. Üretilen raporu CIS Ubuntu/Windows Benchmark gereksinimleriyle karşılaştırın.
  4. Uygunsuz bulunan her bulgu için Ansible sıkılaştırma oyun kitabı (playbook) yazarak açığı otomatik kapatın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, kör kontrol listesi demek, gözün kapalı test yapmak demek değildir. Sistemin geçmişine, kuran kişinin lafına gözünü kapatıp, sadece standart kurallara ve ham verilere odaklanmak demektir. Negatif testler işte bu yüzden vardır; denetim motorun hatalı veriyi reddedemiyorsa, kör kontrol listesi güvenilir olamaz."*

---

## [G042-SC3] Aşama 2 Risk Analizi: İzin, Servis ve Yapılandırma Sapmaları

### Temel Kavram ve Güvenlik Mekanizması
İşletim sistemi düzeyindeki en büyük güvenlik riski; kurulum anında güvenli olan bir sunucunun, zaman içerisinde operasyonel ihtiyaçlar, acil hata gidermeler veya ihmaller nedeniyle güvenliğini kaybetmesidir (**Configuration Drift**).

Bu riskler üç ana grupta toplanır:
1. **Gereksiz İzinler:** Umask'ın gevşetilmesi, `/etc/shadow` dosyasına okuma izni verilmesi, kullanıcıların gereksiz yere `sudo` yetkisi alması.
2. **Yanlış Servisler:** Telnet, rsh veya eski SMB servislerinin açılması, geliştiricilerin test için açtığı geçici portların unutulması.
3. **Geri Alınamaz Yapılandırma:** Yapılan değişikliklerin belgelenmemesi, konfigürasyon dosyalarının yedeksiz düzenlenmesi ve bir sorun anında sistemin çalışmaz hale gelmesi.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"Aşama 2 kabul: işletim sistemi temelleri" bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir? Kullanıcı/izin/servis envanteri ve fark raporu savunmada nasıl bir rol oynar?

**Didaktik Çözüm:**  
- **Risk Oluşumu:** Sistem yöneticisi "işimiz hemen çözülsün" diye geçici bir kullanıcı açar, şifresini basit koyar ve `sudo` verir; sonra o kullanıcıyı silmeyi unutur. Ya da uzaktan dosya atmak için TFTP servisi kurar ve portu açık bırakır.
- **Tespit Mekanizması:** Sistemde periyodik olarak envanter çıkarılır (`stage2_os_foundations_auditor.py`). Elde edilen envanter, temiz "Altın İmaj" (Golden Image) taban çizgisiyle karşılaştırılır (Fark Raporu / Drift Analysis). Yeni açılmış bir port veya değişmiş bir dosya izni anında kırmızı bayrakla tespit edilir.
- **Önleme (Savunma):** En Az Ayrıcalık (Least Privilege) ilkesi uygulanır. İdari değişiklikler doğrudan sunucuya girilerek değil, Git üzerinden Kod Olarak Altyapı (IaC - Ansible/Puppet) ile yapılır. Hatalı bir konfigürasyon anında `git revert` ile güvenli duruma geri alınabilir (Rollback).

---

### Savunma ve Tespit Kılavuzu
- **Sıkılaştırma Kontrolleri:**
  - AIDE ile `/etc/` dizinini günlük hash denetimine tabi tutun.
  - `fail2ban` ve `auditd` ile şüpheli `sudo` denemelerini SIEM'e gönderin.
  - SSH anahtarlarının izinlerini `chmod 600 ~/.ssh/authorized_keys` seviyesinde zorlayın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, en tehlikeli saldırı dışarıdan gelen değil, içeride unutulmuş bir yanlış yapılandırmadan içeri sızan saldırıdır. Bir kapıyı kilitlersin ama pencerenin mandalını gevşek bırakırsan evin güvenli değildir. Kullanıcı, izin ve servis envanteri senin güvenlik röntgenindir. Röntgeni düzenli çekmeyen doktor hastalığı teşhis edemez."*

---

## [W06-SC1] Haftalık Mini Proje Sorun Giderme: Çıktı Beklenildiği Gibi Değilse İlk 3 Adım

### Temel Kavram ve Güvenlik Mekanizması
Karmaşık bir güvenlik denetim veya karşılaştırma aracı çalıştırıldığında çıktının beklendiği gibi görünmemesi (hatalı puanlama, eksik tablo, Python istisnası) durumunda panikle rastgele kod değiştirmek sorunu daha da derinleştirir. Sistematik sorun giderme (troubleshooting) disiplini işletilmelidir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
«Aşama 2 kabul: işletim sistemi temelleri» çıktısı beklendiği gibi görünmüyorsa sorun giderme için ilk 3 adımın ne olmalıdır?

**Didaktik Çözüm:**  
1. **Adım 1 — Ön Koşul ve İzinli Ortam Kontrolü:** Çalıştırılan betiğin Python sürümü, bağımlılıkları ve dosya sistemi okuma/yazma izinleri kontrol edilir. Dosyaların doğru dizinde ve UTF-8 formatında olup olmadığı teyit edilir.
2. **Adım 2 — Ham Girdi ve Hata Analizi:** Konsola düşen hata çıktısı (stderr, stack trace) ve girdi olarak verilen JSON dosyasının sentaksı (`json.load`) izole olarak incelenir. Hatanın veriden mi yoksa kod mantığından mı kaynaklandığı ayrıştırılır.
3. **Adım 3 — Yeniden Üretim ve Kontrollü Düzeltme:** Hata senaryosu tekil bir birim test (`unittest`) ile izole edilir ve yeniden üretilir. Düzeltme kontrollü şekilde yapıldıktan sonra tüm test süiti baştan koşturulur ve sonuç kaynaklı olarak belgelenir.

---

### Savunma ve Tespit Kılavuzu
- Hata ayıklarken `print` yerine Python'un `logging` modülünü veya `python -m pdb` hata ayıklayıcısını kullanın.
- Kod değişikliklerini Git commit'leri ile adım adım takip edin.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, hata aldığında kodu rastgele kurcalama. Önce nefes al, hata mesajını satır satır oku. Python sana hatanın nerede olduğunu söyler. Sorunu bir test senaryosuna dönüştür; test geçene kadar kodu düzelt, test geçince arkana yaslan."*

---

## [W06-SC2] Üçüncü Taraf Sistemlerde Güvenlik Uygulaması: İzin ve Veri Koşulları

### Temel Kavram ve Güvenlik Mekanizması
Bir güvenlik denetim aracını veya test betiğini kendi laboratuvarınız dışında başka bir kurumsal sistemde çalıştırmak yasal ve operasyonel sorumluluk doğurur. Yetkisiz test, bilişim suçu kapsamına girer (TCK Madde 243-244).

---

### Soru ve Didaktik Çözüm
**Soru:**  
«Aşama 2 kabul: işletim sistemi temelleri» çalışmasını başka bir sistem üzerinde uygulamadan önce hangi izin ve veri koşullarını doğrulamalısın?

**Didaktik Çözüm:**  
Şu 6 zorunlu koşul doğrulanmalıdır:
1. **Yazılı Yetki ve Kapsam:** Kurum yönetiminden alınmış imzalı izin belgesi ve test edilecek sistemlerin açık IP/hostname listesi (Rules of Engagement).
2. **Veri Minimizasyonu:** Denetim sırasında kişisel veri (KVKK/GDPR) veya hassas müşteri verisi toplanmamalı; yalnızca teknik konfigürasyon metrikleri okunmalıdır.
3. **Test Zamanı ve Penceresi:** Testlerin sistemin en az yoğun olduğu bakım saatlerinde (maintenance window) yapılması.
4. **Hız Sınırı (Rate Limiting):** Denetim betiklerinin sunucunun CPU veya disk kaynaklarını tüketerek hizmet kesintisine (DoS) yol açmaması için hız sınırlandırması uygulanması.
5. **Durdurma Koşulu (Kill Switch):** Sistemde beklenmedik bir performans düşüşü veya uyarı görüldüğünde testin anında kesilebilmesi protokolü.
6. **Raporlama Yetkisi ve Gizlilik:** Üretilen teknik raporun yalnızca yetkili mercilerle gizlilik sözleşmesi (NDA) çerçevesinde paylaşılması.

---

### Savunma ve Tespit Kılavuzu
- Denetime başlamadan önce onay belgesinin SHA-256 karmasını saklayın.
- Toplanan tüm verileri yerel olarak AES-256 ile şifreleyin.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, izinsiz yapılan testin adı siber güvenlik değil, siber suçtur! Dünyanın en iyi denetim kodunu yazsan bile, o kodu yazılı yetki olmadan bir sunucuya doğrultamazsın. Beyaz şapkalı uzmanı hacker'dan ayıran şey teknik gücü değil, ahlakı ve yasal sınırlarıdır."*

---

## [W06-SC3] Aşama Kapanışı ve PASS Kararı için 3 Somut Kanıt

### Temel Kavram ve Güvenlik Mekanizması
Müfredat ve operasyonel standartlar gereği bir haftalık mini projeye ve aşama kapanışına "PASS" kararı verilebilmesi için nesnel ve doğrulanabilir 3 somut kanıtın arşivlenmesi zorunludur.

---

### Soru ve Didaktik Çözüm
**Soru:**  
«Aşama 2 kabul: işletim sistemi temelleri» için PASS kararını verebilmek adına hangi 3 somut kanıtı saklamalısın?

**Didaktik Çözüm:**  
1. **Çalışan Çıktı / Komut veya Kaynak:** Denetim motorunun gerçek komut satırı üzerinde çalıştırıldığını ve hatasız çıkış kodu (returncode 0) ürettiğini gösteren terminal yürütme kaydı (`kanit/gercek/komut_ve_cikis.txt`).
2. **Olumlu / Olumsuz Test Sonuçları:** Birim testlerin ve negatif sınır kontrollerinin eksiksiz geçtiğini belgeleyen bağımsız test çıktısı (`kanit/gercek/test_sonuclari.txt` ve `kanit/gercek/negatif_kontrol_sonuclari.txt`).
3. **Sınırlı ve Anonim Teknik Rapor:** Kişisel verilerden arındırılmış, 6 sütunun her biri için puan ve bulguları açıkça sunan nihai Markdown kabul raporu (`kanit/gercek/stage2_kalite_kabul_raporu.txt`).

---

### Savunma ve Tespit Kılavuzu
- Kanıt dosyaları `manifest.json` içine SHA-256 bütünlük imzalarıyla kaydedilmeli ve `yedekler/` dizinine tarih damgalı zip olarak arşivlenmelidir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bu 3 kanıt senin mühendislik şerefindir. Yarın bir denetmen geldiğinde 'Ben bu aşamayı tamamladım' dediğinde sana bu 3 kanıtı soracak. Komutun çalıştığını göstereceksin, testlerinin geçtiğini göstereceksin ve resmi raporunu sunacaksın. İşte o zaman hiç kimse senin başarına gölge düşüremez."*

---

## [A02-KALİTE] Aşama Kalite Özeti: Gerçek Kanıtların Temsilî İçeriklerden Ayrımı

### Temel Kavram ve Güvenlik Mekanizması
Siber güvenlik eğitiminde ve denetiminde kavramları zihinde canlandırmak için mimari şemalar ve ASCII çizimleri kullanılır. Ancak bu görseller tek başına asla bir güvenlik başarısının kanıtı olamaz. Gerçek bir kanıt, sistem üzerinde çalışan kodun ürettiği doğrulanabilir çıktıdır.

---

### Soru ve Didaktik Çözüm
**Soru:**  
'Aşama 2 kabul: işletim sistemi temelleri' için yazılı ve görsel anlatımdan farklı olarak hangi gerçek kanıtlar gerekir? Neden yalnız temsili görsel yeterli değildir?

**Didaktik Çözüm:**  
- **Temsilî İçerik Sınırı:** Temsilî görseller (`kanit/temsili/stage2_os_temelleri_mimarisi.txt`) konsepti açıklamak için faydalıdır; ancak altına açıkça `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` uyarısı konmalıdır. Bir görsel sahte olabilir veya elle çizilmiş olabilir.
- **Zorunlu Gerçek Kanıtlar:**
  1. Çalışan yerel simülatör veya doğrulama motoru (`stage2_os_foundations_auditor.py`).
  2. Bağımsız sentetik girdi verisi (`stage2_acceptance_inventory.json`).
  3. Hem olumlu hem de negatif senaryoları kapsayan otomatik test süiti (14/14 PASS).
  4. Kapsam sınırları ve izlenebilir teknik metrikler.
  Yalnızca bu unsurlar bir arada olduğunda gerçek mühendislik doğrulaması sağlanmış olur.

---

### Savunma ve Tespit Kılavuzu
- Temsili ve gerçek kanıtlar dosya sisteminde fiziksel olarak ayrılmalıdır (`kanit/gercek/` ve `kanit/temsili/`).
- Gerçek kanıtlar otomatik olarak betikler tarafından oluşturulmalı, elle düzenlenmemelidir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, resim çizmek sanatçının işidir; ama o resmi arkasında çalışan kodla ve geçen testlerle doğrulamak mühendisin işidir. Biz burada ressam yetiştirmiyoruz; sistemleri savunan, her satır kodunu test eden ve delil üreten siber güvenlik mühendisleri yetiştiriyoruz. Aşama 02'yi bu bilinçle kapattığın için seninle gurur duyuyorum!"*
