# GÜN 020: Soru & Cevap — Linux Dosya Ağacı ve FHS

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu soru-cevap dokümanı Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## G020-SC1: Linux dosya ağacı ve FHS: Temel mekanizmayı ve güvenlik önemini açıkla.

### Temel Mekanizma ve Güvenlik Önemi
Linux ve POSIX uyumlu işletim sistemlerinde depolama mimarisi, Windows'taki çoklu sürücü harfleri (`C:`, `D:`) modelinden farklı olarak tek bir kök dizine (`/`) bağlanan hiyerarşik bir ağaç yapısına dayanır. Filesystem Hierarchy Standard (FHS 3.0), bu hiyerarşi içerisindeki dizinlerin yerleşimini ve amacını tanımlar:
- `/etc`: Sistem genelindeki statik yapılandırma dosyalarını (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) barındırır.
- `/var`: Loglar (`/var/log`), posta kuyrukları (`/var/spool`) ve geçici veritabanı dosyaları gibi dinamik ve boyutu sürekli değişen verileri depolar.
- `/home`: Normal sistem kullanıcılarının kişisel dosyaları ve ortam yapılandırmaları için ayrılmıştır.
- `/tmp`: Tüm süreçlerin ve kullanıcıların geçici tampon dosyalarını yazabildiği ortak alandır.
- `/dev`: Çekirdek ile donanım/sanal aygıtlar arasındaki köprü olan aygıt düğümlerini (`/dev/sda`, `/dev/urandom`) içerir.
- `/proc`: Çekirdeğin bellek durumunu ve çalışan süreç bilgilerini sunan sözde dosya sistemidir (procfs).

Güvenlik açısından FHS'nin önemi, **izolasyon ve en az ayrıcalık ilkesinin** fiziksel veya mantıksal disk bölümlerine yansıtılmasını sağlamasıdır. Örneğin `/var` ayrı bir disk bölümü yapılmadığında meydana gelen bir log taşkını kök dosya sistemini doldurarak tüm sistemi kilitleyebilir. Aynı şekilde `/tmp` üzerinde Sticky Bit (`+t`) ve `noexec` bulunmaması saldırganlara doğrudan kod yürütme ve dosya gaspı imkanı verir.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** FHS uyumlu bir sistemde dizin izinleri ve mount parametreleri haritası (`ornek_veri/linux_fhs_sample_map.json`).
- **İşlem:** `linux_fhs_hierarchy_auditor.py` aracı çalıştırılarak FHS çekirdek dizinlerinin varlığı, izinleri ve mount parametreleri denetlenir.
- **Beklenen Çıktı:** 6 zorunlu dizinin (`/etc`, `/var`, `/home`, `/tmp`, `/dev`, `/proc`) eksiksiz tanımlandığı, `/tmp` üzerinde Sticky Bit'in etkin olduğu ve çıktıda `DOGRULANDI` durumunun üretildiği gözlenir.
- **Negatif Kontrol:** `/var` dizini yapılandırmadan silindiğinde sistemin bunu kritik bir ihlal olarak yakalaması ve `fhs_karsilandi_mi: false` üretmesi test edilir (`test_06_fhs_eksik_dizin_negatif_kontrol`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** FHS standartlarına uyulmaması sonucu statik ve dinamik verilerin ayrıştırılamaması, yetkisiz kullanıcıların kritik sistem alanlarına dosya bırakması veya log taşması sonucu DoS oluşması.
- **Tespit Sinyali:** SIEM veya FIM üzerinde `/etc` altında beklenmeyen dosya oluşturma olayları, `/tmp` altında izin verilen dosya türleri dışındaki ELF ikililerinin tespiti veya `df -h` üzerinde `/` bölümünün %100 doluluğa ulaşması.
- **Savunma Kontrolü:** Kök (`/`), `/home`, `/var`, `/var/log` ve `/tmp` için bağımsız LVM bölümleri oluşturulması; `/etc/fstab` üzerinde `/tmp` için `nodev,nosuid,noexec` mount parametrelerinin uygulanması.

### Etik ve Yasal Sınırlar
Dosya sistemi hiyerarşisi denetimleri ve FHS taramaları yalnızca yetkilendirilmiş sistemlerde, güvenlik denetimi sözleşmeleri ve ISO 27001 kapsamındaki iç kontrol prosedürlerine uygun olarak yürütülmelidir. Üçüncü şahıslara ait sistemlerde yetkisiz dosya ağacı keşfi yasal olarak suç teşkil eder (TCK Madde 243).

---

## G020-SC2: Linux dosya ağacı ve FHS: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

### Temel Mekanizma ve Güvenlik Önemi
Bağımsız güvenlik laboratuvarı yaklaşımı, dış kütüphanelere ve öncül günlerin kalıntılarına bağımlı olmaksızın, doğrulanabilir bir girdi ile tekrarlanabilir bir analiz gerçekleştirmeyi amaçlar. FHS 3.0 standardına göre en az 6 çekirdek dizinin (`/etc`, `/var`, `/home`, `/tmp`, `/dev`, `/proc`) izinleri, sahiplikleri ve kullanım amaçları sistem güvenliğini doğrudan etkiler. Laboratuvar ortamında bu hiyerarşi bir girdi matrisi ile modellenir ve denetim motoru tarafından kurallara göre değerlendirilir.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** 
  1. `ornek_veri/linux_fhs_sample_map.json`: 6 çekirdek FHS dizini, `/tmp` ve `/home` mount parametreleri, `/etc/shadow` ve `/etc/sudoers` dosya kayıtları.
  2. `ornek_veri/linux_fhs_security_baseline.json`: CIS Linux Benchmark 1.1 ve 6.1 kuralları (zorunlu dizinler, sticky bit şartı, noexec/nosuid bayrakları, 0640 shadow izni).
- **İşlem:**
  `LinuxFhsHierarchyAuditor` sınıfı başlatılır, `denetim_raporu_olustur()` metodu ile FHS doğrulaması, sticky bit kontrolü, mount sertleştirme analizi ve kritik dosya izin denetimi icra edilir.
- **Beklenen Çıktı:**
  6 dizinin tamamı için `DOGRULANDI` üretilir. `/tmp` için `Sticky Bit: True` ve `Mount: nodev,nosuid,noexec` tam puan alır. `/etc/shadow` için 0640 izni `GUVENLI_SHADOW` olarak işaretlenir. Genel sonuç `TEMIZ` döner.
- **Negatif Kontrol:**
  1. `/etc/shadow` dosyasının izni `0644` (herkes okuyabilir) yapıldığında denetleyicinin `KRITIK` seviyeli CWE-732 ihlali üretmesi (`test_12`).
  2. `/tmp` dizininden `noexec` parametresi kaldırıldığında `YUKSEK` risk üretilmesi (`test_10`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Güvensiz dosya izinleri (`0777` veya `0666`) nedeniyle yetkisiz kullanıcıların kritik sistem yapılandırmalarını değiştirmesi veya hassas şifrelenmiş kimlik bilgilerini okuması.
- **Tespit Sinyali:** `find / -perm -0002 -type f` komutuyla dünya çapında yazılabilir dosyaların listelenmesi; AIDE/Tripwire bütünlük denetiminde izin değişiklik alarmları.
- **Savunma Kontrolü:** `chmod 0640 /etc/shadow`, `chmod 0440 /etc/sudoers` ve `chmod 1777 /tmp` komutları ile izinlerin sıkılaştırılması; CI/CD pipeline'larında ve sunucu provizyon betiklerinde otomatik denetim çalıştırılması.

### Etik ve Yasal Sınırlar
Test senaryolarında kullanılan örnek zafiyetli konfigürasyonlar kontrollü bellek/dosya nesneleri üzerinde simüle edilmiştir. Canlı kurumsal ortamlarda izin testleri yapılırken mevcut çalışan servislerin erişim haklarının kesintiye uğramaması için yetkilendirilmiş bakım pencerelerinde çalışılmalıdır.

---

## G020-SC3: 'Linux dosya ağacı ve FHS' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

### Temel Mekanizma ve Güvenlik Önemi
Linux dosya ağacındaki riskler üç ana kaynaktan doğar:
1. **Gereksiz ve Gevşek İzinler:** Dizin ve dosyalara gereğinden fazla okuma/yazma/çalıştırma hakkı verilmesi (`/etc/shadow`'un `0644` olması, `/tmp` dizininde Sticky Bit'in unutulması `0777`).
2. **Hatalı Mount Yapılandırması:** `/tmp` veya `/home` gibi kullanıcıların dosya yazabildiği bölümlerin `noexec` ve `nosuid` olmaksızın bağlanması.
3. **Fiziksel Bölümlendirme Eksikliği:** Tüm sistemin tek bir kök (`/`) bölümüne kurulması ve `/var/log` gibi log alanlarının sınırlandırılmaması.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Zafiyetli test senaryoları içeren JSON girdisi (Sticky bitsiz `/tmp`, eksik bayraklı `/home`, izinleri gevşetilmiş `/etc/shadow`).
- **İşlem:** `linux_fhs_hierarchy_auditor.py` motoru çalıştırılarak güvenlik ihlalleri taranır.
- **Beklenen Çıktı:** Her bir zafiyet için risk seviyesi (`KRITIK`, `YUKSEK`), ilgili CWE referansı (`CWE-732`, `CWE-377`) ve uygulanması gereken düzeltme önerisi açıkça raporlanır.
- **Negatif Kontrol:** Hatalı veya geçersiz dosya yolu verildiğinde aracın çökmeyip `FileNotFoundError` üreterek güvenli biçimde sonlanması doğrulanır (`test_04`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk Analizi:**
  - `/tmp` üzerinde Sticky Bit olmaması: Herhangi bir yerel kullanıcı başka bir kullanıcının veya servisin geçici dosyasını ezebilir veya silebilir (CWE-377 Geçici Dosya Yarış Durumu).
  - `/home` üzerinde `nosuid` olmaması: Saldırgan kendi ev dizininde root yetkisi veren bir SUID ikilisi derleyip saklayabilir.
  - `/etc/shadow` üzerinde world-readable (`0644`): Sisteme giriş yapmış herhangi bir düşük yetkili kullanıcı veya web servisi parola hash'lerini okuyup Hashcat/John the Ripper ile kırabilir.
- **Tespit Sinyalleri:**
  - `auditd` loglarında `/etc/shadow` erişim denemeleri (`ausearch -k shadow_access`).
  - `find / -perm -4000` komutu ile sistemdeki tüm SUID dosyalarının periyodik olarak taranması ve envanter dışı dosyaların tespiti.
- **Savunma Kontrolleri:**
  - **En Az Ayrıcalık (Least Privilege):** Tüm sistem dosyaları için CIS Benchmark uyumlu katı izinler (`0640`, `0440`, `1777`).
  - **Mount Sertleştirmesi:** `/etc/fstab` içinde `tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0` kaydı oluşturulması.
  - **Kritik Dizin İzolasyonu:** `/home`, `/var`, `/var/log`, `/tmp` için ayrı disk bölümlerinin tanımlanması.

### Etik ve Yasal Sınırlar
Kritik sistem dosyaları (`/etc/shadow`, `/etc/sudoers`) üzerinde gerçekleştirilen denetimler kurumsal onay ve güvenlik politikalarına tabi olmalıdır. İzinsiz gözetleme veya sızdırılan hash'lerin kırılması teşebbüsü hukuki yaptırımlara tabidir.
