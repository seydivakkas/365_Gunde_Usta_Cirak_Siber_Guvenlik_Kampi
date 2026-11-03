# GÜN 023: Soru & Cevap — Linux Terminali ve Kabuk

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu soru-cevap dokümanı Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## G023-SC1: Linux terminali ve kabuk: Temel mekanizmayı ve güvenlik önemini açıkla.

### Temel Mekanizma ve Güvenlik Önemi
Linux işletim sisteminde kabuk (Bash, Sh, Zsh), kullanıcı veya betik tarafından girilen komut satırını sözcüksel olarak ayrıştıran (tokenization), değişkenleri genişleten, boru hatları (`|`) ve yönlendirmeleri (`>`, `<`) kuran ve çekirdeğe süreç başlatma çağrıları (`fork`, `execve`) gönderen bir komut yorumlayıcısıdır. Her kabuk oturumu çekirdek düzeyinde mevcut bir çalışma dizini (`cwd`) bağlamına sahiptir.

Güvenlik açısından kabuğun en kritik mekanizması **yol çözümleme (path resolution)** sürecidir:
- **Mutlak Yol (Absolute Path):** Kök dizin (`/`) ile başlar (`/etc/passwd`, `/var/log/auth.log`). Deterministiktir; sürecin o anda hangi dizinde olduğundan bağımsız olarak her zaman aynı hedefi gösterir.
- **Göreli Yol (Relative Path):** Çalışma dizinine (`pwd`) bağımlı olarak çözümlenir (`./script.sh`, `cat app.conf`, `../../etc/shadow`).

**Güvenlik Tehlikesi:** Bir sistem betiğinde veya zamanlanmış görevde (cron job) göreli yol kullanıldığında, sürecin çalışma dizini beklenmeyen veya saldırganın yazma yetkisine sahip olduğu bir alana (örn. `/tmp` veya `/var/tmp`) kayarsa, komut orijinal sistem dosyası yerine saldırganın bıraktığı sahte bir konfigürasyonu veya truva atı betiğini hedefler (CWE-426 Untrusted Search Path). Aynı şekilde `../../` karakter dizileriyle dizin aşımı (CWE-22 Path Traversal) yapılarak kısıtlı alanların dışındaki hassas dosyalara erişilebilir.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Sanal Linux dosya sistemi haritası (`ornek_veri/shell_virtual_filesystem.json`) ve yol güvenlik kuralları (`ornek_veri/shell_security_rules.json`).
- **İşlem:** `linux_shell_security_simulator.py` aracı üzerinden `resolve_path()` ve `audit_path_traversal()` fonksiyonları çalıştırılır.
- **Beklenen Çıktı:** Göreli yolların çalışma dizini bağlamına göre mutlak yola dönüştürüldüğü, standart yolların `TEMIZ` onaylandığı gözlenir.
- **Negatif Kontrol:** Girdide `../../etc/shadow` gibi dizin aşımı kalıbı sağlandığında, simülatörün `YUKSEK` risk seviyesinde CWE-22 ihlali üretmesi doğrulanır (`test_12_goreli_yol_ve_path_traversal_tespiti`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Otomasyon betiklerinin yanlış çalışma dizininde tetiklenmesi sonucu kritik olmayan sahte dosyaları işlemesi veya saldırganın manipüle ettiği göreli yollar üzerinden yetki yükseltmesi (LPE).
- **Tespit Sinyali:** `auditd` loglarında bir sürecin `/tmp` veya `/dev/shm` altından beklenmeyen ikilileri yürütmesi; `ps -ef` veya `lsof -p <PID>` ile sürecin `cwd` dizininin anormal görünmesi.
- **Savunma Kontrolü:** Tüm üretim ve yönetim betiklerinde istisnasız mutlak yolların kullanılması; betik başlarında `set -euo pipefail` katı kurallarının tanımlanması; `PATH` değişkeninin mutlak sistem dizinleriyle sınırlandırılması.

### Etik ve Yasal Sınırlar
Kabuk komutları ve yol analizi denetimleri yalnızca izin verilen test sistemlerinde ve adli analiz laboratuvarlarında icra edilmelidir. Başka kullanıcılara ait oturumlarda çalışma dizini veya ortam değişkenlerini manipüle etmek bilişim sistemine müdahale suçunu oluşturur (TCK Madde 244).

---

## G023-SC2: Linux terminali ve kabuk: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

### Temel Mekanizma ve Güvenlik Önemi
Bağımsız laboratuvar uygulaması, harici kütüphanelere ve öncül günlere bağımlı olmaksızın, bir güvenlik uzmanının Linux terminalinde gerçekleştirdiği ilk keşif (reconnaissance) ve adli inceleme iş akışını 5 temel POSIX komutu (`pwd`, `ls`, `cd`, `cat`, `head`) üzerinden modeller. Bu komutlar, dosya hiyerarşisi üzerinde gezinmeyi, erişim haklarını denetlemeyi ve log kayıtlarını incelemeyi sağlar.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:**
  1. `shell_virtual_filesystem.json`: `/home/analyst`, `/var/log`, `/etc`, `/tmp` dizinlerini ve `auth.log`, `passwd`, `notes.txt` dosyalarını içeren sanal dosya sistemi.
  2. `shell_security_rules.json`: Komut doğrulama ve yol kuralları.
- **İşlem:**
  `linux_shell_security_simulator.py` motoru başlatılır ve şu sıralı adımlar işletilir:
  1. `pwd`: Başlangıç dizini doğrulanır (`/home/analyst`).
  2. `ls`: Mevcut dizindeki öğeler ve izinler listelenir (`notes.txt` - `0600`).
  3. `cd /var/log`: Günlük kayıtlarının bulunduğu dizine geçilir.
  4. `pwd`: Yeni dizinin `/var/log` olduğu teyit edilir.
  5. `head auth.log -n 3`: Kimlik doğrulama logunun ilk 3 satırı okunur.
  6. `cat /home/analyst/notes.txt`: Analist güvenlik notlarının tam metni okunur.
  7. `head /etc/passwd -n 2`: Kullanıcı hesap dosyasının ilk 2 satırı süzülür.
- **Beklenen Çıktı:**
  `kanit/gercek/kabuk_komut_analiz_ciktisi.txt` dosyası üretilir. Çıktıda her adımın başarıyla tamamlandığı, çalışma dizininin hatasız güncellendiği ve log/yapılandırma satırlarının eksiksiz çekildiği gözlenir.
- **Negatif Kontrol:**
  1. Var olmayan bir dizine `cd` yapılmak istendiğinde `FileNotFoundError` fırlatılması (`test_04`).
  2. Dizin yoluna `cat` komutu verildiğinde `IsADirectoryError` üretilmesi (`test_10`).
  3. Var olmayan dosya istendiğinde `FileNotFoundError` fırlatılması (`test_09`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Terminal üzerinden yapılan dikkatsiz operasyonlarda büyük dosyaların `cat` ile açılması sonucu terminalin kilitlenmesi veya yetkisiz dizinlere girilerek hassas dosyaların ifşa olması.
- **Tespit Sinyali:** Kullanıcı kabuk geçmişinde (`~/.bash_history`) yetkisiz dizinlere geçiş veya hassas dosyalara (`/etc/shadow`) yönelik başarısız erişim denemeleri.
- **Savunma Kontrolü:** Kabuk geçmişinin korunması (`HISTCONTROL=ignoredups`, `chattr +a ~/.bash_history`), kritik dosyalara yalnızca `sudo` ve `auditd` denetiminde erişim izni verilmesi.

### Etik ve Yasal Sınırlar
Laboratuvar akışında incelenen log ve kimlik verileri yapay test ortamında simüle edilmiştir. Gerçek ortamlarda çalışanların veya kullanıcıların özel günlüklerinin izinsiz okunması KVKK ve kişisel gizlilik ihlali oluşturur.

---

## G023-SC3: 'Linux terminali ve kabuk' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

### Temel Mekanizma ve Güvenlik Önemi
Linux kabuk ortamında güvenlik riski üç temel faktörden kaynaklanır:
1. **Gereksiz İzinler ve Güvensiz PATH Değişkeni (CWE-426):** `PATH` ortam değişkeninde `.` (mevcut dizin) veya `/tmp` gibi dünya çapında yazılabilir (world-writable) dizinlerin bulunması.
2. **Yanlış Yapılandırma ve Güvensiz Betik Yazımı:** Betiklerde `set -e` veya katı değişken kontrolü kullanılmaması; göreli yollarla harici ikili çağrılması.
3. **Komut Enjeksiyonu ve Kaçış Karakterleri (Command Injection):** Kullanıcı girdilerinin kabukta filtrelenmeden doğrudan `eval`, `system()` veya ters tırnak (backticks `` ` ``) içine sokulması.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Zafiyetli PATH değişkeni (`/usr/bin:/bin:.`) ve şüpheli göreceli yollar içeren test senaryosu.
- **İşlem:** `audit_path_environment()` fonksiyonu çağrılarak arama dizinleri taranır.
- **Beklenen Çıktı:** 
  - PATH değişkenindeki `.` için: `KRITIK` risk ve "Mevcut dizindeki truva atı ikilisinin sistem komutu yerine çalıştırılması (CWE-426)" uyarısı üretilir.
  - Önleme önerisi: "PATH değişkeninden '.' ve '/tmp' dizinlerini kaldırın."
- **Negatif Kontrol:** Yalnızca güvenli sistem dizinlerini (`/usr/local/bin:/usr/bin:/bin`) içeren bir PATH dizesinde risk seviyesinin `GUVENLI` dönmesi doğrulanır (`test_13`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk Senaryosu:** Root kullanıcısının PATH değişkeninin başında veya sonunda `.` vardır. Bir saldırgan `/tmp` içine kötü niyetli bir `ls` kabuk betiği yerleştirir. Sistem yöneticisi inceleme yapmak için `/tmp` dizinine girip `ls` yazdığında, sistem gerçek `/bin/ls` yerine saldırganın betiğini root yetkisinde çalıştırır.
- **Tespit Sinyalleri:**
  - `echo $PATH` komutunda iki nokta üst üste yan yana (`::`) veya `.` görülmesi.
  - Güvenlik tarayıcılarında (Lynis, CIS-CAT) "PATH contains current working directory" uyarısı.
- **Savunma Kontrolleri:**
  - **En Az Ayrıcalık ve Temiz PATH:** `/etc/environment` ve `/etc/profile` dosyalarında PATH'in katı olarak `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` şeklinde sabitlenmesi.
  - **Geri Alınabilir Yapılandırma:** Kullanıcı `.bashrc` ve `.profile` dosyalarının yetkisiz düzenlemelere karşı `chmod 0644` ile korunması ve değişikliklerin FIM (AIDE) ile izlenmesi.

### Etik ve Yasal Sınırlar
PATH manipülasyonu veya kabuk ortam değişkeni zehirleme (environment poisoning) teknikleri yalnızca sızma testi sözleşmesi kapsamındaki yetkili güvenlik tatbikatlarında test edilmelidir; yetkisiz ortamlarda bu yöntemleri kullanmak suç teşkil eder.
