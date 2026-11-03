# GÜN 010: Soru & Cevap Bankası — Linux Sanal Makinesine Güvenli Başlangıç

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Soru Sayısı](https://img.shields.io/badge/sorular-3%20Soru-blue?style=flat-square)
![Format](https://img.shields.io/badge/format-4%20B%C3%B6l%C3%BCml%C3%BC%20Kat%C4%B1%20Standart-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G010-SC1): Linux sanal makinesine güvenli başlangıç: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Linux sanal makinesine güvenli başlangıç; lüks bir mücevher dükkanına taşınırken **varsayılan fabrika kilidini ("0000") derhal söküp yerine çift kilitli çelik kasa ve parmak izi okuyucu takma** eylemidir. Birçok kullanıcı Linux (özellikle Kali veya Ubuntu) kurduğunda sistemin doğuştan güvenli olduğunu zanneder; oysa varsayılan ayarlar çoğunlukla test ve geliştirme kolaylığı için tasarlanmıştır (varsayılan kullanıcı adı/parolalar, açık port 22, parolasız root izinleri). Güvenli başlangıç taban çizgisi (Baseline); sistem henüz ağa tam bağlanmadan önce kapıların kilitlenmesini, gereksiz arka bahçe girişlerinin (Telnet, FTP) tuğlayla örülmesini ve yalnızca kriptografik anahtarı olan yetkililerin içeri alınmasını sağlar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Mekanizma 4 ana savunma sütunundan meydana gelir:
* **Kimlik ve Erişim Sınırlandırması (SSH Hardening):** OpenSSH sunucusunda `PermitRootLogin no` ile süper kullanıcının doğrudan hedef alınması engellenir; `PasswordAuthentication no` ile parola kaba kuvvet (brute-force) saldırıları matematiksel olarak saf dışı bırakılır; yalnızca Ed25519/RSA-4096 açık anahtar doğrulaması (`PubkeyAuthentication yes`) kabul edilir.
* **Ayrıcalık Hapsi ve Denetim İzi (Sudoers & PoLP):** Doğrudan root oturumu kilitlenir (`passwd -l root`). Günlük işlemler standart kullanıcı (`UID >= 1000`) ile yürütülür. Yetki yükseltme yalnızca parola zorunlu `sudo` ile yapılır ve her komut `/var/log/auth.log` kütüğüne denetim izi (audit trail) olarak kazınır.
* **Kritik Dosya İzinleri (POSIX Hardening):** Parola özetlerini tutan `/etc/shadow` dosyası `0640 root:shadow` ile kilitlenir; standart kullanıcıların hash çalması engellenir. Kullanıcı hesaplarını tutan `/etc/passwd` dosyası `0644` ile salt-okunur tutulur; yetkisiz UID 0 ekleme saldırıları önlenir.
* **Ağ Kapılarının Kilitlenmesi (UFW Default Deny):** Güvenlik duvarı `default deny incoming` politikası ile yapılandırılır. Açıkça izin verilmeyen hiçbir port dış dünyaya yanıt vermez.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan internette veya yerel ağda yeni açılmış bir Linux sanal makinesi gördüğünde (örneğin Shodan veya Masscan taramasıyla Port 22'yi yakaladığında); saniyede binlerce parola deneyen otomatik araçları (`hydra -L users.txt -P rockyou.txt ssh://<IP>`) çalıştırır. Eğer sistemde `PasswordAuthentication yes` açıksa ve analist `kali:kali` veya `admin:123456` gibi tahmin edilebilir bir şifre bırakmışsa, saldırgan 1 dakikadan kısa sürede sisteme sızar. İkinci adımda `sudo -l` yazıp `NOPASSWD` açığını görürse, GTFOBins istismarı ile (`sudo /bin/bash`) anında sistemin mutlak efendisi (root) haline gelir.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2016 yılında dünya çapında interneti çökerten devasa **Mirai Botnet** saldırısında; yüz binlerce Linux tabanlı IoT cihazı, sunucu ve sanal makine, yalnızca üreticilerin bıraktığı varsayılan `root:admin`, `root:toor` veya `admin:admin` kullanıcı adı ve parolaları sayesinde saniyeler içinde zombi orduya dahil edilmiştir.  
**Çıkarılan Ders:** Bir Linux sanal makinesi kurulduğunda ağa bağlanmadan önce ilk yapılması gereken şey parola kimlik doğrulamasını kapatmak, root SSH girişini yasaklamak ve güvenlik duvarını devreye almaktır.

---

### Soru 2 (G010-SC2): Linux sanal makinesine güvenli başlangıç: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Bir havaalanının uçuş öncesi güvenlik kontrol noktasını (Check-in ve X-Ray) düşün: Girdi olarak yolcunun biletini ve bagajını verirsin; işlem olarak bagajın X-Ray taramasından geçirilmesi, pasaportunun ve vizesinin biyometrik olarak doğrulanmasıdır; beklenen sonuç temiz yolcunun uçağa kabul edilmesidir; negatif kontrol ise bilerek bagajın içine sahte bir ateşli silah konulduğunda dedektörün anında kırmızı alarm verip yolcuyu gözaltına alması ve uçağa binişi durdurmasıdır. Linux laboratuvar motorumuz da işletim sistemi konfigürasyonunu aynı katılıkta tarar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Geliştirdiğimiz `linux_baseline_auditor.py` ve `test_linux_baseline_auditor.py` altyapısı bu 4 adımı şu standartlarda işletir:
* **Girdi (Input):** Linux sanal makinesinin SSH ayarlarını, sudoers politikalarını, dosya izinlerini, umask değerini, UFW durumunu ve çalışan servislerini tanımlayan makinece okunabilir JSON profili (`linux_vm_yapilandirmasi.json`).
* **İşlem (Process):** Denetim motorunun CIS Benchmark Seviye 1 kurallarını adım adım işletmesi:
  1. *SSH Analizi:* `PermitRootLogin` ve `PasswordAuthentication` parametrelerinin kontrolü.
  2. *Yetki Analizi:* `/etc/sudoers` dosyasında `NOPASSWD` varlığının ve root hesap kilidinin denetimi.
  3. *Dosya İzinleri Analizi:* `/etc/shadow` (0640) ve `/etc/passwd` (0644) izinlerinin taranması.
  4. *Güvenlik Duvarı Analizi:* UFW'nin aktifliği ve `default deny incoming` politikasının doğrulanması.
  5. *Servis Hijyeni:* Telnet, RSH, vsftpd gibi şifresiz arka plan servislerinin tespiti.
* **Beklenen Sonuç (Expected Output):** Sertleştirilmiş `LINUX-SEC-01` profili için 100/100 tam puan, 0 açık bulgu, durumun "GÜVENLİ (CIS SEVİYE 1)" olarak onaylanması ve üretime hazır `sshd_config_hardened` ile `sudoers_hardened` şablonlarının üretilmesi.
* **Negatif Kontrol (Negative Control):** Kasıtlı olarak konfigürasyonda `PermitRootLogin=yes`, `NOPASSWD: ALL` veya `/etc/shadow=0644` tanımlandığında; denetleyicinin derhal 35-50 ceza puanı keserek durumu "KRİTİK FELAKET" olarak ilan etmesi ve çıkış kodu 2 (`Exit Code 2`) ile işlemi reddetmesidir.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan düşük yetkili bir kullanıcıyla sistemde gezinirken `ls -l /etc/shadow` komutunu çalıştırır. Eğer izinlerin `0644` (`-rw-r--r--`) olduğunu görürse sevinçten havalara uçar. Dosyayı okur (`cat /etc/shadow`), root kullanıcısının `$6$salt$hash...` dizgesini kopyalar ve kendi GPU kümesinde Hashcat çalıştırarak parolayı kırar. Negatif kontrol testimiz bu açığı daha sistem devreye girmeden engeller.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
Bir teknoloji şirketinde çalışan sistem yöneticisi, otomasyon betiklerinin şifre sormadan çalışabilmesi için Ansible yapılandırmasında `/etc/sudoers.d/deploy` dosyasına `deploy ALL=(ALL) NOPASSWD: ALL` satırını eklemiştir. Şirketin web sitesindeki bir dosya yükleme (File Upload) açığından yararlanan bir saldırgan, `deploy` kullanıcısı adına bir web kabuğu çalıştırmış ve saniyeler içinde `sudo -i` komutuyla tüm veri tabanı sunucusunun kök (root) kontrolünü ele geçirmiştir.  
**Çıkarılan Ders:** Parolasız sudo yetkisi (`NOPASSWD: ALL`), bir sisteme vurulabilecek en büyük darbedir. Otomasyon için gerekiyorsa sadece tek bir sınırlı betiğe parola muafiyeti verilmeli; genel kullanıcılara asla sınırsız NOPASSWD tanımlanmamalıdır.

---

### Soru 3 (G010-SC3): 'Linux sanal makinesine güvenli başlangıç' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Risk, su geçirmez bir denizaltının torpido kapağını içeriden açıp unutmaya benzer. Denizaltının gövdesi (Linux çekirdeği) devasa basınca dayanacak kadar sağlamdır; ancak torpido kapağındaki küçük bir dikkatsizlik (açık bırakılmış bir Telnet portu veya root SSH izni) tüm denizaltının saniyeler içinde suyla dolup batmasına sebep olur. Linux ortamında risk; yöneticinin "sonra düzeltirim" diyerek geçici olarak açtığı kolaylıkların sistemde kalıcı açık kapılara dönüşmesinden doğar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
* **Risk Nasıl Oluşur?**
  1. *Açık Root Kapısı:* `PermitRootLogin yes` ve zayıf parolalarla internete bağlı SSH servisi.
  2. *Kontrolsüz Yetki Dağıtımı:* `/etc/sudoers` dosyasında `NOPASSWD: ALL` izni verilmesi.
  3. *Gevşek İzinler (Over-Permissive Files):* `/etc/shadow` dosyasının okunabilir, `/etc/passwd` dosyasının yazılabilir bırakılması.
  4. *Ağ Kalkanının Yokluğu:* Güvenlik duvarının kapalı bırakılması ve şifresiz servislerin (Telnet, RSH) ağda dinlemede kalması.
* **Risk Nasıl Tespit Edilir?**
  * SSH Konfigürasyon Denetimi: `sshd -T | grep -E "permitrootlogin|passwordauthentication"` komutuyla canlı ayarların dökülmesi.
  * Sudo İzin Taraması: `sudo -l` komutuyla kullanıcının parolasız çalıştırabileceği GTFOBins ikililerinin taranması.
  * İzin Denetimi: `stat -c "%a %n" /etc/shadow /etc/passwd` komutuyla dosya izinlerinin sayısal olarak kontrol edilmesi.
  * Port ve Servis Taraması: `ss -tulpn` veya `netstat -tuln` komutlarıyla dinleyen portların izlenmesi.
* **Hangi Kontrolle Önlenir?**
  * *NIST CSF PR.AC (Erişim Kontrolü):* SSH anahtarlı kimlik doğrulama, root giriş yasağı, parola zorunlu sudo politikası.
  * *NIST CSF PR.DS (Veri Güvenliği):* `/etc/shadow` dosyasının `0640` ve `umask 027` ile korunması.
  * *NIST CSF PR.PT (Koruyucu Teknoloji):* UFW ile `default deny incoming` politikası uygulanması ve güvensiz servislerin sistemden kaldırılması (`apt purge telnetd`).

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan bir Linux sunucusuna sınırlı bir hesapla sızdıktan sonra GTFOBins kütüphanesini tarar. Eğer yönetici `sudo /usr/bin/vim` komutuna parolasız izin vermişse, saldırgan vim'i açar ve komut satırına `:!/bin/bash` yazar. Vim root yetkisiyle çalıştığı için fırlatılan kabuk da anında root olur. Savunmacı ise "ben sadece bir metin düzenleyiciye izin verdim" diyerek şaşkınlık içinde kalır.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2018 yılında Tesla'nın AWS Kubernetes kümesine yapılan saldırıda; saldırganların internete açık ve şifresiz bir Kubernetes kontrol paneline sızdığı, buradan bir Linux poduna ulaştığı ve pod içindeki aşırı geniş sudo izinlerini kullanarak tüm AWS erişim anahtarlarını çalıp kripto para madenciliği (Cryptojacking) başlattığı ortaya çıkmıştır.  
**Çıkarılan Ders:** Sanal makineler veya konteynerler fark etmeksizin; her Linux ortamı ilk açıldığı anda en az ayrıcalık ilkesiyle (PoLP) kilitlenmeli, varsayılan açık kapılar kapatılmalı ve yetkilendirmeler katı sınırlarla sınırlandırılmalıdır.
