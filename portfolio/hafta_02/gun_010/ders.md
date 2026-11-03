# GÜN 010: Linux Sanal Makinesine Güvenli Başlangıç
**Aşama 01: Temel Kavramlar ve Tehdit Ortamı | Hafta 02: Güvenli Ortam ve Temel Altyapı**

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Süre](https://img.shields.io/badge/s%C3%BCre-90%20dakika-blue?style=flat-square)
![Seviye](https://img.shields.io/badge/seviye-Temel%20%2F%20Orta-orange?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, arkana yaslan ve derin bir nefes al. Bugün siber güvenlik evreninin ana vatanına, hacker'ların, savunmacıların ve bulut altyapılarının ortak dili olan **Linux** topraklarına ayak basıyoruz.

Sana bir soru: *"Dünyadaki web sunucularının, süper bilgisayarların, siber güvenlik dağıtımlarının (Kali, Parrot, REMnux) ve bulut konteynerlerinin kalbinde ne çalışıyor?"*
Cevap tartışmasız **Linux**'tur!

Fakat siber güvenliğe yeni başlayanların düştüğü en trajik yanılgı şudur:
*"Ben sanal makineye Kali Linux veya Ubuntu kurdum, ISO'yu çalıştırdım, artık güvendeyim!"*
Evlat, bu düşünce neye benzer biliyor musun?
**Yeni taşındığın lüks bir villanın çelik kapısındaki şifreli kilidi "0000" bırakıp, evin anahtarını da kapının önündeki paspasın altına koymaya benzer!**

Sen o villanın içine dünyanın en gelişmiş güvenlik kameralarını, alarm sistemlerini (Nmap, Metasploit, Wireshark) koysan ne yazar? Kapıyı kilitlemediğin sürece hırsız elini kolunu sallayarak içeri girer, senin silahlarını alıp seni rehin alır!

Varsayılan bir Linux kurulumunda:
1. Parola ya `kali:kali`'dir ya da `toor`'dur. İnternetteki botnet'ler 30 saniye içinde bu parolayı kaba kuvvetle (brute-force) kırar.
2. SSH servisi doğrudan `root` kullanıcısının parola ile girişine açıktır (`PermitRootLogin yes`).
3. Tembellik olsun diye `/etc/sudoers` dosyasına `kullanici ALL=(ALL) NOPASSWD: ALL` yazılır; yani sıradan bir web kabuğu (web shell) alan saldırgan tek tuşla makinenin kralı (root) olur.
4. Güvenlik duvarı (`ufw`) varsayılan olarak kapalıdır; tüm portlar açıktadır.

Bugün masamızda, sıfırdan kurduğumuz bir Linux sanal makinesini **CIS (Center for Internet Security) Benchmark Seviye 1** standartlarında kurşun geçirmez bir kaleye dönüştürmek var. SSH'ı parola saldırılarına kapatmayı, dosya izinlerinin namusunu korumayı, sudoers dosyasını doğru yapılandırmayı ve UFW güvenlik duvarıyla kapıları kilitlemeyi öğreneceksin.

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### A. Linux Kullanıcı ve Yetki Hiyerarşisi: En Az Ayrıcalık İlkesi

Linux işletim sisteminde güvenlik, kullanıcı kimlik numaraları (**UID - User ID**) üzerine inşa edilmiştir:
* **UID 0 (`root` - Süper Kullanıcı):** Linux'un mutlak hükümdarıdır. Sistemde açamayacağı dosya, silemeyeceği çekirdek modülü veya durduramayacağı süreç yoktur. `rm -rf --no-preserve-root /` komutunu versen kendi bacağını keser ve sistemi intihara sürükler.
* **Sistem Kullanıcıları (UID 1 - 999):** `www-data`, `nobody`, `sshd`, `daemon` gibi hesaplardır. Bu hesapların amacı, çalışan servisleri (örneğin Apache veya SSH) kısıtlı bir yetki kafesine hapsetmektir. Apache hacklense bile saldırgan sadece `www-data` yetkisi alır, sistemi hemen yok edemez.
* **Standart Kullanıcılar (UID >= 1000):** Senin günlük çalıştığın hesaplardır (örneğin `analist`). Bu hesaplar yalnızca kendi ev dizinlerinde (`/home/analist`) tam yetkiye sahiptir; sistem dosyalarını (`/etc/`, `/bin/`, `/sbin/`) değiştiremezler.

**Hocanın Altın Kuralı:** Asla ve asla günlük işlemlerini `root` kullanıcısı ile yürütmeyeceksin! Her zaman standart bir kullanıcı ile oturum açacak, yönetimsel bir işlem yapman gerektiğinde **`sudo` (Superuser Do)** mekanizmasını kullanacaksın.

#### Neden Doğrudan Root Değil de `sudo`?
1. **Denetim İzi (Audit Trail):** Root ile oturum açtığında kimin ne yaptığı belli olmaz. `sudo` kullandığında ise her komut `/var/log/auth.log` (Debian/Ubuntu) veya `/var/log/secure` (RedHat) dosyasına tarih, saat, kullanıcı adı ve çalıştırılan komut ile birlikte kazınır:
   `Oct 27 10:15:02 lab-vm sudo: analist : TTY=pts/0 ; PWD=/home/analist ; USER=root ; COMMAND=/usr/bin/apt update`
2. **Kaza Önleme:** Her komutun başına `sudo` yazmak analiste zihinsel bir duraklama verir: *"Ben şu an sistemi etkileyecek kritik bir komut çalıştırıyorum!"*

### B. OpenSSH Sunucusu Sertleştirme (`/etc/ssh/sshd_config`)

Linux makinelerine uzaktan güvenli yönetim sağlayan **OpenSSH** servisi, internete bağlandığı anda botnet'lerin ve otomatik tarayıcıların ana hedefi haline gelir. CIS standartlarına göre bir SSH sunucusunda yapılması zorunlu 5 sertleştirme kuralı vardır:

```
+-----------------------------------------------------------------------------+
|               OPENSSH GÜVENLİK SERTLEŞTİRME PARAMETRELERİ                   |
+-----------------------------------------------------------------------------+

 1. PermitRootLogin no
    -> Root kullanıcısının SSH üzerinden doğrudan giriş yapmasını KESİNLİKLE ENGELLER.
    -> Saldırgan root kullanıcısının parolasını bilse bile kapıdan içeri giremez!

 2. PasswordAuthentication no
    -> Parola ile kimlik doğrulamayı tamamen kapatır.
    -> Sözlük saldırıları (Hydra, Medusa, RockYou) etkisiz hale gelir.

 3. PubkeyAuthentication yes
    -> Yalnızca kriptografik açık anahtar (SSH Public Key - Ed25519/RSA 4096) ile
       girişe izin verir. Matematiksel olarak kaba kuvvetle kırılması imkansızdır.

 4. Port 2222
    -> Standart port 22 yerine standart dışı bir porta taşınır.
    -> İnternetteki otomatik tarayıcıların (Shodan, Masscan) log kirliliğini %95 azaltır.

 5. MaxAuthTries 3
    -> Tek bir bağlantı oturumunda denenebilecek kimlik doğrulama sayısını 3 ile sınırlar.
```

### C. Kritik Sistem Dosyası İzinleri ve `/etc/shadow` Kalkanı

Linux dosya sisteminde her dosyanın bir sahibi (Owner), grubu (Group) ve diğer kullanıcılar (Others) için erişim izinleri vardır:
* **`/etc/passwd` (0644 - `rw-r--r--`):** Sistemdeki kullanıcı adlarını, varsayılan kabuklarını ve ev dizinlerini tutar. Herkes tarafından okunabilir olmalıdır; ancak **asla ve asla başkaları tarafından yazılamaz (0777 yapılamaz)**! Eğer bu dosyaya yazma izni verirsen, saldırgan içine `hacker:x:0:0::/root:/bin/bash` satırını ekleyerek anında şifresiz bir root hesabı oluşturur!
* **`/etc/shadow` (0640 - `rw-r-----` Sahip: `root:shadow`):** Sistem kullanıcılarının tuzlanmış (salted) parola özetlerini (SHA-512, Yescrypt) saklar. Bu dosyanın izinleri gevşetilirse (örneğin 0644 yapılırsa), sistemdeki herhangi bir kısıtlı kullanıcı veya zararlı betik tüm parola hash'lerini çeker ve çevrimdışı (offline) olarak `hashcat` veya `john the ripper` ile kırar.
* **`umask 027` (Kullanıcı Dosya Oluşturma Maskesi):** Varsayılan `umask 022` yerine `027` kullanıldığında; yeni oluşturulan dosyalar `0640` (`rw-r-----`), dizinler ise `0750` (`rwxr-x---`) izinleriyle doğar. Diğer kullanıcılar (Others) senin dosyalarını ne görebilir ne de okuyabilir.

### D. `/etc/sudoers` ve "NOPASSWD: ALL" Felaketi

`/etc/sudoers` dosyası, hangi kullanıcının hangi süper komutları çalıştırabileceğini belirler.
Birçok acemi analist şifre girmekten sıkıldığı için şu satırı ekler:
`analist ALL=(ALL:ALL) NOPASSWD: ALL`  # <--- SİBER FELAKET!

Bu satır ne anlama gelir?
Eğer sistemdeki `analist` kullanıcısının web tarayıcısı hacklenirse, bir phising e-postasıyla arka kapı (reverse shell) açılırsa veya bir web uygulaması (ör. DVWA, Juice Shop) üzerinden komut enjeksiyonu yapılırsa; saldırgan terminale yalnızca şunu yazar:
`sudo su`
Ve sistem hiçbir parola sormadan saldırgana anında tam **root** yetkisi verir! GTFOBins sitesinde listelenen yüzlerce ikili dosya (`vim`, `find`, `awk`, `less`) parolasız sudo izni olduğunda anında kök kabuğu fırlatır.

**Doğru Sudoers Yapılandırması:**
Parolasız kural KESİNLİKLE YASAKTIR. Yalnızca `%sudo ALL=(ALL:ALL) ALL` tanımlanmalı ve her kritik işlemde kullanıcının kendi parolasını girmesi şart koşulmalıdır.

### E. Güvenlik Duvarı (UFW) ile Varsayılan Reddetme (Default Deny)

Linux makinelerinde çalışan servisler ağ kartının portlarını dinler. Güvenlik duvarının ilk kuralı şudur:
**"Açıkça izin verilmeyen her şey yasaktır (Default Deny)!"**

```bash
# 1. Varsayılan politikaları belirle
sudo ufw default deny incoming   # Dışarıdan gelen her şeyi reddet
sudo ufw default allow outgoing  # İçeriden dışarıya çıkışa izin ver

# 2. Yalnızca sertleştirilmiş SSH portunu ve güvenilir yerel ağı aç
sudo ufw allow from 192.168.56.0/24 to any port 2222 proto tcp

# 3. Güvenlik duvarını devreye al
sudo ufw enable
```

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### 🔴 Saldırganın Gözü (Offensive Perspective)

Bir saldırgan ağda yeni bir Linux makine keşfettiğinde (örneğin `nmap -sV -p- <Hedef>`):
1. **Port 22 SSH Taraması:** Port 22 açıksa derhal `hydra -L users.txt -P rockyou.txt ssh://<Hedef>` çalıştırarak `root:root`, `admin:admin`, `kali:kali` gibi varsayılan parolaları dener.
2. **Ayrıcalık Yükseltme (Privilege Escalation):** Sisteme düşük yetkili bir kullanıcı olarak sızdığında ilk çalıştırdığı komut:
   `sudo -l`
   Eğer çıktıda `(ALL) NOPASSWD: /usr/bin/find` veya `NOPASSWD: ALL` görürse, tek bir komutla root olur:
   `sudo find . -exec /bin/sh -p \; -quit`
3. **Shadow Hash Hırsızlığı:** Eğer dikkatsiz bir yönetici `/etc/shadow` dosyasına okuma izni vermişse (`cat /etc/shadow`), tüm hash'leri yerel bilgisayarına indirip GPU ile kırar.
4. **Eski Servis Avı:** Sistemde Telnet (Port 23) veya FTP (Port 21) açıksa, ağ trafiğini dinleyerek (sniffing) geçen kullanıcı adı ve şifreleri açık metin olarak yakalar.

---

### 🔵 Savunmacının Kalkanı (Defensive Perspective)

Biz savunmacılar olarak Linux kalesini şu 5 zırhla donatırız:
1. **SSH Kalkanı:** `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `Port 2222`. Kaba kuvvet saldırıları matematiksel olarak imkansız hale gelir.
2. **Sudoers Disiplini:** NOPASSWD tamamen yasaklanır. Yetkiler `visudo` aracıyla doğrulanır; her ayrıcalıklı komut `/var/log/sudo.log` kütüğüne denetim izi bırakır.
3. **Shadow Koruması:** `/etc/shadow` kesinlikle `0640 root:shadow` yapılır. Standart kullanıcıların hash görmesi engellenir.
4. **UFW Kalkanı:** `default deny incoming` politikası ile port taramaları tamamen sağır edilir.
5. **Gereksiz Servislerin İtlafı:** Telnet, RSH, vsftpd servisleri kaldırılır; yalnızca güvenli SSH ve NTP (Chrony) çalışır.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Bugünkü laboratuvarımızda geliştirdiğimiz `linux_baseline_auditor.py` aracı; verilen Linux sistem profillerini CIS Benchmark Seviye 1 standartlarında satır satır denetler ve sertleştirilmiş üretim konfigürasyonları üretir.

### A. İncelenen Sistem Profilleri

`portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json` dosyasında iki profili modelledik:
* `LINUX-SEC-01 (Sertleştirilmiş Debian VM)`: Port 2222, Root login kapalı, parola kapalı (sadece Ed25519 anahtar), shadow 0640, umask 027, UFW açık, gereksiz servis sıfır.
* `LINUX-RISK-99 (Güvensiz Varsayılan Kali VM)`: Port 22, Root login açık, NOPASSWD: ALL tanımlı, shadow 0644 dünya okuyabilir, passwd 0777 yazılabilir, UFW kapalı, Telnet açık.

### B. Canlı Denetimin Çalıştırılması

Öğrenci olarak terminalinde şu komutu çalıştır:

```bash
python portfolio/hafta_02/gun_010/uygulama/linux_baseline_auditor.py --profile portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json
```

Bu komutu çalıştırdığında ekranda gerçek denetim sonuçları belirecektir:
* `LINUX-SEC-01`: Güvenlik Skoru **100/100** | Durum: **GÜVENLİ (CIS SEVİYE 1 SERTLEŞTİRİLMİŞ)** | 0 Bulgu.
* `LINUX-RISK-99`: Güvenlik Skoru **0/100** | Durum: **KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)** | 10 Kritik Bulgu! (Root SSH açık, NOPASSWD felaketi, shadow 0644, UFW kapalı, Telnet aktif vb.).

### C. Sertleştirilmiş Güvenli Konfigürasyon Dosyalarının Üretilmesi

Sertleştirilmiş sistemimiz için tek komutla kurumsal standartlarda `/etc/ssh/sshd_config` ve `/etc/sudoers` dosyaları üretebilirsin:

```bash
python portfolio/hafta_02/gun_010/uygulama/linux_baseline_auditor.py --profile portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json --system-id LINUX-SEC-01 --generate-sshd portfolio/hafta_02/gun_010/ornek_veri/sshd_config_hardened --generate-sudoers portfolio/hafta_02/gun_010/ornek_veri/sudoers_hardened
```

Üretilen [sshd_config_hardened](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_02/gun_010/ornek_veri/sshd_config_hardened) ve [sudoers_hardened](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_02/gun_010/ornek_veri/sudoers_hardened) dosyalarını Linux sanal makinene kopyalayarak sistemini anında CIS Seviye 1 zırhıyla kaplayabilirsin!

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, bu 5 ölümcül hatayı meslek hayatında asla yapmayacaksın:

1. **"Kali Linux Kurup Varsayılan `kali:kali` Parolasını Bırakmak"**:
   * *Felaket:* Ağa bağlandığın saniyede başka bir penetrasyon test uzmanı veya botnet makineni hackler ve kendi Kali'n sana karşı silah olarak kullanılır!
   * *Doğrusu:* Kurulum biter bitmez `passwd` komutu ile güçlü bir parola belirlenir veya doğrudan SSH anahtarına geçilir.

2. **"SSH'ta `PermitRootLogin yes` Açıkken Parolalı Giriş Bırakmak"**:
   * *Felaket:* Kaba kuvvet saldırıları doğrudan root kullanıcısını hedefler ve sistemi ele geçirir.
   * *Doğrusu:* Daima `PermitRootLogin no` ve `PasswordAuthentication no`.

3. **"Tembellikten `/etc/sudoers` Dosyasına `NOPASSWD: ALL` Yazmak"**:
   * *Felaket:* Düşük yetkili bir kullanıcı hesabını ele geçiren saldırgan GTFOBins ile tek bir saniyede tam root yetkisi alır.
   * *Doğrusu:* Parolasız sudo kesinlikle yasaktır; her komutta parola istenmelidir.

4. **"İzin Sorunu Çıkınca Dosyaları `chmod 777` Yapmak"**:
   * *Felaket:* Özellikle `/etc/shadow` veya web dizinlerini 777 yapmak, sistemin tüm sırlarını dünyaya ifşa etmektir.
   * *Doğrusu:* İzinler en az ayrıcalık ilkesiyle (shadow için 0640, passwd için 0644, betikler için 0750) yapılandırılır.

5. **"Güvenlik Duvarını (`ufw`) Kapatıp Telnet Açmak"**:
   * *Felaket:* Şifresiz metin tabanlı protokoller ağdaki herkes tarafından koklanır ve tüm parolalar çalınır.
   * *Doğrusu:* Telnet ve FTP tamamen kaldırılır; UFW varsayılan olarak gelen tüm trafiği reddeder (`default deny incoming`).

---

## 6. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` içinde yer alan `G010-SC1`, `G010-SC2` ve `G010-SC3` numaralı soruların usta-çırak derinliğindeki yanıtları:

* **Soru 1 (G010-SC1):** Linux sanal makinesine güvenli başlangıç: Temel mekanizmayı ve güvenlik önemini açıkla.
  * *Hocanın Yanıt Özeti:* Linux sanal makinesine güvenli başlangıç; varsayılan zayıf konfigürasyonları CIS Seviye 1 taban çizgisine yükselterek sistemin ilk açılışından itibaren saldırı yüzeyini en aza indirme disiplinidir. Root ile doğrudan SSH oturumunun kapatılması, parola yerine kriptografik anahtar zorunluluğu, NOPASSWD açıklarının kapatılması ve UFW ile varsayılan engelleme bu mekanizmanın omurgasını oluşturur.
* **Soru 2 (G010-SC2):** Linux sanal makinesine güvenli başlangıç: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
  * *Hocanın Yanıt Özeti:* Girdisi Linux konfigürasyon parametrelerini içeren JSON profili; işlemi SSH, sudoers, shadow/passwd izinleri ve UFW kurallarının denetlenmesi; beklenen sonucu 100/100 güvenlik skoru ve sertleştirilmiş `sshd_config` / `sudoers` şablonları üretilmesi; negatif kontrolü ise `NOPASSWD: ALL` veya `shadow=0644` tespit edildiğinde sistemin işlemi FELAKET seviyesinde reddetmesidir.
* **Soru 3 (G010-SC3):** 'Linux sanal makinesine güvenli başlangıç' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
  * *Hocanın Yanıt Özeti:* Risk; varsayılan parolalar, parolasız sudo yetkileri ve açık gelen portların saldırganlara yetki yükseltme ve kaba kuvvet kapısı açmasıyla oluşur. `linux_baseline_auditor.py`, `sudo -l` ve `sshd -T` kontrolleriyle tespit edilir. `PermitRootLogin no`, `PasswordAuthentication no`, katı dosya izinleri ve UFW kalkanı ile önlenir.

*(Detaylı kurumsal yanıtların tamamı `soru_cevap.md` dosyasında yer almaktadır.)*

---

## 7. Ödev & Bir Sonraki Güne Hazırlık

1. **Günün Pratik Ödevi:**
   Kendi Linux sanal makinende (Kali veya Ubuntu) terminali aç. `sudo cat /etc/ssh/sshd_config | grep -E "PermitRootLogin|PasswordAuthentication"` komutunu çalıştırarak mevcut SSH ayarlarını gör. Ardından `sudo -l` çıktısını inceleyerek parolasız bir komut olup olmadığını denetle!
2. **Yarın Bizi Ne Bekliyor (GÜN 011)?**
   Yarın Linux dünyasında derinleşmeye devam ediyoruz: **Temel Linux Komutları ve Dosya Sistemi Hiyerarşisi (FHS)** konusuna geçeceğiz. Dosya sisteminde kaybolmadan bir dedektif gibi gezinmeyi, boru hatlarını (pipes), yönlendirmeleri ve süreç yönetimini bizzat ellerimizle uygulayacağız.

Tebrikler evlat, Linux sanal makinen artık siber fırtınalara karşı hazır!
