# GÜN 025: Kullanıcı, Grup ve Oturum Güvenliği Mimarisi

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## 1. GİRİŞ VE PEDAGOJİK ÇERÇEVE (USTA-ÇIRAK VİZYONU)

Evlat, dünkü dersimizde dosyaların erişim izinlerini (rwx) ve umask filtrelerini öğrendik. Fakat bir dosyanın veya sistem kaynağının kime ait olduğunu, bir sürecin hangi yetkiyle çalıştığını belirleyen asıl omurga **Kullanıcı (User), Grup (Group) ve Oturum (Session)** mimarisidir.

Çoğu acemi sistem yöneticisi ve güvenlikçi adayı kimlik (Identity) ile etkin oturumu (Active Session) birbirine karıştırır. Veritabanında veya `/etc/passwd` dosyasında bir kullanıcının tanımlı olması yalnızca bir **kimlik kaydıdır**. O kullanıcının sisteme parola, SSH anahtarı veya biyometrik veriyle başarılı bir şekilde girmesi ise bir **etkin oturum** doğurur. İşte siber güvenlik operasyonları ve adli bilişim (forensics) tam bu noktada başlar: *"Bu eylemi hangi kimlik, hangi oturum belirteciyle (token), hangi IP adresinden ve ne zaman yaptı?"*

Bugünkü dersimizde kimlik-oturum ayrımını, Linux ve Windows kimlik modellerini, UID/GID/SID kavramlarını, servis hesaplarının sıkılaştırılmasını, ortak hesapların (shared accounts) yok ettiği inkâr edilemezlik (non-repudiation) ilkesini ve canlı oturum denetimini en derin teknik katmanlarıyla inceleyeceğiz.

---

## 2. KİMLİK (IDENTITY) İLE ETKİN OTURUM (SESSION) AYRIMI

Bir işletim sisteminde güvenlik mekanizmaları iki temel aşamadan oluşur:

### 2.1 Kimlik Doğrulama (Authentication - "Kimsin?")
- Kullanıcının sistemde tanımlı bir hesaba sahip olduğunu ve bu hesabın meşru sahibi olduğunu kanıtlamasıdır (parola, SSH anahtarı, MFA kodu, Kerberos bileti).
- Linux sistemlerinde kimlik verileri `/etc/passwd` (kullanıcı adı, UID, GID, ev dizini, kabuk) ve `/etc/shadow` (parola hash'leri, hesap son kullanım tarihleri) dosyalarında saklanır.
- Windows sistemlerinde yerel kimlikler SAM (Security Account Manager) veritabanında, etki alanı (domain) kimlikleri ise Active Directory (NTDS.dit) veritabanında tutulur.

### 2.2 Yetkilendirme ve Oturum (Authorization & Session - "Ne Yapabilirsin?")
- Kimlik doğrulama başarıyla tamamlandığında işletim sistemi çekirdeği bir **Oturum (Session)** nesnesi ve süreç kimlik belirteçleri (Process Credentials) üretir.
- Oturum; süreçlerin çalıştığı sanal bir kabuk, ortam değişkenleri kümesi, terminal aygıtı (TTY/PTS), bellek limitleri ve oturum kimliğini (Session ID - SID) kapsar.
- **En Kritik Güvenlik İlkesi:** Kimlik kalıcıdır, oturum ise geçicidir (ephemeral). Eğer oturum güvenliği iyi yönetilmezse (oturum çalma, sonsuz boşta kalma süresi, yetki yükseltme), saldırgan meşru kullanıcının açtığı oturuma tutunarak tüm sistemi ele geçirir.

---

## 3. LİNUX VE WINDOWS KİMLİK BELİRTEÇLERİ (UID/GID VS. SID)

Farklı işletim sistemleri kullanıcıları isimleriyle değil, çekirdeğin anladığı benzersiz sayısal tanımlayıcılarla takip eder:

### 3.1 Linux Kimlik Yapısı: UID, GID ve Süreç Seviyeleri
- **UID (User Identifier):** 
  - `UID 0`: Her zaman `root` (süper kullanıcı).
  - `UID 1 - 999`: Sistem ve servis hesapları (`daemon`, `syslog`, `www-data`, `systemd`).
  - `UID 1000+`: İnsan kullanıcılar ve etkileşimli hesaplar.
- **GID (Group Identifier):** Birincil (primary) ve ikincil (supplementary) grup kimlikleri.
- **Süreç Seviyesinde 3 Farklı UID:**
  1. **Real UID (RUID):** Süreci başlatan gerçek kullanıcının kimliğidir.
  2. **Effective UID (EUID):** Çekirdeğin dosya ve kaynak erişim kararlarında baktığı etkin kimliktir (SUID programlarda root olur).
  3. **Saved UID (SUID):** Sürecin geçici olarak yetki düşürüp tekrar asıl yetkisine dönmesini sağlayan yedek kimliktir.

### 3.2 Windows Kimlik Yapısı: SID (Security Identifier)
Windows ortamında her kullanıcı, grup ve bilgisayar bir SID ile temsil edilir (örn: `S-1-5-21-4251509839-2239028382-1546434742-1006`):
- `S`: String yapısında olduğunu belirtir.
- `1`: SID revizyon seviyesidir.
- `5`: NT Yetki Kurumunu (NT Authority) gösterir.
- `21-...`: Etki alanı veya yerel makineye özgü rastgele alt yetki tanımlayıcısıdır.
- `1006`: RID (Relative Identifier). 500 yerel Administrator'dır; 1000 ve üzeri normal kullanıcılara atanır.

---

## 4. ORTAK HESAP (SHARED ACCOUNT) ANTİ-PATERNİ VE İNKÂR EDİLEMEZLİK

Kurumsal ortamlarda yapılan en tehlikeli mimari hatalardan biri **ortak hesap kullanımıdır** (örn: birden fazla sistemcinin aynı `root` veya `admin` parolasını paylaşarak sunucuya girmesi).

### 4.1 İnkâr Edilemezlik (Non-Repudiation) Kaybı
- Güvenliğin temel SAC üçlüsüne (Gizlilik, Bütünlük, Erişilebilirlik) ek olarak **İnkâr Edilemezlik** ilkesi bulunur.
- Bir sunucuda kritik bir müşteri veritabanı silindiğinde (`rm -rf /var/lib/postgresql`), denetim günlüğünde sadece `"root kullanıcısı sildi"` kaydı varsa ve o sunucuya 5 farklı mühendis `root` olarak erişebiliyorsa:
  - Hangi personelin bu komutu çalıştırdığı kanıtlanamaz.
  - Hata veya kötü niyet örtbas edilebilir.
  - Yasal düzenlemeler (KVKK, GDPR, PCI-DSS, ISO 27001) açıkça ihlal edilmiş olur.

### 4.2 Doğru Savunma Mimarisi
1. **Bireysel Hesaplar:** Her personele `ad.soyad` formatında tekil hesap açılır.
2. **Kişiselleştirilmiş SSH Anahtarları:** Ortak şifre yerine yalnızca personele zimmetli donanım token'ı veya SSH anahtarı kullanılır.
3. **Sudo Tabanlı Ayrıcalık Yükseltme:** Root doğrudan oturuma kapatılır (`PermitRootLogin no`); işlemler `sudo` üzerinden kayıt altına alınır (`/var/log/auth.log`).
4. **Eşzamanlı Oturum Kısıtlaması:** `/etc/security/limits.conf` içerisinde idari hesaplar için `maxlogins 1` tanımlanarak aynı anda birden fazla oturum açılması engellenir.

---

## 5. SERVİS HESAPLARI VE GÜVENLİK SIKILAŞTIRMASI

Web sunucuları, veritabanları ve arka plan ajanları özel sistem hesapları altında çalışır (`www-data`, `nginx`, `postgres`, `mysql`).

### 5.1 Yasaklı Kabuk Kuralı (Non-Interactive Shells)
- Servis hesaplarının hiçbir zaman konsol veya SSH üzerinden etkileşimli bir kabuk açmasına izin verilmemelidir.
- Eğer `/etc/passwd` dosyasında `www-data:x:33:33:...:/bin/bash` yazıyorsa, bu web uygulamasındaki bir Uzaktan Kod Çalıştırma (RCE) açığı saldırgana doğrudan tam fonksiyonlu bir interaktif kabuk hediye eder!
- **Doğru Yapılandırma:** Servis hesaplarının kabuğu mutlaka `/usr/sbin/nologin` veya `/bin/false` olarak tanımlanmalıdır:
  ```bash
  usermod -s /usr/sbin/nologin www-data
  ```

### 5.2 Yetkisiz Grup Üyelikleri
- Servis hesapları asla `wheel`, `sudo`, `adm` veya Windows'ta `Administrators` grubuna üye yapılmamalıdır (En Az Ayrıcalık İlkesi - PoLP).

---

## 6. ATIL (DORMANT) HESAPLAR VE OTURUM ZAMAN AŞIMI YÖNETİMİ

### 6.1 Atıl / Yetim Hesaplar (Dormant Accounts)
- Şirketten ayrılan çalışanların veya süresi dolan dış kaynak personellerinin sistemde açık unutulan hesaplarıdır.
- Saldırganlar bu hesapları tespit ettiğinde (örneğin parola sızıntısı veya zayıf parola üzerinden), kimsenin kullanmadığı bir hesaba sızarak tespit edilmeden aylarca sistemde cirit atabilir.
- **Savunma:** 90 günden uzun süredir oturum açmamış hesaplar otomatik olarak kilitlenmeli (`usermod -L <user>`) veya kaldırılmalıdır.

### 6.2 Oturum Zaman Aşımı (Idle Session Timeout)
- Masasından kalkan bir yöneticinin açık unuttuğu terminal oturumu, içeri sızan bir saldırgan veya ofisteki yetkisiz bir kişi için doğrudan fiziksel arka kapıdır.
- **Savunma:** Sistem genelinde (`/etc/profile` veya `/etc/profile.d/timeout.sh`) `export TMOUT=900` ve `readonly TMOUT` tanımlanarak 15 dakika işlem yapılmayan kabukların otomatik kapanması sağlanmalıdır.

---

## 7. ÖZET VE BÖLÜM KONTROL LİSTESİ

- [x] Kimlik (Authentication) ile Etkin Oturum (Active Session) arasındaki temel fark kavrandı.
- [x] Linux UID/GID ve Windows SID kimlik belirteçlerinin işletim sistemi düzeyindeki anlamı incelendi.
- [x] Ortak hesap kullanımının inkâr edilemezliği (non-repudiation) nasıl yok ettiği ve oluşturduğu adli bilişim açmazı anlaşıldı.
- [x] Servis hesaplarında etkileşimli kabuk (`/bin/bash`) kullanımının yarattığı CWE-250 güvenlik riski kavrandı.
- [x] Yerel çalışan oturumun kimlik ve yetki meta verileri canlı olarak sorgulanıp belgelendi (G025-SC2).
- [x] Otomatik denetim motoru ile kullanıcı, grup ve oturum anomalileri tespit edilip iyileştirme komutları üretildi.
