# GÜN 024: Linux Dosya İzinleri (RWX), Umask ve Güvenli Geri Alma Mimarisi

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
*ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR*  
*Lisans Rozeti:* ![All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## 1. GİRİŞ VE PEDAGOJİK ÇERÇEVE (USTA-ÇIRAK VİZYONU)

Evlat, siber güvenliğin ve Linux sistem yönetiminin en temel sütununa geldik: **Dosya İzinleri (Discretionary Access Control - DAC)**. 

Bir işletim sisteminde çekirdek ne kadar sağlam olursa olsun, ağ güvenlik duvarı ne kadar katı yapılandırılırsa yapılandırılsın, dosya sistemi izinlerindeki tek bir hata tüm sistemi saldırgana teslim edebilir. Linux felsefesinde *"Her şey bir dosyadır"* (everything is a file). Yapılandırmalar `/etc/` altında dosyadır, parolaların özetleri `/etc/shadow` dosyasında saklanır, donanım aygıtları `/dev/` altında dosyadır, süreç bellekleri ve çekirdek parametreleri `/proc/` ve `/sys/` altında dosya arayüzüyle sunulur. Dolayısıyla dosyaya erişimi yönetmek, tüm işletim sisteminin egemenliğini yönetmektir.

Bugünkü dersimizde sadece `chmod 777` deyip geçen acemi sistemcilerin yaptığı ölümcül hataları analiz etmeyecek; bit düzeyinde okuma, yazma ve çalıştırma mekanizmalarını, SUID/SGID/Sticky bit özel yetkilerini, umask matematiğini, CWE-732 güvenlik zafiyetini ve yapılan değişikliklerin bir denetim günlüğü (journal) üzerinden nasıl güvenle geri alınacağını (rollback) en ince ayrıntısına kadar öğreneceğiz.

---

## 2. POSIX ERİŞİM DENETİMİ: USER, GROUP, OTHER VE RWX BİTLERİ

Linux dosya sistemi, her bir dosya ve dizin için sahiplik ve izinleri inode yapısında saklar. İzinler üç farklı aktör katmanı için bağımsız olarak tanımlanır:

1. **Kullanıcı / Sahip (User - `u`):** Dosyayı oluşturan veya `chown` ile sahibi kılınan tekil kullanıcı hesabıdır.
2. **Grup (Group - `g`):** Dosyanın ait olduğu işletim sistemi grubudur (`chgrp`). Bu gruptaki tüm kullanıcılar aynı grup izinlerini paylaşır.
3. **Diğerleri / Herkes (Others/World - `o`):** Dosyanın sahibi olmayan ve dosya grubuna üye olmayan, sistemdeki tüm diğer yerel hesaplardır.

### 2.1 İzin Türleri ve Oktal Ağırlıkları

Her aktör için üç temel izin biti atanabilir:
- **Okuma (`r` - Read):** Sayısal değeri **4**'tür ($2^2$). 
  - Normal dosyada dosya içeriğini görüntüleme (örn: `cat`, `less`) yetkisidir.
  - Dizinde dizin içerisindeki dosya ve alt dizin isimlerini listeleme (`ls`) yetkisidir.
- **Yazma (`w` - Write):** Sayısal değeri **2**'dir ($2^1$).
  - Normal dosyada dosya içeriğini değiştirme, üzerine yazma veya kesme yetkisidir.
  - Dizinde yeni dosya/dizin oluşturma veya var olan dosyaları silme yetkisidir. **DİKKAT:** Bir dosyayı silebilmek için dosyanın kendisine yazma hakkına değil, dosyanın içinde bulunduğu **üst dizine yazma (`w`)** hakkına ihtiyaç vardır!
- **Çalıştırma (`x` - Execute):** Sayısal değeri **1**'dir ($2^0$).
  - Normal dosyada betik veya ikili (binary) programı bir süreç olarak hafızaya yükleyip çalıştırma yetkisidir.
  - Dizinde dizinin içine girme (`cd`) ve dizin altındaki bilinen dosyaların inode/meta verilerine erişme yetkisidir.

### 2.2 Oktal ve Sembolik Eşleme Tablosu

| Sayısal (Oktal) | İkili (Binary) | Sembolik | Anlamı ve Yetki Kapsamı |
| :---: | :---: | :---: | :--- |
| **0** | `000` | `---` | Hiçbir yetki yok |
| **1** | `001` | `--x` | Yalnızca çalıştırma / dizine girme |
| **2** | `010` | `-w-` | Yalnızca yazma (nadir kullanılır) |
| **3** | `011` | `-wx` | Yazma ve çalıştırma (dizinler için tehlikeli) |
| **4** | `100` | `r--` | Yalnızca okuma |
| **5** | `101` | `r-x` | Okuma ve çalıştırma (standart çalıştırılabilir ikililer ve genel dizinler) |
| **6** | `110` | `rw-` | Okuma ve yazma (standart veri/yapılandırma dosyaları) |
| **7** | `111` | `rwx` | Tam yetki: Okuma, yazma ve çalıştırma |

Üç katman bir araya geldiğinde standart 3 veya 4 haneli oktal sayı oluşur:
- `0755` = Sahip (`7` - `rwx`), Grup (`5` - `r-x`), Diğerleri (`5` - `r-x`) -> `-rwxr-xr-x`
- `0644` = Sahip (`6` - `rw-`), Grup (`4` - `r--`), Diğerleri (`4` - `r--`) -> `-rw-r--r--`
- `0600` = Sahip (`6` - `rw-`), Grup (`0` - `---`), Diğerleri (`0` - `---`) -> `-rw-------`

---

## 3. ÖZEL İZİN BİTLERİ: SUID, SGID VE STICKY BIT

Standart RWX üçlüsünün solunda dördüncü bir oktal hane bulunur. Bu hane özel izin bitlerini kontrol eder:

### 3.1 SUID (Set User ID - `0o4000`)
- **Mekanizma:** Bir çalıştırılabilir dosya SUID biti ile işaretlendiğinde (`chmod u+s /path/binary`), bu dosya kim tarafından çalıştırılırsa çalıştırılsın, dosya **sahibinin yetkileriyle** (genellikle `root`) belleğe yüklenir.
- **Örnek:** `/usr/bin/passwd` programı. Sıradan kullanıcı kendi parolasını değiştirdiğinde `/etc/shadow` dosyasına yazabilmesi için SUID root çalışır.
- **Güvenlik Riski:** SUID atanmış ikili dosyalarda bellek taşması (buffer overflow), ortam değişkeni enjeksiyonu veya komut enjeksiyonu açığı varsa, saldırgan anında root haklarına sıçrar (Yetki Yükseltme - Privilege Escalation).

### 3.2 SGID (Set Group ID - `0o2000`)
- **Mekanizma:** 
  - İkili dosyada dosya çalışırken dosyanın grubunun yetkileriyle çalışır (`chmod g+s`).
  - Dizinlerde kullanıldığında, bu dizin altında yeni oluşturulan tüm alt dosya ve klasörler oluşturan kullanıcının ana grubunu değil, dizinin ait olduğu grubu miras alır. Paylaşımlı takım çalışma alanları için standarttır.

### 3.3 Sticky Bit (Yapışkan Bit - `0o1000`)
- **Mekanizma:** Bir dizine sticky bit uygulandığında (`chmod +t` veya `chmod 1777`), dizin herkese yazılabilir (world-writable) olsa bile, dosya ve dizinleri yalnızca **dosyanın sahibi, dizinin sahibi veya root** silebilir veya yeniden adlandırabilir.
- **Kritik Rolü:** `/tmp` ve `/var/tmp` dizinleri sistemdeki tüm kullanıcı ve servislerin geçici dosya oluşturabilmesi için `1777` (`drwxrwxrwt`) olarak yapılandırılır. Sticky bit olmazsa, herhangi bir kullanıcı diğer kullanıcıların veya sistem servislerinin oturum ve kilit dosyalarını silebilir veya üzerine sahte dosya koyarak hizmet dışı bırakma (DoS) saldırısı yapabilir.

---

## 4. UMASK MATEMATİĞİ VE VARSAYILAN İZİN TÜRETİMİ

Bir program veya kullanıcı yeni bir dosya ya da dizin oluşturduğunda işletim sistemi izinleri doğrudan keyfi belirlemez. Çekirdek, `umask` (User Mask) filtresini uygular.

### 4.1 Matematiksel Mantık
POSIX standartlarında yeni oluşturulan nesneler için işletim sistemi taban izinleri:
- **Yeni Dosyalar İçin Taban İzin:** `0666` (`rw-rw-rw-`) - Dosyalara varsayılan olarak asla çalıştırma (`x`) hakkı verilmez!
- **Yeni Dizinler İçin Taban İzin:** `0777` (`rwxrwxrwx`) - Dizinlerin gezilebilmesi için çalıştırma biti zorunludur.

Sonuç izin, taban iznin umask değerinin tersi ile **Bit Düzeyinde VE (Bitwise AND with NOT)** işlemine sokulmasıyla türetilir:
$$\text{Hedef İzin} = \text{Taban İzin} \ \& \ (\sim\text{Umask})$$

### 4.2 Umask Karşılaştırma Analizi

1. **Umask 0022 (Standart Dağıtım Varsayılanı):**
   - Dosya: $0666 \ \& \ \sim0022 = 0644$ (`-rw-r--r--`). Sahip yazar/okur, grup ve diğerleri sadece okur.
   - Dizin: $0777 \ \& \ \sim0022 = 0755$ (`drwxr-xr-x`). Sahip tam yetkili, diğerleri girer ve listeler.
2. **Umask 0027 (CIS Benchmark / Güçlendirilmiş Sunucu Modeli):**
   - Dosya: $0666 \ \& \ \sim0027 = 0640$ (`-rw-r-----`). Diğerleri için **sıfır erişim**!
   - Dizin: $0777 \ \& \ \sim0027 = 0750$ (`drwxr-x---`). Yabancılar dizine adım dahi atamaz.
3. **Umask 0000 (Kritik Güvenlik İhlali):**
   - Dosya: $0666$ (`-rw-rw-rw-`) -> Herkes değiştirebilir!
   - Dizin: $0777$ (`drwxrwxrwx`) -> Herkes içine dosya atabilir, tahrif edebilir.

---

## 5. CWE-732 ZAFİYETİ VE SALDIRI SENARYOLARI

**CWE-732 (Incorrect Permission Assignment for Critical Resource):** Kritik bir kaynağa gereğinden fazla geniş izin tanımlanması durumudur.

### 5.1 Tipik Sektör Hataları ve İstismar Vektörleri
1. **Geliştirici Tembelliği (`chmod 777` Sendromu):**
   - "Web uygulaması dosya yükleyemedi, klasöre 777 verdim çözüldü." Bu cümle bir siber güvenlik analistinin duyabileceği en acı verici itiraftır. 777 verilen web dizinine veya yapılandırma dosyasına sistemdeki herhangi bir kısıtlı servis veya saldırgan doğrudan kötü amaçlı PHP web kabuğu (web shell) yazıp sistemi ele geçirir.
2. **Dünyaya Yazılabilir Log Dosyaları (`/var/log/syslog` 0666):**
   - Bir saldırgan sisteme sızdığında ilk işi izlerini silmektir. Eğer log dosyası world-writable ise, saldırgan root yetkisi olmadan kendi IP adresini ve gerçekleştirdiği istismar satırlarını dosyadan silebilir veya anlamsız veriler basarak diski doldurabilir (DoS).
3. **SSH Özel Anahtarının Açıkta Olması (`id_rsa` 0644):**
   - SSH istemcisi güvenlik gereği `0600` izninden daha geniş izne sahip bir `id_rsa` dosyasını kullanmayı reddeder (*"Permissions 0644 for 'id_rsa' are too open"*). Açık bırakılırsa aynı sunucudaki başka bir kullanıcı anahtarı kopyalayarak yetkisiz oturum açabilir.

---

## 6. GÜVENLİK DENETİMİ, FARKLILIK TESPİTİ VE GERİ ALMA (ROLLBACK) İLKELERİ

Güvenlik güçlendirmesi (hardening) yaparken altın bir kural vardır: **"Geri alamayacağın hiçbir değişikliği üretim ortamına uygulama!"**

Bir güvenlik analisti sunucuda izinleri sıkılaştırırken:
1. **Envanter Çıkarmalı:** Dosya yolları, mevcut izinler, sahiplikler tespit edilir.
2. **Kural Temeli ile Karşılaştırmalı:** CIS Benchmark veya NIST SP 800-53 AC-6 ilkelerine göre izin aşımı (permission drift) belirlenir.
3. **İşlem Günlüğü (Journaling) Tutmalı:** `chmod` komutu uygulanmadan önce dosyanın eski modu, yeni modu, işlem zamanı ve operatör kimliği güvenli bir günlüğe yazılmalıdır.
4. **Tek Komutla Geri Alma (Rollback):** Eğer sıkılaştırma sonrası meşru bir uygulama veya servis çökerse, güvenlik ekibi saniyeler içinde eski izinleri geri yükleyebilmelidir.

Geliştirdiğimiz `linux_permission_rwx_auditor.py` aracı tam olarak bu kurumsal prensibi yerine getirmekte; yapılan tüm izin değişikliklerini JSON tabanlı bir günlükte saklayarak `--rollback` bayrağı ile atomik geri dönüş sağlamaktadır.

---

## 7. ÖZET VE BÖLÜM KONTROL LİSTESİ

- [x] Okuma (`r=4`), Yazma (`w=2`), Çalıştırma (`x=1`) bit ağırlıkları ve Kullanıcı, Grup, Diğerleri hiyerarşisi anlaşıldı.
- [x] SUID (`4000`), SGID (`2000`) ve Sticky (`1000`) bitlerinin işletim sistemi ve yetki yükseltme boyutu kavrandı.
- [x] Umask hesaplama formülü ($Base \ \& \ \sim Umask$) ve 022 ile 027 arasındaki güvenlik farkı test edildi.
- [x] CWE-732 kapsamında world-writable ve aşırı izinli kaynakların oluşturduğu siber riskler analiz edildi.
- [x] Kontrollü girdi, gözlenebilir çıktı, geri alma günlüğü (journal) ve rollback döngüsü bizzat icra edilip kanıtlandı.
