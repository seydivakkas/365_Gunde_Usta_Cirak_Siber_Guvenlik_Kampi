# Güvenlik Denetimi Komut Satırı Çalışma Defteri (Runbook)

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu çalışma defteri işletim sistemi gözlemlerini ve güvenlik denetim bulgularını yeniden üretilebilir kılmak için oluşturulmuştur.*

---

## 1. Denetim Özeti ve Yürütme Parametreleri

| Parametre | Değer |
| :--- | :--- |
| **Oluşturulma Zamanı (UTC)** | `2026-10-27T08:09:59.226028+00:00` |
| **Toplam İncelenen Komut** | `12` (Asgari 10 şartı sağlandı) |
| **Başarılı Yürütme Oranı** | `%100.0` |
| **Desen Eşleşme Uyumu** | `%100.0` |
| **Engellenen Yıkıcı Komut Sayısı** | `0` |
| **Güvenlik Politikası Sınıfı** | `SALT_OKUNUR_KESIF (READ_ONLY_DISCOVERY)` |

---

## 2. Çalışma Defteri Komut İndeksi

| No | Komut ID | Komut | Kategori | Güvenlik Amacı (MITRE / NIST) | Bütünlük Özeti (SHA256 İlk 8) |
| :---: | :---: | :--- | :--- | :--- | :---: |
| 1 | `CMD-01` | `whoami` | `kimlik_yonetimi` | Saldırgan ve savunmacı için temel keşif adımı... | `3ad851a9` |
| 2 | `CMD-02` | `id` | `kimlik_yonetimi` | Kullanıcının 'sudo', 'wheel' veya 'docker' gi... | `189df040` |
| 3 | `CMD-03` | `hostname` | `sistem_bilgisi` | Hedef makinenin etki alanı (domain) rolünü ve... | `c3e596ef` |
| 4 | `CMD-04` | `uname -a` | `sistem_bilgisi` | Çekirdek sürümüne özgü bilinen zafiyetlerin (... | `17751499` |
| 5 | `CMD-05` | `uptime` | `sistem_durumu` | Sistemin yakın zamanda yetkisiz yeniden başla... | `c7ccc7c3` |
| 6 | `CMD-06` | `ps aux` | `surec_yonetimi` | Yetkisiz arka plan ajanlarının, ters kabuklar... | `3e50c5de` |
| 7 | `CMD-07` | `df -h` | `depolama_ve_dosya` | Log taşması saldırıları (Log Flooding DoS) ve... | `ec395002` |
| 8 | `CMD-08` | `free -m` | `bellek_kaynaklari` | Bellek tüketimi tabanlı Hizmet Engelleme (DoS... | `174d9f51` |
| 9 | `CMD-09` | `ss -tulpn` | `ag_soketleri` | Yetkisiz arka kapı (backdoor), güvensiz servi... | `c9ee57b6` |
| 10 | `CMD-10` | `ip addr` | `ag_yapilandirmasi` | Gizli ağ arayüzleri, promiscuous moddaki dinl... | `df06a506` |
| 11 | `CMD-11` | `env` | `ortam_degiskenleri` | PATH manipülasyonu, LD_PRELOAD suistimalleri ... | `c52f1815` |
| 12 | `CMD-12` | `ls -ld /tmp` | `dosya_izinleri` | Geçici dizinlerde sticky bit eksikliği kullan... | `89689e3d` |

---

## 3. Komut Analiz Kartları ve Terminal Gözlemleri

### 3.1. whoami (`whoami`)

- **Komut ID:** `CMD-01`
- **Kategori:** `kimlik_yonetimi`
- **Hedef Platform:** `cross-platform`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `3ad851a969f243d1e486b1632839de02d19ea311ac5261d4072744ef59ba880b`

**Komut Açıklaması ve Amacı:**
Aktif kabuk oturumunu icra eden kullanıcının kullanıcı adını görüntüler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Saldırgan ve savunmacı için temel keşif adımıdır (MITRE ATT&CK T1033). Yetkisiz oturum veya beklenmeyen ayrıcalık (root/SYSTEM) durumunu ortaya koyar.

```text
$ whoami
secops_analyst
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.2. id (`id`)

- **Komut ID:** `CMD-02`
- **Kategori:** `kimlik_yonetimi`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `189df040ee7c608a1d64052f6732a825f83e05d9e8a66306713cce252435a8a2`

**Komut Açıklaması ve Amacı:**
Kullanıcının UID, GID ve üye olduğu tüm ikincil grup kimliklerini dökümler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Kullanıcının 'sudo', 'wheel' veya 'docker' gibi ayrıcalıklı gruplara dahil olup olmadığını doğrular. İstem dışı yetki artışı riskini tespit eder.

```text
$ id
uid=1001(secops_analyst) gid=1001(secops) groups=1001(secops),27(sudo)
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.3. hostname (`hostname`)

- **Komut ID:** `CMD-03`
- **Kategori:** `sistem_bilgisi`
- **Hedef Platform:** `cross-platform`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `c3e596efc4bb54ae10a82eb7efe4d905b67295a5747cb5859d8b85d16128d0ef`

**Komut Açıklaması ve Amacı:**
Sistemin yerel ve ağ seviyesindeki ana makine adını görüntüler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Hedef makinenin etki alanı (domain) rolünü ve ortamını (prod-db-01, dev-srv) anlamak için kullanılır (MITRE ATT&CK T1082).

```text
$ hostname
sec-core-prod-01
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.4. uname -a (`uname -a`)

- **Komut ID:** `CMD-04`
- **Kategori:** `sistem_bilgisi`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `17751499ee4ac8425046952a10f34a3f83113f459e465202a5c85e949246a564`

**Komut Açıklaması ve Amacı:**
İşletim sistemi çekirdek sürümü, mimarisi (x86_64, aarch64) ve derleme zamanını listeler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Çekirdek sürümüne özgü bilinen zafiyetlerin (örn: Dirty COW, Dirty Pipe) ve yama eksikliklerinin analizi için zorunludur.

```text
$ uname -a
Linux sec-core-prod-01 6.5.0-28-generic #29-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.5. uptime (`uptime`)

- **Komut ID:** `CMD-05`
- **Kategori:** `sistem_durumu`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `c7ccc7c33818f727e4b1bf707542d63f40d6688269200d4f0c2024b4ebfce6fc`

**Komut Açıklaması ve Amacı:**
Sistemin son yeniden başlatmadan bu yana geçen çalışma süresini ve yük ortalamasını (load average) verir.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Sistemin yakın zamanda yetkisiz yeniden başlatılıp başlatılmadığını ve anormal kaynak tüketimini (kripto madenciliği vb.) gösterir.

```text
$ uptime
10:15:22 up 45 days, 3:12,  2 users,  load average: 0.14, 0.08, 0.05
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.6. ps aux (`ps aux`)

- **Komut ID:** `CMD-06`
- **Kategori:** `surec_yonetimi`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `3e50c5dea7db927a230ecc1d2bbda5b22720e4a40f3000b103e2967b749f33a2`

**Komut Açıklaması ve Amacı:**
Sistemde o anda çalışan tüm süreçlerin PID, kullanıcı, bellek, CPU ve komut satırı argümanlarını listeler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Yetkisiz arka plan ajanlarının, ters kabukların (reverse shell) ve olağan dışı süreç ağaçlarının tespiti için birincil araçtır (MITRE ATT&CK T1057).

```text
$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168432 13540 ?        Ss   Sep12   1:45 /sbin/init
root       612  0.0  0.2  18740  8920 ?        Ss   Sep12   0:15 /lib/systemd/systemd-journald
www-data   980  0.0  0.4 124500 18450 ?        S    Sep12   2:10 nginx: worker process
secops    1450  0.0  0.1  11450  3240 pts/0    R+   10:15   0:00 ps aux
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.7. df -h (`df -h`)

- **Komut ID:** `CMD-07`
- **Kategori:** `depolama_ve_dosya`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `ec395002f6c729658d4b6ce6f48386a9adc651bed7192db136145054dadc7e04`

**Komut Açıklaması ve Amacı:**
Bağlı dosya sistemlerini, toplam alanları, kullanılan miktarları ve doluluk oranlarını okunabilir (GB/MB) formatta sunar.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Log taşması saldırıları (Log Flooding DoS) veya saldırgan tarafından /tmp veya /var/tmp altına indirilen gizli verileri tespit eder.

```text
$ df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        98G   24G   70G  26% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sda2       196G   45G  142G  25% /var/log
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.8. free -m (`free -m`)

- **Komut ID:** `CMD-08`
- **Kategori:** `bellek_kaynaklari`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `174d9f51d45cf0c5ad30a225ea39c3219283b504f280dc9ce27396cb7492f861`

**Komut Açıklaması ve Amacı:**
Fiziksel RAM ve takas (swap) alanının toplam, kullanılan ve boş miktarlarını megabayt cinsinden görüntüler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Bellek tüketimi tabanlı Hizmet Engelleme (DoS) zafiyetlerini veya yetkisiz bellek içi kötücül yazılımları işaret eder.

```text
$ free -m
total        used        free      shared  buff/cache   available
Mem:            7942        1820        4510         124        1612        5710
Swap:           2048           0        2048
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.9. ss -tulpn (`ss -tulpn`)

- **Komut ID:** `CMD-09`
- **Kategori:** `ag_soketleri`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `c9ee57b601465c57fbef44dfd804e16ba2f582a88c817367f28a2a6a9aa3b200`

**Komut Açıklaması ve Amacı:**
Dinleme durumundaki TCP ve UDP soketlerini, port numaralarını ve bu soketleri açan süreçlerin PID/adlarını listeler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Yetkisiz arka kapı (backdoor), güvensiz servis (Telnet, rsh) veya dışa açık hassas portları (3306, 5432, 6379) tespit eder (MITRE ATT&CK T1049).

```text
$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=780,fd=3))
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=980,fd=6))
tcp   LISTEN 0      511          0.0.0.0:443        0.0.0.0:*    users:(("nginx",pid=980,fd=7))
tcp   LISTEN 0      128        127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=1120,fd=4))
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.10. ip addr (`ip addr`)

- **Komut ID:** `CMD-10`
- **Kategori:** `ag_yapilandirmasi`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `df06a506e2ae4f0e87aa304ee6963c82035171113c3d7d168ae0a5cc1a45a279`

**Komut Açıklaması ve Amacı:**
Sistemdeki tüm fiziksel ve sanal ağ arayüzlerini, bunlara atanmış IPv4/IPv6 adreslerini ve bayrakları (UP/DOWN) listeler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Gizli ağ arayüzleri, promiscuous moddaki dinleyiciler ve yetkisiz VPN/tünel adaptörlerinin keşfi için kritiktir (MITRE ATT&CK T1016).

```text
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.4.15/24 brd 10.0.4.255 scope global dynamic eth0
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.11. env (`env`)

- **Komut ID:** `CMD-11`
- **Kategori:** `ortam_degiskenleri`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `c52f18150b7c9a9c533c92c61e4b820a33cc20607c1d36d7c04a47042360a8dd`

**Komut Açıklaması ve Amacı:**
Aktif oturuma ait tüm ortam değişkenlerini anahtar-değer çiftleri olarak yazdırır.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
PATH manipülasyonu, LD_PRELOAD suistimalleri veya ortam değişkenlerine açık metin olarak gömülmüş API anahtarları/şifreleri denetler.

```text
$ env
SHELL=/bin/bash
USER=secops_analyst
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/home/secops_analyst
HOME=/home/secops_analyst
LANG=en_US.UTF-8
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

### 3.12. ls -ld /tmp (`ls -ld /tmp`)

- **Komut ID:** `CMD-12`
- **Kategori:** `dosya_izinleri`
- **Hedef Platform:** `posix`
- **Güvenlik Düzeyi:** `read_only` (Salt-okunur)
- **Yürütme Modu:** `MOCK_DETERMINISTIC`
- **Çıkış Kodu (Exit Code):** `0`
- **Kriptografik SHA256 İzi:** `89689e3d824be2c31f526758e6d7019eb34f24be6853f32849f82017fac57d8f`

**Komut Açıklaması ve Amacı:**
Geçici dizinin (/tmp) izinlerini, sahipliğini ve sticky bit (t) durumunu listeler.

**Siber Güvenlik Önemi ve Tehdit Modeli:**
Geçici dizinlerde sticky bit eksikliği kullanıcıların birbirlerinin dosyalarını silmesine veya değiştirmesine yol açar (CWE-276 / CWE-377).

```text
$ ls -ld /tmp
drwxrwxrwt 14 root root 4096 Oct 27 10:15 /tmp
```

> **Analist Gözlemi ve Kontrol Önerisi:**  
> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `UYUMLU`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.

---

## 4. Güvenlik Duvarı ve Engellenen Girişimler Raporu (Negatif Kontrol)

Bu denetim oturumunda doğrudan engellenen güvensiz komut teşebbüsü kaydedilmedi.

---
