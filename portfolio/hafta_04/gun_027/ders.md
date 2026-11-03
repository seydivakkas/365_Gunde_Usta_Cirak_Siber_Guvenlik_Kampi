# Hafta 04 — Gün 027: Paket ve Güncelleme Yöneticileri Güvenlik Mimarisi

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## 1. Giriş ve Felsefi Temel

### Usta ile Çırak Arasında Bir Sohbet
*Çırak:* "Ustam, dün `PATH` ortam değişkeninin nasıl bir saldırı vektörüne dönüştürülebileceğini gördük. Bugün sunucuda `apt update && apt upgrade -y` komutunu çalıştırırken aklıma takıldı: Bir komut veriyoruz ve sistem internetten yüzlerce ikili (binary) dosya indirip çekirdek seviyesine kadar her şeyi yeniliyor. Bu mekanizmanın arkasında ne tür bir güven bağı var? Neden `curl | bash` yapmaktan daha güvenli sayılıyor?"

*Usta:* "Evlat, UNIX dünyasının ilk yıllarını hatırla. Bir yazılım kurmak istediğinde kaynak kodun tarball (`.tar.gz`) arşivini indirir, `./configure && make && make install` yapardın. O günlerde 'bağımlılık cehennemi' (dependency hell) vardı; bir kütüphanenin sürümü uyuşmadığında tüm işletim sistemi kilitlenirdi. Paket yöneticileri (Debian'da `dpkg/APT`, Red Hat'te `RPM/DNF`), işte bu kaosu sistematik bir veritabanı, bağımlılık çözümleme grafı ve en önemlisi **kriptografik güven zinciri** ile çözmek için icat edildi."

"Ancak çırak, modern siber güvenlikte en ölümcül tehditlerden biri **Yazılım Tedarik Zinciri Saldırılarıdır (Software Supply Chain Attacks)**. Eğer indirdiğin paketin kaynağını doğrulayamazsan (CWE-347), iletişim şifresiz HTTP üzerindense (CWE-319) veya kritik bir servis için sürüm sabitlemesi (pinning) yapmadan körlemesine yükseltme yaparsan, sistemin sadece saldırıya uğramaz; aynı zamanda çöker! Bir güvenlik uzmanı, güncellemenin sadece bir yenilik değil, aynı zamanda işlev değişikliği ve kırılma riski taşıdığını asla aklından çıkarmaz."

---

## 2. Paket Yöneticisi Anatomisi ve Kriptografik Güvenlik

Paket yöneticileri sadece bir dosya indirici değildir; karmaşık bir paket yaşam döngüsü motorudur.

```
+-------------------------------------------------------------------+
|               RESMİ DAĞITIM SUNUCUSU (REPOSITORY)                  |
|  - InRelease / Release        (Paket listelerinin SHA256 özetleri)|
|  - Release.gpg                (Release dosyasının GPG İmzası)     |
|  - Packages.gz / repomd.xml   (Paket üstverileri ve bağımlılıklar)|
|  - *.deb / *.rpm              (İkili yazılım paketleri)           |
+---------------------------------+---------------------------------+
                                  | TLS 1.3 / HTTPS (CWE-319 Önleme)
                                  v
+-------------------------------------------------------------------+
|                 YEREL İSTEMCİ (APT / DNF MOTORU)                  |
|  1. /etc/apt/trusted.gpg.d/ içindeki açık anahtarla imzayı sına.  |
|     (CWE-347 Kriptografik İmza Doğrulama)                         |
|  2. Release dosyasındaki SHA256 ile indirilen paketi karşılaştır. |
|  3. Sabitleme (Pinning/Hold) kontrolü yap.                        |
|  4. Bağımlılık ağacını çöz ve atomik olarak kur.                  |
+-------------------------------------------------------------------+
```

### Kriptografik Güven Zinciri (Chain of Trust)
1. **Depo Listesi (`sources.list` veya `.repo`):** Sistemin hangi sunuculardan paket çekeceğini tanımlar. Burada kullanılan protokol kesinlikle `https://` olmalıdır. Şifresiz `http://` kullanıldığında, yerel ağdaki bir saldırgan ARP Spoofing veya DNS Spoofing yaparak paket listelerini manipüle edebilir (MitM).
2. **GPG Anahtar Doğrulaması:** Dağıtım sağlayıcısı (Debian, Canonical, Red Hat), paket indeks dosyasını (`Release`) kendi özel (private) GPG anahtarıyla imzalar. İstemci makine, önceden güvenilen açık anahtarla (`/etc/apt/trusted.gpg.d/`) bu imzayı çözer. Eğer imza uyuşmazsa paket yüklemesi derhal reddedilir.
3. **Checksum (Özet) Bütünlüğü:** `Release` dosyası içinde her bir paketin SHA256 özeti yer alır. Paket indirildiğinde özeti hesaplanır; 1 bit bile farklıysa paket derhal silinir.

---

## 3. Sürümleme, Sürüm Sabitleme (Pinning) ve Bağımlılık Yönetimi

### Anlamsal Sürümleme (Semantic Versioning - SemVer)
Modern paketler standart olarak `MAJOR.MINOR.PATCH` (örn: `1.24.0`) formatını takip eder:
- **MAJOR (Büyük Değişiklik):** Geriye dönük uyumsuzluk (breaking changes) içerir. API'ler veya yapılandırma sözdizimi değişebilir.
- **MINOR (Küçük Değişiklik):** Geriye dönük uyumlu yeni özellikler eklenir.
- **PATCH (Yama):** Geriye dönük uyumlu hata ve güvenlik düzeltmeleridir.

### Neden Sürüm Sabitleme (Pinning)?
Üretim (production) ortamlarında çalışan veritabanları (PostgreSQL), web sunucuları (Nginx) veya kriptografik kütüphaneler (`openssl`) plansız bir `upgrade` ile majör sürüm atlayabilir. Bu durum:
- Yapılandırma dosyalarının geçersiz kalmasına,
- Bağımlı uygulamaların çökmesine,
- Hizmet kesintilerine (DoS) neden olur.

```bash
# Debian / Ubuntu (APT) üzerinde sürüm sabitleme:
sudo apt-mark hold nginx openssl

# RHEL / CentOS / Rocky (DNF) üzerinde sürüm sabitleme:
sudo dnf versionlock add nginx openssl
```

Sabitlenen bir paket, `apt upgrade` veya `dnf upgrade` çalıştırılsa dahi yerinde kalır; yönetici bilinçli olarak sabitlemeyi kaldırmadıkça (`unhold`) sürüm değişmez.

---

## 4. Güvenlik Yamaları ve İşlevsel Değişiklikler

*Usta der ki:* "Her güncelleme aynı değildir evlat. Bir yazılım güncellemesi iki farklı motivasyon taşır:
1. **İşlev Değişikliği (Feature Update):** Yeni yetenekler, değişen arayüzler. Genellikle planlı bakım penceresi ve regresyon testi gerektirir.
2. **Güvenlik Düzeltmesi (Security Patch):** Keşfedilen bir CVE zafiyetinin (örn: Uzaktan Kod Çalıştırma / RCE) istismar edilmesini önleyen acil yamadır."

### Backporting (Geriye Taşıma) Sanatı
Kurumsal dağıtımlar (Debian Stable, Red Hat Enterprise Linux), kararlılığı bozmamak adına yazılımın en güncel ana sürümünü sisteme sokmaz. Bunun yerine, mevcut kararlı sürüme (örn: `openssl 3.0.2`) yalnızca ilgili güvenlik yamasını ekleyerek sürümü `3.0.2-0ubuntu1.14` gibi alt sürümlerle yamalar. Buna **backporting** denir. Bu sayede API kırılmadan güvenlik zafiyeti kapatılır.

---

## 5. İşlem Günlüğü, Güvenli Güncelleme ve Geri Alma (Rollback) Mimarisi

Bir sistem yöneticisinin veya DevSecOps mühendisinin en büyük güvencesi **Geri Alma (Rollback)** planıdır. Güncelleme öncesinde:
1. Sistemin mevcut paket envanteri ve sürümleri atomik bir işlem günlüğüne (`transaction journal`) kaydedilir.
2. Güncelleme işlemi simüle edilir (dry-run).
3. Güncelleme sonrasında duman testleri (smoke tests) veya servis sağlık kontrolleri başarısız olursa, işlem günlüğü okunarak bir önceki sürüme geri dönülür (`rollback`).

```bash
# DNF üzerinde işlem geçmişi ve geri alma:
dnf history
dnf history undo <islem_id>

# APT üzerinde belirli bir sürüme dönme:
apt-get install openssl=3.0.2
```

---

## 6. Geliştirilen Denetim Aracının Satır Satır Analizi

Geliştirdiğimiz `package_update_manager_auditor.py` aracı şu temel modüllerden oluşur:
1. **`parse_version(version_str)`:** SemVer dizgilerini ayrıştırarak matematiksel demetlere (`(major, minor, patch)`) dönüştürür. Sürüm karşılaştırmalarının string bazlı değil sayısal hiyerarşiyle yapılmasını sağlar.
2. **`audit_package_manager(inventory, baseline)`:** Depo URL'lerini inceler (`http://` tespiti -> CWE-319; eksik GPG tespiti -> CWE-347). Kritik servis paketlerinde sabitleme eksikliği (CWE-1395) ve bekleyen kritik CVE'leri denetler.
3. **`pin_package(inventory, package_name)`:** Paketin durumunu `pinned: True` yapar; sabitleme günlüğüne işler.
4. **`update_package(inventory, package_name, target_version, force, journal_path)`:** Paket sabitlenmişse ve `force` verilmemişse işlemi **bloke eder** (G027-SC2 negatif kontrol). Serbestse eski sürümü işlem günlüğüne yazar ve sürümü günceller.
5. **`rollback_package(inventory, package_name, journal_path)`:** Günlükteki en son geçerli eski sürümü bulur ve envanteri o sürüme geri döndürür.
6. **`generate_policy_note()`:** Kurumsal paket yönetim politikasını yazılı yönerge olarak üretir.

---

## 7. Çırağa Tavsiyeler, Savunma Kontrolleri ve Gelecek Güne Köprü

1. **Üçüncü Taraf Depoları Sınırla:** Asla rastgele PPA veya bilinmeyen RPM depoları ekleme. Her eklenen depo, kök (root) seviyesinde kod çalıştırma hakkına sahip bir güven ortaklığıdır.
2. **Yalnızca Güvenlik Güncellemelerini Otomatikle:** Üretim sunucularında `unattended-upgrades` ile yalnızca güvenlik depolarını (`security.debian.org`) otomatik kuracak şekilde yapılandır.
3. **Gelecek Güne Köprü (Gün 28):** Paket yöneticileri aracılığıyla kurulan servisler, işletim sistemi üzerinde süreçler (processes) olarak hayat bulur. Yarın, Linux süreç mimarisini (`ps`, `top`, `kill`), süreç sinyallerini ve yetkisiz arka plan süreçlerinin tespitini inceleyeceğiz!
