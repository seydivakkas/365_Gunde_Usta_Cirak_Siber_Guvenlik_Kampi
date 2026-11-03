<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 141: Yama Yönetimi ve CVE — Usta-Çırak Soru & Cevap

Bu belgede, kurumsal zafiyet yönetimi ve yama yaşam döngüsünde karşılaşılan en kritik operasyonel ve teknik sorular, CVSS skorlaması, CISA KEV triyajı ve güvenli geri alma (rollback) stratejileri çerçevesinde derinlemesine incelenmiştir.

---

## Soru 1: CVSS Skoru vs CISA KEV ve EPSS: Zafiyet Triyajında Hangisi Önceliklidir?

### 1. Soru Başlığı ve Tanımı
Geleneksel olarak güvenlik ekipleri yalnızca CVSS taban skoruna (CVSS $\ge 9.0$) bakarak yama önceliklendirmesi yaparken, günümüz modern tehdit istihbaratında CISA KEV (Known Exploited Vulnerabilities) ve EPSS (Exploit Prediction Scoring System) neden CVSS'ten daha belirleyici hale gelmiştir?

### 2. Derinlemesine Teknik Analiz
**CVSS Taban Skoru (Base Score):** Bir zafiyetin laboratuvar koşullarındaki teorik şiddetini ölçer. CVSS skoru hesaplanırken saldırının uzaktan yapılabilirliği (AV:N), karmaşıklığı (AC:L) ve etkisi (C:H/I:H/A:H) dikkate alınır. Ancak CVSS şu iki soruya yanıt veremez:
1. *Bu açığı vahşi doğada aktif olarak kullanan bir tehdit aktörü veya fidye yazılımı (ransomware) grubu var mı?*
2. *Önümüzdeki günlerde bu açık için kamuya açık çalışan bir exploit yayınlanma olasılığı nedir?*

Bir zafiyetin CVSS puanı 9.8 (Critical) olabilir; ancak karmaşık bir mimaride yer alıyor ve hiçbir saldırgan tarafından pratikte istismar edilmiyorsa, aciliyeti ikincil plandadır.
Buna karşılık, CVSS puanı 7.5 (High) olan bir CVE (örneğin Citrix Bleed veya eski bir VPN zafiyeti), **CISA KEV** listesinde yer alıyorsa; yani aktif olarak devlet destekli APT grupları veya fidye çeteleri tarafından kurumlara sızmak için kullanılıyorsa, bu açık **EMERGENCY (Acil)** statüsündedir ve derhal (72 saat içinde) yamalanmalıdır.

**EPSS (Exploit Prediction Scoring System):** Makine öğrenimi algoritmalarıyla tehdit istihbaratı verilerini analiz eder ve bir CVE'nin önümüzdeki 30 gün içinde istismar edilme olasılığını (0.0 ile 1.0 arası) hesaplar. EPSS skoru 0.85 (%85 olasılık) olan bir açık, CVSS skoru orta bile olsa öncelikli sıraya alınmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir holdingin BT güvenlik ekibi, haftalık zafiyet taramasında iki CVE tespit etmiştir:
- `CVE-A`: CVSS 9.8 (Kritik). İç ağda çalışan ve dışarı kapalı bir mesajlaşma kütüphanesinde bellek taşması. CISA KEV: Hayır, EPSS: 0.02 (%2).
- `CVE-B`: CVSS 7.8 (Yüksek). Dışa açık OpenSSH veya SSL-VPN geçidinde kimlik doğrulama bypass açığı. CISA KEV: **Evet (Aktif İstismar)**, EPSS: 0.91 (%91).

Eski yaklaşıma göre ekip CVE-A'ya odaklanırdı ve CVE-B'yi haftalık rutin döngüye bırakırdı. Bu süreçte saldırganlar CVE-B üzerinden içeri sızarak kurumu şifrelerdi.

**Bizim Motorumuzun Triyaj Çözümü (`patch_cve_engine.py`):**
```python
# Kural: KEV listesindeki açıklar doğrudan EMERGENCY ve 3 Gün SLA alır
urgency, max_days = engine.determine_urgency(cve_b)
# Sonuç: urgency="EMERGENCY", max_sla_days=3
```
Motor, CVE-B'yi doğrudan **EMERGENCY** ilan eder, acil CAB toplantısını tetikler ve 72 saat içinde yamalanmasını zorunlu kılar.

### 4. Ustanın Çırağa Tavsiyesi
> "Unutma evlat: CVSS sana 'silahın ne kadar güçlü olduğunu' söyler; CISA KEV ise 'o silahın şu an senin kafana doğrulup doğrultulmadığını' gösterir! Kafana doğrultulmuş bir tabanca (CVSS 7.5 ama KEV), depodaki bir nükleer bombadan (CVSS 10.0 ama istismarı yok) bin kat daha acildir. Triyaj yaparken daima KEV ve EPSS verisini CVSS'in önüne koyacaksın."

---

## Soru 2: Üretim Sistemlerinde Güvenli Yama Dağıtımı ve Regresyon / Geri Alma (Rollback) Yönetimi

### 1. Soru Başlığı ve Tanımı
Kritik bir sunucuda güvenlik yaması uygulandıktan sonra üretim servisinin çökmesi (regresyon) durumunda, sistem kesintisini en aza indirmek için aşamalı dağıtım (Canary/Staged Deployment) ve otomatik geri alma (rollback) boru hattı nasıl tasarlanmalıdır?

### 2. Derinlemesine Teknik Analiz
Yama operasyonları doğası gereği çalışan bir ikiliyi veya kütüphaneyi yenisiyle değiştirir. Bir güvenlik açığını kapatırken (örneğin glibc veya openssl güncellemesi), eski API çağrılarına dayanan kurum içi tescilli bir uygulamanın çökmesi (regression) en sık rastlanan operasyonel risklerden biridir.

Bu riski yönetmek için modern kurumsal mimarilerde **Aşamalı Dağıtım (Phased Rollout)** stratejisi uygulanır:
1. **Geliştirme / Staging Ortamı:** Yamalı paket önce test makinelerine kurulur ve otomatik testler koşturulur.
2. **Canary Dağıtımı (%10):** Üretim kümesindeki (cluster) sunucuların sadece bir tanesine yama uygulanır ve gerçek trafik altında performans/hata logları izlenir.
3. **Kademeli Yaygınlaştırma (%50 -> %100):** Belirlenen gözlem süresinde (canary window) hata tespit edilmezse tüm sunuculara yama tatbik edilir.

**Geri Alma (Rollback) Mimarisi:**
Yama uygulanmadan önce mutlaka ters işlem (reversal command) hazırlanmalıdır:
- Debian/Ubuntu ortamında: `apt-get install -y --allow-downgrades <paket>=<eski_surum>`
- RHEL/CentOS ortamında: `dnf downgrade -y <paket>-<eski_surum>`
- Sanallaştırma/Bulut seviyesinde: Yama öncesi oluşturulan disk anlık görüntüsü (LVM / ZFS / AWS EBS Snapshot) referans tutulur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux veritabanı sunucusunda `openssl` paketine kritik bir yama uygulanır. Ancak güncellemeden hemen sonra kurumun eski bir C++ socket uygulaması SSL el sıkışmasında `SIGSEGV` hatası vererek çöker. Üretim operasyonu durmuştur.

**Uygulanan Çözüm:**
Gün 141 projemizde geliştirdiğimiz motor:
```bash
python uygulama/cve_patch_cli.py rollback-plan ornek_veri/package_inventory_cve_spec.json --output /tmp/acil_geri_alma.sh
```
Komutu ile yama öncesinde otomatik olarak oluşturulmuş olan geri alma betiğini anında çalıştırır:
```bash
bash /tmp/acil_geri_alma.sh
```
Betik, paket yöneticisinde paketleri saniyeler içinde zafiyet öncesi kararlı sürüme indirger (`--allow-downgrades`), servisleri yeniden başlatır ve iş sürekliliği kesintiye uğramadan sorunlu yama izole edilir.

### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, arkasında geri dönüş köprüsü bırakmayan komutan ordusunu felakete sürükler. Yama yapmadan önce geri alma komutunu test etmeyen sistemci de kendi kuyusunu kazar. Bir yamayı uygulamak marifet değildir; marifet, yama patladığında 60 saniye içinde sistemi eski haline getirebilme soğukkanlılığına ve hazırlığına sahip olmaktır!"

---

## Soru 3: Linux'ta `unattended-upgrades` ve Yeniden Başlatma (`reboot-required`) İkilemi

### 1. Soru Başlığı ve Tanımı
Linux sunucularında `unattended-upgrades` ile otomatik yama yapılması önerilirken, çekirdek (kernel) ve glibc güncellemeleri sonrasında ortaya çıkan yeniden başlatma (`/var/run/reboot-required`) gereksinimi hizmet kesintisi yaratmadan nasıl yönetilir?

### 2. Derinlemesine Teknik Analiz
Linux işletim sisteminde çalışan bir süreç, bellek adres alanına yüklediği kütüphaneleri (örneğin `libc.so.6`) süreç sonlanana kadar bellekte tutmaya devam eder.
Paket yöneticisi (`apt` veya `dnf`) diske yeni bir `libc.so.6` yazsa dahi, bellekteki çalışan eski süreçler zafiyetli sürümü çalıştırmayı sürdürür. Bu duruma "çalışma zamanı uyumsuzluğu" (runtime inconsistency) denir.

Özellikle Linux çekirdeği (`linux-image-*`) güncellendiğinde, yeni çekirdek kodunun devreye girmesinin geleneksel tek yolu sistemin **yeniden başlatılmasıdır (reboot)**.
Bu durum gerçekleştiğinde işletim sistemi dosya sistemine bir bayrak bırakır:
`/var/run/reboot-required` (ve hangi paketlerin reboot istediğini listeleyen `/var/run/reboot-required.pkgs`).

**Reboot Yönetim Stratejileri:**
1. **Canlı Çekirdek Yamalama (Live Kernel Patching):** `kpatch`, `kgraft` veya Canonical `Livepatch` teknolojileri sayesinde, sistem yeniden başlatılmadan çekirdeğin ftrace mekanizması kullanılarak bellek içindeki zafiyetli fonksiyonlar dinamik olarak yamalanır.
2. **Kural Tabanlı Bakım Penceresi (Maintenance Windows):** `unattended-upgrades` dosyasında `Automatic-Reboot-Time "03:00"` ve `Automatic-Reboot "true"` direktifleri kullanılarak sunucunun yalnızca trafiğin en düşük olduğu gece saatlerinde ve yük dengeleyiciden (load balancer) otomatik çıkartılarak yeniden başlatılması sağlanır.
3. **`needrestart` veya `checkrestart` Araçları:** Yalnızca kütüphane güncellemelerinde, tüm sistemi kapatmak yerine sadece eski kütüphaneyi kullanan servisleri tespit edip sırayla yeniden başlatır (`systemctl restart <servis>`).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kritik bir ödeme API sunucusunda `openssl` ve Linux çekirdeği yamalanmıştır. Sistem yöneticisi `uptime` komutunda sunucunun 400 gündür ayakta olmasıyla övünmektedir. Ancak güvenlik taramasında sunucunun hala kritik bellek zafiyetlerine maruz olduğu tespit edilir; çünkü 45 gündür `/var/run/reboot-required` bayrağı aktif beklemektedir.

**Motorun Tespiti ve Çözüm:**
`patch_cve_engine.py` envanteri taradığında:
```
reboot_required = True -> Hijyen Puanından 10 puan ceza düşülür
Compliance Status: AT_RISK
Uygulama Betiğinde: Aşama 4 'Yeniden Başlatma Gereksinimi Denetimi' alarm üretir.
```
Sistem yöneticisi uyarılır; sunucu yük dengeleyiciden drenaj (drain) moduna alınır, planlı olarak yeniden başlatılır ve yeni çekirdeğin aktif olduğu doğrulanır.

### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, 500 gün açık kalan sunucuyla övünen sistem yöneticisi görürsen hemen oradan uzaklaş! Uzun uptime bir marifet değil, 500 gündür çekirdek yamalarının uygulanmadığının itirafıdır. Uptime'ı değil, yama hijyenini ve kontrollü bakım pencerelerini kutsayacaksın. Temiz bir reboot, zafiyetli bir kalıcılıktan evladır!"
