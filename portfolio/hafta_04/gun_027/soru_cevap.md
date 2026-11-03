# Hafta 04 — Gün 027: Soru & Cevap ve Senaryo Analizleri

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## Senaryo 1 (G027-SC1): Paket ve Güncelleme Yöneticileri Temel Mekanizması ve Güvenlik Önemi

### Senaryo Analizi ve Kapsam
Kurumsal bir Linux altyapısında sistem yöneticileri ve güvenlik analistleri, yazılım paketlerinin yaşam döngüsünü (kurulum, güncelleme, bağımlılık çözümleme ve kaldırma) yönetmek zorundadır. Ancak yazılım güncellemeleri salt bir yenilik veya güvenlik yaması değildir; hem işlev değişikliği (feature change) hem de güvenlik düzeltmesi (security patch) taşırlar. Ayrıca paketlerin temin edildiği kaynak deposunun (repository) güvenilirliği ve bütünlüğü, paket yöneticisinin kendisinden bağımsız olarak kriptografik yöntemlerle denetlenmelidir. Bu senaryonun kapsamı, paket yöneticilerinin çalışma mekanizmasını ve kaynak deposu doğrulama adımlarını ortaya koymaktır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **İşlev Değişikliği vs Güvenlik Düzeltmesi:** Bir yazılım güncellemesi yeni özellikler ve API değişiklikleri getirebilir; bu durum mevcut bağımlılıkları veya sistem kararlılığını bozabilir (breaking change). Güvenlik düzeltmesi ise keşfedilen bir güvenlik açığını (CVE) kapatmak amacıyla yayınlanan acil yamadır. Kurumsal sistemlerde bu iki kavram birbirinden ayrılmalı ve güvenlik yamaları backporting yöntemiyle API bozulmadan uygulanmalıdır.
2. **Kaynak Deposu Güvenilirliği ve Kriptografik İmza Doğrulama:** Paket yöneticileri (APT, DNF), uzak sunuculardaki paket listelerini (`Release`, `repomd.xml`) indirirken dağıtım sağlayıcısının özel GPG anahtarıyla imzalanmış olmasını şart koşar. Yerel sistemdeki `/etc/apt/trusted.gpg.d/` altındaki açık anahtarlar kullanılarak imza doğrulanır (CWE-347). İmza geçersizse paket indirme işlemi durdurulur.
3. **Şifresiz İletişim Riski (CWE-319):** Depolar `http://` protokolü üzerinden tanımlandığında, ağdaki Ortadaki Adam (MitM) saldırganları paket üstverilerini veya paketleri tahrif etme girişiminde bulunabilir. Bu nedenle tüm depolar zorunlu olarak TLS (`https://`) protokolünü kullanmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Depo ve Güvenlik Denetimi:**
  ```bash
  python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --inventory portfolio/hafta_04/gun_027/ornek_veri/sample_package_inventory.json --audit
  ```
- **Kanıt Dosyası:** `kanit/gercek/komut_ve_cikis.txt` dosyasında doğrulanmıştır. `thirdparty-untrusted-ppa` deposunun şifresiz HTTP kullandığı (`CWE-319`) ve GPG doğrulaması barındırmadığı (`CWE-347`) tespit edilerek kritik risk uyarısı verilmiştir.
- **Kritik Paket Zafiyet Tespiti:** `openssl 3.0.2` üzerinde `CVE-2024-0727` (CVSS: 7.5) zafiyeti tespit edilmiş, hedef sürüm `3.0.13` olarak belirlenmiştir.

### Savunma Kontrolleri ve Alınacak Dersler
- Yalnızca resmi ve doğrulanmış HTTPS depoları sisteme eklenmelidir.
- Yetkisiz PPA ve üçüncü taraf depolar engellenmelidir.
- Otomatik güncellemelerde yalnızca güvenlik depoları (`security.ubuntu.com` veya `rhel-security`) aktif edilmelidir.

---

## Senaryo 2 (G027-SC2): Bağımsız Laboratuvar Doğrulaması: Sürüm Sabitleme ve Geri Alma

### Senaryo Analizi ve Kapsam
Bir üretim ortamında kritik servislerin (veritabanı, web sunucusu, kripto kütüphaneleri) kontrolsüz şekilde güncellenmesi felakete yol açabilir. Bu senaryoda bağımsız bir laboratuvar deneyi kurgulanmıştır: Kontrollü bir envanter girdisi alınmış, sürüm sabitleme (pinning/hold) politikası uygulanmış, sabitlenmiş paketin güncellenmeye çalışılmasıyla negatif kontrol sınanmış, ardından serbest bir paket için güvenli güncelleme ve işlem günlüğü (journal) üzerinden geri alma (rollback) döngüsü doğrulanmıştır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Sürüm Sabitleme (Pinning / Version Locking):** Kritik servislerin istenmeyen veya zamansız majör güncellemelerden korunması için `apt-mark hold` veya `dnf versionlock add` mekanizmaları kullanılır. Bu mekanizma paket yöneticisinin paketi güncelleme listesinden çıkarmasını sağlar (CWE-1395 önleme).
2. **Negatif Kontrol:** Sabitlenmiş (`pinned: True`) bir paketin standart güncelleme çağrısıyla güncellenmeye çalışılması durumunda işlemin **bloke edilmesi** ve hata döndürülmesi zorunludur. Yönetici açıkça `--force` parametresi vermedikçe sürüm değişmemelidir.
3. **İşlem Günlüğü ve Geri Alma (Rollback):** Güncelleme öncesi mevcut sürüm ve hedef sürüm atomik bir işlem günlüğüne (`transaction journal`) kaydedilir. Güncelleme sonrasında olası bir hata durumunda sistem önceki kararlı duruma geri döndürülür.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
Laboratuvar akışı aşağıdaki komut zinciri ile icra edilmiş ve `kanit/gercek/guncelleme_ve_geri_alma_kaydi.txt` dosyasına kaydedilmiştir:
1. **Politika Notu Üretimi:**
   `python package_update_manager_auditor.py --policy-note`
2. **Kritik Paketi Sabitleme:**
   `python package_update_manager_auditor.py --inventory working_inventory.json --pin nginx`
   *(Çıktı: `[BASARILI] 'nginx' paketi donduruldu (pinned: True). Plansiz guncellemelere karsi koruma altinda.`)*
3. **Negatif Kontrol (Sabitlenmiş Paketi Güncelleme Denemesi):**
   `python package_update_manager_auditor.py --inventory working_inventory.json --update nginx 1.24.0`
   *(Çıktı: `[HATA] 'nginx' paketi sabitlenmistir (pinned). Guncelleme ENGELLENDI! Zorlamak icin --force parametresini kullanin.` — Çıkış Kodu: 1)*
4. **Güvenli Güncelleme (OpenSSL 3.0.2 -> 3.0.13):**
   `python package_update_manager_auditor.py --inventory working_inventory.json --journal journal.json --update openssl 3.0.13`
   *(Çıktı: `[BASARILI] 'openssl' paketi 3.0.2 surumunden 3.0.13 surumune yukseltildi. Islem gunlugune kaydedildi.`)*
5. **Geri Alma (Rollback Testi):**
   `python package_update_manager_auditor.py --inventory working_inventory.json --journal journal.json --rollback openssl`
   *(Çıktı: `[BASARILI] 'openssl' paketi 3.0.13 surumunden onceki 3.0.2 surumune GERI ALINDI (Rollback).`)*
- **Birim Testler:** 14/14 test PASS (`kanit/gercek/test_sonuclari.txt`).

### Savunma Kontrolleri ve Alınacak Dersler
- Herhangi bir paket güncellemesi yapılmadan önce geri alma planı ve yapılandırma yedekleri hazır olmalıdır.
- Üretim ortamlarında kritik paketler dondurulmalı (hold/pin), güncellemeler önce test ve kabul (staging) ortamlarında doğrulanmalıdır.

---

## Senaryo 3 (G027-SC3): Risk Oluşumu, Tespiti ve Önleyici Savunma Kontrolleri

### Senaryo Analizi ve Kapsam
Paket ve güncelleme yöneticileri bağlamında riskler; gereksiz izinler, yanlış yapılandırılmış servisler, güvensiz depo tanımları ve yamasız bilinen zafiyetler (Known Exploited Vulnerabilities) nedeniyle ortaya çıkar. Bu risklerin tespit edilmesi için periyodik paket ve servis envanteri fark raporları oluşturulmalı, savunma tarafında ise en az ayrıcalık ve geri alınabilir yapılandırma ilkeleri hayata geçirilmelidir.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Risk Nasıl Oluşur?**
   - **Gereksiz Paketler ve İzinler:** Sunucuda ihtiyaç duyulmayan derleyicilerin (`gcc`, `make`) veya servislerin (FTP, Telnet) kurulu olması, saldırı yüzeyini genişletir ve ayrıcalık yükseltme (privilege escalation) araçlarını saldırganın hizmetine sunar.
   - **Tedarik Zinciri ve Yetkisiz PPA Depoları:** Doğrulanmamış üçüncü taraf depolar, arkasında kötü niyetli paketler barındırabilir.
   - **Geciken Yamalar:** Bilinen CVE'lerin uzun süre yamalanmaması, otomatik exploit araçlarıyla sistemin ele geçirilmesine yol açar.
2. **Nasıl Tespit Edilir?**
   - **Paket Envanteri ve Fark Analizi:** Sistemdeki kurulu paketler baseline (referans) liste ile düzenli olarak karşılaştırılır. `package_update_manager_auditor.py` aracıyla depoların HTTPS/GPG durumları, kritik paketlerin sürüm sabitlemeleri ve bekleyen CVE'ler taranır.
3. **Hangi Kontrollerle Önlenir?**
   - **En Az Ayrıcalık (Least Privilege):** Paket yöneticisini yalnızca yetkili sistem yöneticileri `sudo` ile çalıştırabilmeli, root şifresi paylaşılmamalıdır.
   - **Sertleştirme (Hardening):** Derleyici ve gereksiz araçlar üretim sunucularından kaldırılmalıdır (`apt purge gcc make`).
   - **Geri Alınabilir Yapılandırma:** İşlem günlükleri (`dpkg.log`, `dnf history`) merkezi SIEM sistemine aktarılmalı, snapshot tabanlı anlık sistem yedekleri alınmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Fark ve Risk Denetimi:**
  Geliştirilen denetim aracı, `sample_package_inventory.json` üzerinde yaptığı analizde toplam 6 ihlal (4 kritik, 2 yüksek) tespit etmiştir. İhlal raporunda CWE eşleştirmeleri ve net iyileştirme yönergeleri sunulmuştur (`kanit/gercek/komut_ve_cikis.txt`).
- **Envanter Uyumluluk Skoru:** Başlangıç skoru %25.0 olarak ölçülmüş; sabitleme ve yama adımlarıyla tam uyumluluğa (%100.0) ulaşılmıştır.

### Savunma Kontrolleri ve Alınacak Dersler
- Paket yönetim süreçleri CI/CD pipeline'larına entegre edilmeli ve imzasız depolar derhal reddedilmelidir.
- "Çalışıyorsa dokunma" anlayışı yerine, kontrollü, sabitlenmiş ve geri alınabilir yama yönetimi standardı benimsenmelidir.
