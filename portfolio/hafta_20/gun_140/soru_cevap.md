<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 140: Mini Proje 19 — Bütünleşik Linux Sertleştirme ve Denetim Çerçevesi — Usta-Çırak Soru & Cevap

Bu belgede, Hafta 20 boyunca ele alınan 6 temel güvenlik alanının bütünleşik olarak denetlenmesi, zafiyet zincirlerinin kırılması ve kurumsal Linux altyapılarında uyumluluk yönetimi üzerine 3 kritik soru ve derinlemesine teknik analizler yer almaktadır.

---

## Soru 1: Çok Katmanlı Zafiyet Zincirleri (Exploit Chains) ve Katmanlı Savunmanın Kırılma Noktaları

### 1. Soru Başlığı ve Tanımı
Bir Linux sunucusunda tek tek önemsiz görünen küçük konfigürasyon eksiklikleri (örneğin TMOUT tanımlanmaması, SSH MaxAuthTries yüksekliği, env_reset eksikliği) saldırganlar tarafından nasıl bir zafiyet zincirine (exploit chain) dönüştürülür ve katmanlı savunma (Defense-in-Depth) bu zinciri nerede kırar?

### 2. Derinlemesine Teknik Analiz
Siber saldırılarda tehdit aktörleri nadiren tek bir "sıfırıncı gün" (zero-day) zafiyeti ile tam yetki elde ederler. Çoğu başarılı saldırı, sistemdeki küçük konfigürasyon gevşekliklerinin birbirini tetiklemesiyle oluşan bir **saldırı zinciri** (Cyber Kill Chain / MITRE ATT&CK) üzerinden ilerler:

1. **Aşama 1 (İlk Erişim):** Güvenlik duvarında kısıtlanmamış bir test portu veya açık bırakılan şifresiz servis (örneğin port 8080'de çalışan zafiyetli bir web uygulaması).
2. **Aşama 2 (Kullanıcı Hesabı Elde Etme):** Web sunucusundaki bir RCE (Remote Code Execution) zafiyeti ile saldırgan `www-data` kullanıcısı haklarıyla sisteme girer.
3. **Aşama 3 (Yetki Yükseltme - Privilege Escalation):** Saldırgan `sudo -l` çeker. Sudoers dosyasında `www-data` kullanıcısının belirli bir yedekleme betiğini çalıştırmasına izin verilmiştir ancak `Defaults env_reset` tanımlanmamıştır. Saldırgan `LD_PRELOAD=/tmp/evil.so sudo /opt/backup.sh` komutuyla paylaşımlı kütüphane enjeksiyonu yaparak doğrudan `root` yetkisini ele geçirir.
4. **Aşama 4 (Kalıcılık ve İz Silme):** Saldırgan bir dinamik çekirdek modülü (LKM rootkit) yükler (`init_module`). Sistemde auditd kuralı `-e 2` ile kilitlenmediği için hemen `auditctl -D` çalıştırarak geçmiş adli kayıtları siler.

**Katmanlı Savunmanın Zinciri Kırma Rolü:**
Eğer sistem CIS standartlarına göre sertleştirilmiş olsaydı:
- Systemd kum havuzunda web servisine `NoNewPrivileges=yes` ve `ProtectSystem=strict` verilmiş olsaydı, `www-data` süreci alt süreçlerde SUID bitlerini kullanamaz ve dosya sisteminde değişiklik yapamazdı.
- Sudoers dosyasında `env_reset` zorunlu tutulsaydı, `LD_PRELOAD` enjeksiyonu engellenirdi.
- Auditd `-e 2` ile mühürlenmiş olsaydı, `init_module` çağrısı anında kaydedilir ve saldırgan logları silemezdi.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret platformunda geliştirici ekibi acil hata ayıklama (debug) için `/etc/sudoers` dosyasına şu satırı eklemiştir:
`deployer ALL=(root) NOPASSWD: /usr/bin/find`
Saldırgan ele geçirdiği `deployer` hesabı üzerinden şu GTFOBins komutunu çalıştırır:
```bash
sudo find . -exec /bin/sh \; -quit
```
Saldırgan şifre girmeden anında interaktif bir `root` kabuğu açmıştır.

**Uygulanan Denetim ve Çözüm:**
Geliştirdiğimiz `linux_hardening_audit_engine.py` aracı çalıştırıldığında:
```
[-] SUDO: CIS-1.3.4 - Tehlikeli NOPASSWD Yetkilendirmesi Tespit Edildi
    Mevcut Değer: Shell Escape: True
    Çözüm: Sudoers kurallarından tehlikeli NOPASSWD: ALL ve kabuk tetikleyici komutları kaldırın.
```
Otomatik sıkılaştırma betiği (`otomatik_sikilastirma.sh`) çalıştırılarak riskli satır kaldırılır, `visudo -c` ile sözdizimi doğrulanır ve yetki devri en düşük ayrıcalık ilkesine (PoLP) geri döndürülür.

### 4. Ustanın Çırağa Tavsiyesi
> "Unutma evlat: Bir saldırgan kalenin en güçlü surlarına saldırmaz; nöbetçinin açık unuttuğu arka pencereyi arar. Güvenlikte 'önemsiz detay' diye bir şey yoktur. `env_reset` satırını gereksiz görüp silen yönetici, kendi eliyle saldırgana root anahtarını teslim etmiştir. Tüm katmanları aynı titizlikle denetleyeceksin."

---

## Soru 2: Sürekli Uyumluluk (Continuous Compliance) ve Konfigürasyon Sapması (Configuration Drift)

### 1. Soru Başlığı ve Tanımı
Linux sunucularında konfigürasyon sapması (configuration drift) nedir, sertleştirilmiş bir sunucu zamanla nasıl güvensiz hale gelir ve CI/CD / Cron tabanlı otomatik denetim motorları bu sapmayı nasıl engeller?

### 2. Derinlemesine Teknik Analiz
**Konfigürasyon Sapması (Configuration Drift):**
Bir sistemin onaylanmış güvenli referans durumundan (baseline) zaman içinde plansız, belgelenmemiş ve yetkisiz değişikliklerle uzaklaşması olgusudur.
Pratikte şu yollarla ortaya çıkar:
1. **Acil Durum Müdahaleleri:** Gece nöbetindeki bir sistem mühendisi üretim kesintisini gidermek için güvenlik duvarında `ufw disable` yapar veya `chmod 777` verir ve bunu geri almayı unutur.
2. **Yazılım Paket Güncellemeleri:** `apt upgrade` veya `dnf update` sırasında paket yöneticisi varsayılan konfigürasyonu üzerine yazabilir (örneğin `/etc/pam.d/common-auth` veya `/etc/ssh/sshd_config`).
3. **Yeni Servis Dağıtımları:** Geliştiricilerin sisteme eklediği yeni bir systemd birimi, sandboxing direktiflerinden (`NoNewPrivileges`, `PrivateTmp`) yoksun olarak dağıtılır.

**Otomasyon ile Çözüm Mimarisi:**
Sertleştirme bir defalık bir "proje" değil, yaşayan bir "süreçtir". Bu sebeple:
1. Geliştirdiğimiz CLI aracı (`hardening_audit_cli.py verify`) her gece saat 02:00'de Cron görevi olarak çalıştırılır:
   ```cron
   0 2 * * * /usr/bin/python3 /opt/sec_engine/hardening_audit_cli.py verify /etc/sec_inventory.json || /usr/bin/python3 /opt/sec_engine/hardening_audit_cli.py generate-remediation /etc/sec_inventory.json -o /tmp/fix.sh && bash /tmp/fix.sh
   ```
2. Ansible, Puppet veya SaltStack benzeri konfigürasyon yönetimi araçları ile referans durum zorlanır (idempotency).
3. Herhangi bir sapma durumunda SIEM sistemine webhook veya syslog üzerinden anında uyarı iletilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir finans kurumunda yapılan penetrasyon testinde, 6 ay önce CIS uyumlu sertleştirilmiş olan bir Linux sunucusunun SSH portunun parolalı erişime açıldığı ve `PermitRootLogin yes` yapıldığı görülmüştür. Olay analizi yapıldığında, 3 hafta önce bir stajyerin SCP ile dosya aktarmakta zorlanması üzerine geçici olarak bu ayarları değiştirdiği ve öylece unuttuğu ortaya çıkmıştır.

**Önleme:**
Gün 140 projemizde geliştirdiğimiz denetim motoru:
```bash
python uygulama/hardening_audit_cli.py audit ornek_veri/enterprise_linux_audit_inventory.json --output /var/log/audit_report.json
```
Komutu ile taranır. Puanın 100'den 66.7'ye düştüğü, `CIS-5.2.1` ve `CIS-5.2.2` kurallarının `FAIL` olduğu anında raporlanır. `--output` ile üretilen Bash scripti çalıştırılarak `sshd_config` saniyeler içinde eski güvenli haline getirilir.

### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, sertleştirdiğin bir sunucuyu kendi haline bırakmak, bahçeyi ekip hiç sulamadan meyve beklemeye benzer. Yabani otlar (hatalı konfigürasyonlar) mutlaka biter. Gerçek usta, sistemi bir kez kurup arkasını dönen değil; her gece o bahçeyi denetleyen otomasyon çitini örendir."

---

## Soru 3: Otomatik İyileştirme (Auto-Remediation) Riskleri ve Güvenli Sıkılaştırma Stratejisi

### 1. Soru Başlığı ve Tanımı
Otomatik sıkılaştırma betiklerinin (auto-remediation scripts) üretim ortamlarında körü körüne çalıştırılması hangi operasyonel riskleri (hizmet kesintisi, lockout) doğurur ve güvenli bir düzeltme boru hattı nasıl tasarlanmalıdır?

### 2. Derinlemesine Teknik Analiz
Otomatik iyileştirme, güvenlik ekiplerinin hayalidir ancak dikkatli yönetilmezse en büyük operasyonel kabusa dönüşebilir:

1. **Yönetici Kilitlenmesi (Lockout Riski):**
   - Sunucuda henüz geçerli bir SSH genel anahtarı (`authorized_keys`) tanımlanmadan veya kullanıcının anahtarla giriş yapabildiği teyit edilmeden `PasswordAuthentication no` ve `PermitRootLogin no` uygulanırsa, sunucuya olan tüm uzaktan erişim kalıcı olarak kesilebilir.
2. **Servis Çökmesi (Service Crash):**
   - Systemd servisinde `ProtectSystem=strict` veya `ProtectHome=yes` direktifi rastgele eklenirse; veritabanı veya log yazmak için `/var` veya `/home` dizinini kullanan servis anında çöker (`EACCES - Permission denied`).
3. **Güvenlik Duvarı İzolasyonu (Network Blackhole):**
   - Güvenlik duvarında varsayılan politika `DROP` yapılırken, mevcut aktif SSH oturumunu koruyacak `ct state established,related accept` kuralı yazılmazsa, betik o anda çalışan yöneticinin bağlantısını koparır ve sunucuyu ağdan izole eder.

**Güvenli Sıkılaştırma Boru Hattı (Safe Remediation Pipeline):**
Güvenli bir iyileştirme için 4 aşamalı protokol uygulanmalıdır:
1. **Denetim Modu (Audit-Only / Dry-Run):** İlk aşamada hiçbir ayar değiştirilmez; yalnızca zafiyetler ve sapmalar raporlanır (`audit` komutu).
2. **Staging / Test Ortamında Doğrulama:** Üretilen `otomatik_sikilastirma.sh` betiği birebir klonlanmış test sunucusunda koşturulur, servislerin ayakta kaldığı doğrulanır.
3. **Geri Alma (Rollback) Planı:** Her değişiklikten önce konfigürasyon dosyalarının zaman damgalı kopyası alınır (`cp /etc/sudoers /etc/sudoers.bak_$(date +%s)`).
4. **Sözdizimi Doğrulama:** Betik çalıştığında `visudo -c` veya `sshd -t` test komutları koşturulur; hata varsa değişiklik geri alınır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Yeni işe başlayan bir güvenlik analisti, CIS Benchmark uyumunu %100 yapmak için üretim ortamındaki bir Kubernetes worker node üzerinde doğrudan şu komutu koşturur:
`systemctl stop telnet rsh vsftpd cups` ve güvenlik duvarında `nft add rule inet filter input drop`.
Ancak Kubernetes pod'larının haberleştiği `cni` arayüzü istisna tutulmadığı için cluster'ın tüm ağ trafiği felç olur.

**Bizim Mimari Çözümümüz:**
Geliştirdiğimiz `linux_hardening_audit_engine.py` betiğinde:
- Otomatik düzeltme betiği (`otomatik_sikilastirma.sh`) üretilirken, `set -euo pipefail` emniyeti kullanılır.
- Kritik servisler körü körüne silinmez; yalnızca hedefte kurulu ve çalışan güvensiz servisler (`2>/dev/null || true` ile kontrollü olarak) durdurulur.
- Çözüm adımları bağımsız fonksiyonlar olarak sunularak sistem yöneticisinin her kuralı inceleyip onaylamasına olanak tanır.

### 4. Ustanın Çırağa Tavsiyesi
> "Kulağına küpe olsun çırak: En güvenli sunucu, fişi çekilmiş, kabloları kesilmiş ve denizin dibine atılmış sunucudur; ama kimseye hizmet veremez! Bizim işimiz sistemi kapatmak değil, hizmet vermeye devam ederken kurşun geçirmez kılmaktır. Asla test etmediğin bir düzeltme betiğini canlı sistemde 'Enter' tuşuna basarak çalıştırma. Önce ölç, sonra biç!"
