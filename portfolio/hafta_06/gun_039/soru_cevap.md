<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 039 — Soru & Cevap ve Didaktik İnceleme

## G039-SC1: Yedekleme, Anlık Görüntü (Snapshot) ve RAID Ayrımı ile Geri Yükleme Doğrulamasının Önemi

### Temel Kavram ve Güvenlik Mekanizması
Veri koruma ve felaket kurtarma mühendisliğinde en sık karıştırılan üç kavram: Yedek (Backup), Anlık Görüntü (Snapshot) ve RAID (Redundant Array of Independent Disks) mimarileridir:
1. **RAID (Yüksek Erişilebilirlik - High Availability):** Fiziksel disk arızalarına karşı donanımsal tolerans sağlar. Canlı dosya silindiğinde, bozulduğunda veya fidye yazılımı (ransomware) tarafından şifrelendiğinde, bu işlem milisaniyeler içinde tüm disklere eşzamanlı yansıtılır. RAID geçmişe dönük bir kopyalama veya geri alma mekanizması sunmaz; bu nedenle **kesinlikle bir yedekleme DEĞİLDİR**.
2. **Snapshot (Anlık Durum Dondurma):** Dosya sistemi veya sanal makinenin o anki meta veri durumunu işaretçilerle (pointers / Copy-on-Write) dondurur. Çok hızlıdır ancak birincil verinin bulunduğu depolama havuzunda (Storage Pool) saklandığı sürece, depolama ünitesinin kendisi arızalandığında snapshot'lar da kaybolur. Ayrıca fidye yazılımları yerel snapshot'ları (`vssadmin delete shadows`, `Get-VMSnapshot | Remove-VMSnapshot`) anında hedefler.
3. **Gerçek Yedek (Backup - 3-2-1):** Canlı sistemden tamamen bağımsız, farklı kimlik doğrulama yetkisine sahip, taşınabilir ve geçmişe dönük versiyonlanmış veri arşivleridir.

**Geri Yükleme Doğrulamasının (Restore Verification) Hayati Rolü:**
Bir yedekleme işinin "Başarılı (Green/OK)" bitmesi, verinin gerçekten geri yüklenebilir olduğunu KANITLAMAZ (Schrödinger'in Yedeği). Sadece verinin diske yazıldığını gösterir. Bozuk bloklar (bit rot), eksik veritabanı transaction logları, şifreleme anahtarı eksikliği veya uyumsuz depolama sürücüleri ancak gerçek bir geri yükleme tatbikatı (Restore Drill) yapıldığında anlaşılır. Test edilmemiş bir yedek, felaket anında hiç var olmamış sayılır.

### Soru ve Didaktik Çözüm
**Soru:** Yedekleme, snapshot ve RAID teknolojilerinin çalışma prensipleri ve sağladığı koruma sınırları nelerdir? Neden RAID veya aynı havuzdaki snapshot bir yedek olarak kabul edilemez ve geri yükleme testi yapılmayan bir yedekleme stratejisi neden güvenilemezdir?

**Didaktik Çözüm:**
- **RAID Sınırı:** RAID 5 veya RAID 6, disk sürücüsünün motoru yandığında sunucunun kapanmasını engeller. Ancak bir yönetici kazara `rm -rf /` veya `DROP DATABASE` çalıştırdığında veya saldırgan LockBit fidye yazılımını çalıştırdığında RAID parite blokları bu yıkıcı işlemi sadakatle tüm disklere uygular. Veri kalıcı olarak yok olur.
- **Snapshot Sınırı:** Snapshot bağımsız bir veri kopyası değildir; orijinal veri bloklarına referans veren bir fihristtir. Ana LUN bozulduğunda fihrist anlamsızlaşır.
- **Geri Yükleme Testi Zorunluluğu:**
  - Yedek dosyaları saklama ortamında sessiz veri bozulmasına (silent data corruption) uğrayabilir.
  - Veritabanı tutarlılığı (crash-consistency vs application-consistency) test edilmemişse, geri yüklenen SQL veritabanı "Suspect" veya "Inconsistent" durumuna düşerek açılmayabilir.
  - Bu nedenle ISO 27001 (A.12.3.1) ve NIST SP 800-34 standartları düzenli geri yükleme testlerini zorunlu kılar.

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizması:**
  - Depolama envanterinde yedekleme hedeflerinin incelenmesi:
    - Hedef canlı SAN ile aynı LUN mu? (Risk!)
    - Tek bir RAID dizisi mi yedek sanılıyor? (Risk!)
    - En son geri yükleme testi ne zaman yapılmış? (>90 gün ise Alarm!)
- **Savunma Stratejisi:**
  - 3-2-1 Kuralını tavizsiz uygulamak: 3 Kopya, 2 Farklı Medya, 1 Tesis Dışı.
  - Otomatik Geri Yükleme Tatbikatları (Automated Sandbox Restore): Veeam SureBackup veya özel betiklerle yedek arşivleri haftalık olarak izole bir VLAN'da sanal makineye dönüştürülmeli, veritabanı servisinin açıldığı (`systemctl status postgresql`) doğrulanıp rapor üretilmelidir.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Evlat, sana 'Bizim RAID-6 depomuz var, 2 disk yansa bile bir şey olmaz, o yüzden harici yedek almıyoruz' diyen sistemci görürsen hemen oradan uzaklaş. Bir fidye yazılımı o sunucuya girdiğinde o 2 diskin yanmasını beklemez; 1 saniyede tüm RAID dizisini kriptolar, yöneticisini de kapının önüne koydurur."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi (`backup_strategy_321_auditor.py`), `relies_on_raid_as_backup: true` kaydını gördüğü an acımasızca **CRITICAL** mimari hata basar.

---

## G039-SC2: 3-2-1 Yedekleme Planı Tasarımı, Kontrollü Girdi ve Geri Yükleme Doğrulama Laboratuvarı

### Temel Kavram ve Güvenlik Mekanizması
Kurumsal bir yedekleme planı gelişi güzel alınamaz; iş yüklerinin kritiklik seviyelerine (Tier 1 Mission Critical, Tier 2 Business Critical, Tier 3 Non-Critical) göre RPO (Recovery Point Objective) ve RTO (Recovery Time Objective) hedefleriyle tasarlanmalıdır.

Güvenilir bir yedekleme denetim laboratuvarının mimari bileşenleri:
1. **Kontrollü Girdi (Controlled Input):** Sistem telemetrisi; iş yükü adı, kritiklik derecesi, toplam kopya sayısı, kullanılan medya türleri, tesis dışı (offsite) kopya sayısı, değiştirilemezlik (immutability/WORM) durumu, son geri yükleme test tarihi ve bütünlük algoritmasını (SHA256 checksum) yapılandırılmış JSON şemasıyla almalıdır.
2. **Gözlenebilir Çıktı (Observable Output):** Üretilen rapor; 3-2-1 kuralının 4 temel ekseninde (kopya, medya, offsite, immutability) ve geri yükleme sıklığında tespit edilen açıkları, ciddiyet seviyesini ve iyileştirme yönergelerini insan-okunabilir Markdown formatında sunmalıdır.
3. **Olumlu ve Olumsuz Doğrulama:**
   - *Olumlu Test (Positive Control):* Kusursuz yapılandırılmış Tier 1 veritabanı (3 kopya, NVMe+NAS+S3 Glacier, 1 offsite, S3 Object Lock Compliance Mode, 14 gün önce başarılı test, SHA256 checksum) temiz geçmelidir.
   - *Olumsuz Test (Negative Control):* Negatif kopya sayısı (`-1`), sayısal olmayan test günü (`"gecen_hafta"`), negatif gün ve eksik anahtarlar anında yakalanmalı ve `BackupTelemetryValidationError` üretilmelidir.
4. **Etik ve Operasyonel Sınırlar:** Canlı yedekleme depolarında doğrudan silme veya formatlama testleri yapılmaz; tatbikatlar yalnızca izole test ortamlarında (Sandbox / Test Hypervisor) salt-okunur doğrulama mantığıyla yürütülür.

### Soru ve Didaktik Çözüm
**Soru:** Kritik kurumsal iş yükleri için 3-2-1 kuralına uygun bir yedekleme planı ve geri yükleme doğrulama laboratuvarı nasıl tasarlanır? Laboratuvarın kontrollü girdisi, işlem basamakları, beklenen çıktıları ve negatif kontrolleri nelerdir?

**Didaktik Çözüm:**
1. **Girdi:** `sample_backup_inventory.json` dosyası.
   - `POL-CORE-DB`: Tam uyumlu 3-2-1 (3 kopya, NVMe/NAS/S3, 1 offsite, S3 Object Lock, 14 gün önce test edilmiş, SHA256).
   - `POL-LEGACY-FS`: Uyumsuz (1 kopya, yalnızca yerel RAID5, 0 offsite, değiştirilemezlik yok, HİÇ TEST EDİLMEMİŞ - Schrödinger'in Yedeği).
   - `POL-VM-INFRA`: Kısmi uyumsuz (2 kopya, aynı SAN havuzunda snapshot, 0 offsite, test 120 gün önce yapılmış - güncelliğini yitirmiş).
2. **İşlem:**
   - Şema doğrulaması (`validate_telemetry_schema`)
   - 3-2-1 kural uyumluluk analizi (`audit_321_rule_compliance`)
   - Geri yükleme testleri ve Schrödinger analizi (`audit_restore_verification_and_testing`)
   - RAID ve Snapshot yanılgıları analizi (`audit_raid_and_snapshot_misconceptions`)
   - RPO hedef sapması analizi (`audit_rpo_compliance`)
3. **Beklenen Çıktı:** Güvenlik skoru 0 olan, 6 CRITICAL, 6 HIGH ve 4 MEDIUM bulgu içeren, her açık için düzeltme reçetesi sunan Markdown raporu.
4. **Negatif Kontroller:** `corrupted_backup_inventory_test_cases.json` dosyasındaki 4 bozuk senaryonun sistem tarafından başarıyla reddedilmesi.

### Savunma ve Tespit Kılavuzu
- **Yedekleme Sağlama Toplamı (Checksum) Doğrulaması:**
  Yedek arşivi alındığında SHA256 karması hesaplanmalı ve güvenli bir veri tabanına yazılmalıdır:
  ```bash
  sha256sum backup_db_20261027.tar.gz > backup_db_20261027.sha256
  # Geri yükleme öncesinde doğrulama:
  sha256sum -c backup_db_20261027.sha256
  ```
- **İzole Test Otomasyonu:** CI/CD veya zamanlanmış görevlerle sanal makinelerin otomatik ayağa kaldırılıp port kontrolü (`nc -zv localhost 5432`) yapılması.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak, geri yükleme testini sadece 'dosya açıldı mı' diye yapmayacaksın. O veritabanı ayağa kalktıktan sonra içine bir SELECT sorgusu atacaksın, tabloların bozulup bozulmadığını (table corruption) göreceksin. Dosyanın diske inmesi başka şeydir, uygulamanın o dosyayı kabul etmesi bambaşka şeydir."
- *Laboratuvar İpucu:* Test paketimiz (`test_backup_strategy_321_auditor.py`), 14 bağımsız senaryoyla geri yükleme günlerini ve WORM yeteneklerini tek tek denetler.

---

## G039-SC3: Yedekleme Altyapısı Riskleri, Fidye Yazılımları (Ransomware) ve En Az Ayrıcalık Kuralı

### Temel Kavram ve Güvenlik Mekanizması
Yedekleme altyapısı, şirket verilerinin tamamının konsolide edildiği en değerli hazinedir. Bu nedenle modern fidye yazılımı aktörlerinin (Big Game Hunting) 1 numaralı hedefidir.

Fidye yazılımlarının yedekleme sistemlerini imha etme taktikleri:
1. **Windows Gölge Kopyalarının (VSS) Silinmesi:** Saldırgan ele geçirdiği uç noktada ilk olarak `vssadmin delete shadows /all /quiet` veya PowerShell `Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }` çalıştırarak anlık dönüş imkanını yok eder.
2. **Yedekleme Paylaşımlarının Şifrelenmesi:** Windows veya Linux üzerinde çalışan yedekleme hedefleri (NAS, SMB, NFS paylaşımları) kurumsal Active Directory etki alanına dahil edilmişse; saldırgan Domain Admin yetkisiyle tüm bu paylaşımlara erişir ve yedek dosyalarını (`.vbk`, `.tib`, `.bak`) siler veya kendi anahtarıyla şifreler.
3. **Değiştirilemezlik (Immutability / WORM) Savunması:** Veri yazıldıktan sonra dosya sistemi veya depolama seviyesinde kilitlenir. Kök yetkisi (root/admin) dahi olsa belirlenen süre dolmadan dosya silinemez, üzerine yazılamaz.
4. **Hava Boşluğu (Air-Gapping):** Ağ bağlantısı bulunmayan çevrimdışı manyetik teyp veya izole edilmiş (unrouted, tek yönlü veri diyotlu) yedekleme ortamlarıdır.

### Soru ve Didaktik Çözüm
**Soru:** Yedekleme sistemleri bağlamında; gereksiz izinler, yanlış servisler ve hatalı erişim yapılandırmaları ne tür felaketlere yol açar? Bu riskler kullanıcı, izin ve servis envanteriyle nasıl tespit edilir ve "En Az Ayrıcalık" ile "Geri Alınabilir Yapılandırma" ilkeleriyle nasıl engellenir?

**Didaktik Çözüm:**
1. **Risk Tespiti ve Envanter:**
   - **Etki Alanı Entegrasyonu Taraması:** Yedekleme sunucusunun (Veeam/Commvault vb.) Active Directory etki alanına üye yapılıp yapılmadığının tespiti. (Yedekleme sunucusu asla kurumsal AD'ye üye YAPILMAMALIDIR! İzole bir çalışma grubunda - Workgroup - veya bağımsız bir yönetim ormanında tutulmalıdır).
   - **Depolama İzinleri Taraması:** Yedekleme havuzunun (Repository) SMB/NFS paylaşımı olarak herkese veya Domain Admin grubuna tam yetkiyle açılıp açılmadığının denetimi.
   - **WORM/Immutability Denetimi:** Linux Hardened Repository üzerinde `chattr +i` veya S3 üzerinde `Object Lock Compliance Mode` olup olmadığının kontrolü.
2. **Savunma Stratejisi (En Az Ayrıcalık & Mimari İzolasyon):**
   - **Bağımsız Kimlik Doğrulama:** Yedekleme altyapısı için Active Directory'den tamamen bağımsız, çok faktörlü kimlik doğrulama (MFA) zorunlu kılınmış yerel kullanıcılar kullanılmalıdır.
   - **Linux Hardened Repository (XFS + Immutability):** Yedekleme deposu olarak tek kullanımlık kimlik bilgileriyle (single-use credentials) çalışan Linux sunucu yapılandırılmalı; yazılan yedekler çekirdek seviyesinde değiştirilemez yapılmalıdır:
     ```bash
     # XFS üzerinde değiştirilemez bayrak:
     chattr +i /backup/repository/backup_job_01.vbk
     ```
   - **S3 Object Lock (Compliance Mode):** Bulut yedeklerinde "Governance Mode" yerine "Compliance Mode" seçilmelidir. Governance modunda root hesabı kilidi kaldırabilirken, Compliance modunda AWS destek ekibi dahi süre bitmeden dosyayı silemez.
   - **Geri Alınabilirlik:** Yedekleme yapılandırma veritabanı (Configuration Backup) düzenli olarak şifrelenmeli ve çevrimdışı bir teypte veya güvenli bir USB kasasında saklanmalıdır.

### Savunma ve Tespit Kılavuzu
- **Sertleştirme Kontrol Listesi:**
  1. Yedekleme sunucusunda RDP, SMBv1 ve gereksiz uzak yönetim servisleri kapalı mı?
  2. Uç noktalarda yerel yedekleme ajanlarının servis hesapları "Domain Admin" yetkisine sahip mi? (Yalnızca "Backup Operator" veya en düşük yetkili yerel hesap olmalıdır).
  3. Yedekleme havuzları doğrudan işletim sistemi dosya paylaşımı olarak mı sunuluyor yoksa güvenli ajan protokolü (mTLS) üzerinden mi iletişim kuruluyor?
  4. Offsite kopyalar bağımsız bir şifreleme parolası (KMS / AES-256) ile kilitlenmiş mi?

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak, yedekleme sunucusunu gidip şirket domainine üye yapan bir sistemci görürsen bil ki o adam şirketin idam fermanını imzalamıştır. Saldırgan Domain Admin'i aldığı anda yedek sunucusuna da admin olur; 10 dakikada tüm geçmişi siler süpürür. Yedekleme sunucusu etki alanının dışında, tek başına bir ada olmalıdır."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi, `is_immutable_or_airgapped: false` gördüğü an doğrudan **CRITICAL** alarm üretir ve S3 Object Lock / WORM reçetesini ekrana basar.
