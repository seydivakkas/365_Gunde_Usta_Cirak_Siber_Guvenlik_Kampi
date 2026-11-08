# Gün 152: Güvenli Yapılandırma Sapması (Configuration Drift) ve Otomatik İyileştirme

## Usta-Çırak / Hoca Dersi Notu

Evlat, siber güvenlik dünyasında bir uç noktayı (endpoint) kurup sıkılaştırmak (hardening) işin yalnızca ilk beş dakikasıdır. Asıl savaş, o uç noktanın **sıkılaştırılmış durumunu (hardened state)** zaman içinde, değişen iş koşulları, acil sistem müdahaleleri, yetkisiz yazılım yüklemeleri ve en önemlisi zararlı yazılımların gizli modifikasyonları karşısında koruyabilmektir.

Bugün konumuz **Yapılandırma Sapması (Configuration Drift)**. Bir sistemin onaylanmış güvenli referans noktasından (Golden Image / Hardened Baseline) zamanla habersizce uzaklaşması hadisesidir. Gel çırağım, bu derste uç noktaların nasıl sessizce savunmasız hale geldiğini, bu sapmayı nasıl anlık yakalayacağımızı ve "kendi kendini onaran (self-healing)" güvenli otomasyonları nasıl inşa edeceğimizi derinlemesine inceleyelim.

---

### 1. Yapılandırma Sapması Nedir ve Neden Kaçınılmazdır?

Bir sunucu veya istemci kurulduğunda, CIS (Center for Internet Security) Benchmarks veya DISA STIG kurallarına göre ilmek ilmek işlenir:
1. `User Account Control (UAC)` en üst seviyeye alınır (`EnableLUA=1`).
2. `Microsoft Defender` gerçek zamanlı koruması zorunlu kılınır (`DisableRealtimeMonitoring=0`).
3. `Local Security Authority (LSA)` koruması açılarak Mimikatz gibi bellek okuma araçlarına karşı koruma sağlanır (`RunAsPPL=1`).
4. `RemoteRegistry` gibi gereksiz saldırı yüzeyi sunan servisler devre dışı bırakılır.
5. Yerel `Administrators` grubunda yalnızca onaylı hesaplar tutulur.
6. Linux sunucularda `ASLR` (`kernel.randomize_va_space=2`) zorlanır ve paket yönlendirme (`net.ipv4.ip_forward=0`) kapatılır.

Ancak operasyon başlar başlamaz "sapma mikropları" devreye girer:
* **Acil Durum Müdahaleleri (Ad-Hoc Troubleshooting):** Bir sistem yöneticisi gecenin 03:00'ünde çöken bir veritabanı veya lisans sunucusunu ayağa kaldırmak için güvenlik duvarını kapatır (`Firewall=0`) veya UAC'yi devre dışı bırakır. Sorun çözülür ama o ayar asla eski güvenli haline getirilmez.
* **Gölge BT (Shadow IT) ve Geliştirici Talepleri:** Yazılımcılar yerel yönetici hakkı talep eder ve kendilerini yerel `Administrators` grubuna ekler.
* **Zararlı Yazılım ve APT Aktiviteleri:** Savunmayı zayıflatma (Defense Evasion - MITRE ATT&CK T1562.001) taktiği gereği, sisteme sızan bir zararlı ilk iş olarak Defender'ı veya Sysmon'u kayıt defterinden kapatır.

Bu sapmalar fark edilmediği sürece, kâğıt üzerinde "en yüksek güvenlik standartlarına sahip" olduğunu sandığın veri merkezin aslında delik deşik bir kalburdan farksız hale gelir.

---

### 2. Hardening Standartları: CIS Benchmarks ve DISA STIG

Sektörde güvenli referans noktası tanımlanırken iki dev otorite esas alınır:

1. **CIS Benchmarks (Center for Internet Security):**
   * **Level 1 (Temel / Kurumsal):** Saldırı yüzeyini ciddi oranda daraltırken kurumsal iş akışlarını ve uygulama uyumluluğunu aksatmayan pratik sıkılaştırma kurallarıdır.
   * **Level 2 (Yüksek Güvenlik / Defense-in-Depth):** Finans, savunma ve kritik altyapılarda kullanılan, bazı işlevleri kısıtlayabilen ama en üst düzey direnç sağlayan sıkılaştırma kurallarıdır.
2. **DISA STIG (Defense Information Systems Agency - Security Technical Implementation Guides):**
   * ABD Savunma Bakanlığı (DoD) standartlarıdır. İhlali halinde sistemin ağa bağlanması derhal yasaklanan (CAT I, CAT II, CAT III) kategorik kurallar bütünüdür.
3. **Microsoft Security Compliance Toolkit (SCT):**
   * GPO (Group Policy Object) tabanlı referans güvenlik şablonları sunar.

Bizim geliştirdiğimiz motor, bu standartları `BaselineConfig` nesneleri olarak modeller; platform tipine (Windows / Linux), kural kimliğine (CIS-WIN-001 vb.) ve önem derecesine (CRITICAL, HIGH, MEDIUM, LOW) göre etiketler.

---

### 3. Yapılandırma Sapmasını Tespit Etme Mimarisi

Sapmayı tespit etmek için temelde iki model bulunur:

1. **Çekme (Pull) Modeli (Agent / Periodic Scan):** Uç noktada çalışan bir servis (osquery, Wazuh, yerel audit motoru) periyodik olarak kayıt defterini, çalışan servisleri ve izinleri okur; referans durum ile karşılaştırır.
2. **İtme (Push / Centralized) Modeli:** Ansible, SaltStack veya PowerShell DSC (Desired State Configuration) merkezi bir sunucudan periyodik olarak uç noktaların durumunu sorgular (`Test-DscConfiguration`).

#### Tespit Motorunun Çalışma Mantığı:
```
[Hardened Baseline Spec]      [Canlı Sistem Telemetrisi (Current State)]
           \                                /
            \                              /
         +------------------------------------+
         |   ConfigDriftAuditor.audit()       |
         +------------------------------------+
                           |
        [Sapma Analizi (Drift Analysis)]
        - Kural İhlali Var mı? (is_drifted)
        - Beklenen Değer vs Mevcut Değer
        - Risk Skoru ve Ağırlıklı Ceza Puanı
                           |
          +----------------+----------------+
          |                                 |
 [Audit Raporu (JSON/Log)]       [Auto-Remediation Kararı]
                                            |
                                 +---------------------+
                                 | Düzeltme Betiği Üret|
                                 | (PowerShell / Bash) |
                                 +---------------------+
```

---

### 4. Uç Nokta Kritik Sapma Alanları

Geliştirdiğimiz motorda 5 temel yapılandırma tipi (`SettingType`) denetlenmektedir:

1. **Registry (Kayıt Defteri - Windows):**
   * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`: `1` olmalı (UAC devrede).
   * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring`: `0` olmalı (Defender aktif).
   * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`: `1` olmalı (LSA Protection).
2. **Service (Sistem Servisleri):**
   * `RemoteRegistry`: `Disabled` ve `Stopped` olmalı.
   * `Spooler`: Domain Controller'larda kapalı olmalı (PrintNightmare önlemi).
3. **Firewall (Güvenlik Duvarı):**
   * `Domain`, `Private`, `Public` profilleri her daim `Enabled` olmalı.
4. **UserGroup (Yetkili Kullanıcı Grupları):**
   * `Administrators` grubunda yalnızca whitelist'te yer alan onaylı hesaplar (`Domain Admins`, `LocalAdmin`) bulunmalı; yetkisiz geçici hesaplar derhal saptanmalı.
5. **Sysctl (Linux Çekirdek Parametreleri):**
   * `kernel.randomize_va_space`: `2` (Full ASLR).
   * `net.ipv4.ip_forward`: `0` (Sistem yetkisiz bir ağ router'ına dönüştürülmemeli).

---

### 5. Otomatik Düzeltme (Auto-Remediation / Self-Healing) ve Risk Yönetimi

Usta der ki: *"Körlemesine yapılan düzeltme, saldırganın verdiği zarardan daha büyük bir kesintiye yol açabilir."*

Bu nedenle otomatik iyileştirme mimarisi şu altın prensiplerle tasarlanmalıdır:
1. **Idempotence (Eşgüçlülük):** Düzeltme betiği 1 kez de çalışsa, 1000 kez de çalışsa sistemi her zaman aynı güvenli duruma getirmeli; yan etki üretmemelidir.
2. **Audit-First & Dry-Run (Önce Denetle, Sonra Onar):** Sistem önce sapmayı raporlamalı, kritik servislerde (örn. üretim veritabanı) doğrudan değişiklik yapmadan önce onay mekanizmasını tetiklemelidir.
3. **PowerShell DSC ve Ansible Felsefesi:** İyileştirme betikleri salt `Set-ItemProperty` yerine kontrol edip düzelten deterministik yapıda olmalıdır.

---

### 6. Günün Özeti ve Usta Öğüdü

Evlat! Bir sistemin güvenliği bir anlık durum değil, sürekli devam eden bir geri bildirim döngüsüdür. Uç noktalardaki yapılandırma sapmalarını günlük veya anlık olarak denetlemezsen, en pahalı EDR çözümlerin bile temeli çürük bir zeminde çalışmaya mahkûm kalır. Güvenli yapılandırma disiplini, siber savunmanın çelik zırhıdır.
