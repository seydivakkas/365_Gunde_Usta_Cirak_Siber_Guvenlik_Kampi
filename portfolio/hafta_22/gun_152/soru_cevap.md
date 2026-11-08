# Gün 152: Güvenli Yapılandırma Sapması — Soru & Cevap

---

## 1. Soru: Kayıt Defteri Tabanlı Savunma Zayıflatma (Defense Evasion) ve RunAsPPL Koruması

### Soru
Saldırganlar veya zararlı yazılımlar sistemde yerel yönetici (Local Administrator) hakları elde ettiklerinde, uç nokta tespit sistemlerini atlatmak (T1562.001) ve LSASS belleğini dökmek (T1003.001) için neden ilk olarak `DisableRealtimeMonitoring` ve `RunAsPPL` kayıt defteri değerlerini hedeflerler? Bu iki ayarın sapması uç nokta güvenliğini nasıl felç eder ve bunu engellemek için hangi karşı tedbirler uygulanmalıdır?

### Detaylı ve Kapsamlı Teknik Cevap
Saldırganların nihai hedeflerinden biri, bellekte (LSASS - Local Security Authority Subsystem Service) saklanan oturum açmış kullanıcı kimlik bilgilerini (NTLM özetleri, Kerberos biletleri - TGT/TGS ve düz metin parolaları) ele geçirmektir. Bu süreçte Mimikatz veya benzeri araçlar kullanılır.

Ancak modern Windows işletim sistemlerinde iki kritik savunma hattı bulunur:
1. **Microsoft Defender Gerçek Zamanlı Koruma (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring`):** Bu anahtar `1` yapıldığında Defender'ın dosya sistemi ve bellek üzerindeki anlık izleme motoru tamamen körleştirilir. Saldırgan veya zararlı yazılım, bilinen araçları diske yazabilir ve belleğe yükleyebilir.
2. **LSA Protection (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`):** Bu ayar `1` (veya `2`) yapıldığında, LSASS işlemi **Protected Process Light (PPL)** seviyesine yükseltilir. PPL seviyesinde çalışan bir işleme, yerel yönetici veya SYSTEM haklarına sahip bir süreç dahi `PROCESS_VM_READ` veya `PROCESS_VM_WRITE` erişim yetkisiyle `OpenProcess` çağrısı yapamaz. Mimikatz'ın LSASS bellek dökümü alması çekirdek düzeyinde engellenir.

**Sapmanın Yarattığı Tehdit:**
Bir yönetici hata ayıklama amacıyla veya zararlı bir script aracılığıyla `RunAsPPL=0` ve `DisableRealtimeMonitoring=1` yaparsa, uç noktanın kimlik doğrulama omurgası tamamen savunmasız kalır.

**Karşı Tedbirler:**
- **Tamper Protection:** Microsoft Defender'ın kurcalamaya karşı koruması (Tamper Protection) açılarak yerel yöneticilerin dahi bu kayıt defteri anahtarlarını değiştirmesi engellenmelidir.
- **Credential Guard (VBS):** Donanım tabanlı sanallaştırma (Virtualization-Based Security) ile LSASS izole bir sanal alanda (Isolated User Mode - IUM) çalıştırılmalıdır.
- **Anlık Konfigürasyon Sapma Denetimi:** Bu değerler periyodik olarak sorgulanmalı ve baseline dışı bir değişim algılandığında derhal SIEM alarmı üretilip otomatik iyileştirme tetiklenmelidir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat, yerel yönetici hakkına sahip olmak işletim sisteminin tanrısı olmak demek değildir; olmamalıdır! `RunAsPPL` ve `Tamper Protection`, yöneticinin bile kendi ayağına sıkmasını engelleyen emniyet kemerleridir. Eğer bir denetimde `DisableRealtimeMonitoring=1` veya `RunAsPPL=0` görürsen, bunu sıradan bir konfigürasyon hatası değil, "aktif bir saldırı göstergesi (IoC)" kabul edip derhal olay müdahale prosedürünü başlatacaksın!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2023 yılında küresel bir lojistik firmasının IT destek ekibi, lisanslı bir muhasebe yazılımının güncellemesi hata verince geçici bir çözüm olarak tüm istemcilerde GPO üzerinden `DisableRealtimeMonitoring=1` yaptı. "Yazılım kurulunca kapatırız" dedikleri bu geçici değişiklik 3 hafta boyunca unutuldu. Tam bu esnada bir çalışan oltalama e-postasındaki makrolu Excel dosyasını açtı. Normal şartlarda Defender tarafından anında engellenecek olan Qakbot türevi zararlı, sıfır dirençle sisteme yerleşti, Mimikatz ile etki alanı yöneticisinin hash'lerini döktü ve 48 saat içinde 800 sunucu BlackCat fidye yazılımıyla şifrelendi. Küçük bir ayar sapması şirkete 4 milyon dolara mal oldu.

---

## 2. Soru: Desired State Configuration (DSC) ve "Self-Healing" Sistemlerde Sapma Yönetimi

### Soru
PowerShell Desired State Configuration (DSC) veya Ansible gibi sistemlerde yapılandırma sapmasını (configuration drift) yönetirken "ApplyAndMonitor" ile "ApplyAndAutoCorrect" modları arasındaki mimari farklar nelerdir? Kritik kurumsal ortamlarda neden doğrudan agresif otomatik düzeltme (Auto-Correction) yerine kademeli bir yaklaşım tercih edilir?

### Detaylı ve Kapsamlı Teknik Cevap
Konfigürasyon yönetiminde Desired State Configuration (DSC), sistemin istenen durumunu bildirimsel (declarative) olarak tanımlar. Yerel Yapılandırma Yöneticisi (Local Configuration Manager - LCM) bu durumu yönetirken üç temel mod kullanır:

1. **ApplyOnly:** Yapılandırma yalnızca ilk başta veya açık bir tetikleme ile uygulanır. Sonrasında oluşan sapmalar izlenmez veya düzeltilmez.
2. **ApplyAndMonitor:** Yapılandırma uygulanır. LCM periyodik olarak (örn. her 15 dakikada bir) sistemi denetler (`Test-DscConfiguration`). Eğer sapma (drift) varsa bunu Windows Olay Günlüklerine (Event Log) yazar ve raporlama sunucusuna iletir; ancak **sisteme müdahale etmez**.
3. **ApplyAndAutoCorrect:** LCM periyodik denetimde herhangi bir sapma tespit ederse, bildirimsel şablonda tanımlı olan durumu derhal yeniden zorlar (`Set-DscConfiguration`). Sistem "kendi kendini onarır" (self-healing).

**Agresif Otomatik Düzeltmenin Riskleri ve Kademeli Yaklaşım:**
Kurumsal üretim ortamlarında `ApplyAndAutoCorrect` körlemesine uygulandığında ciddi riskler doğurur:
* **Hizmet Kesintisi Riski (Operational Flapping):** Örneğin bir küme (cluster) sunucusunda bakım amacıyla geçici olarak bir servis durdurulduğunda, DSC'nin bunu "sapma" olarak görüp servisi aniden zorla başlatması veri tabanında veri bozulmasına (split-brain) neden olabilir.
* **Saldırgan ve Otomasyon Savaşı:** Saldırgan sürekli bir arka kapı kullanıcısı eklerken otomasyonun bunu sürekli silmesi logların taşmasına ve sistem kaynaklarının tükenmesine (denial of service) yol açabilir.
* **Olay İncelemesinin Sabote Edilmesi (Forensic Erasure):** Bir saldırganın sisteme bıraktığı yapılandırma izleri otomatik düzeltme ile anında silinirse, olay müdahale (Incident Response) ekibi saldırının nereden geldiğini ve hangi ayak izlerini bıraktığını tespit edemez.

Bu sebeple olgun güvenlik operasyonlarında kademeli yaklaşım benimsenir:
1. Adım: Güvenlik açısından kritik ama iş sürekliliğini bozmayan ayarlar (örn. UAC, Defender, Sysctl) için `ApplyAndAutoCorrect`.
2. Adım: Servis durdurma/başlatma, ağ arabirimi ayarları gibi operasyonel ayarlar için `ApplyAndMonitor` + SIEM Alarmı + İnsan Onaylı İyileştirme (Human-in-the-Loop).

### Ustanın Çırağa Tavsiyesi / Altın Kural
Çırağım! Otomasyon iki ucu keskin bıçaktır. İyileştirme betiğin idempotent (aynı sonucu veren) olmalı ve yaptığı her değişikliği mutlaka merkezi bir denetim günlüğüne (audit trail) kanıtlarıyla yazmalıdır. Asla denetlemeden (dry-run yapmadan) ve önceki durumu yedeklemeden bir sistemin ayarını ezmeye kalkışma.

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2021 yılında büyük bir telekomünikasyon operatöründe altyapı ekibi, tüm Linux çekirdek parametrelerini zorlayan agresif bir Ansible playbook'unu 10 dakikalık cron'a bağladı. Bu playbook içerisinde `net.ipv4.ip_forward = 0` kuralı yer alıyordu. Ancak şirketin yeni kurduğu Kubernetes worker düğümleri (nodes), pod'lar arası ağ yönlendirmesini sağlayabilmek için çekirdekte `ip_forward = 1` değerine ihtiyaç duyuyordu. Her 10 dakikada bir Ansible bu değeri `0` yapıyor, tüm mikroservis trafiği 2 dakika boyunca kopuyor, ardından Kubernetes CNI eklentisi değeri tekrar `1` yapıyordu. Sistem saatlerce "ping-pong" oynadı; milyonlarca müşteri kesinti yaşadı. Olayın nedeni güvenlik kuralının yanlış yerde agresif zorlanmasıydı.

---

## 3. Soru: Yerel Yöneticiler (Local Administrators) Grubunda Sapma Tespiti ve Yetki Yükseltme

### Soru
Saldırganların kalıcılık (Persistence - T1098) ve yetki yükseltme (Privilege Escalation) amacıyla yerel `Administrators` grubuna gizlice hesap eklemesi (Backdoor Account) yapılandırma sapması analizinde neden en tehlikeli bulgu olarak sınıflandırılır? Bu sapmanın tespitinde saf grup üyeliği karşılaştırmasının ötesinde hangi derin kontroller yapılmalıdır?

### Detaylı ve Kapsamlı Teknik Cevap
Kurumsal bir Active Directory ortamında uç noktalarda yerel yönetici haklarının sıkı kontrolü (Least Privilege prensibi), yanal hareketin (Lateral Movement) engellenmesinde 1 numaralı savunmadır.

**Tehdit Mekanizması:**
Bir saldırgan yerel bir güvenlik açığını sömürdüğünde veya çalıntı bir kimlik bilgisiyle sisteme eriştiğinde, kalıcılık sağlamak için ilk yaptığı eylemlerden biri yerel bir kullanıcı oluşturmak (`net user /add hacker Password123!`) ve bu kullanıcıyı yerel yöneticiler grubuna eklemektir (`net localgroup administrators hacker /add`). Bu işlem etki alanı yöneticilerine doğrudan bir alarm üretmeyebilir; çünkü yerel SAM veritabanında gerçekleşir.

**Grup Üyeliği Sapma Analizi (Membership Drift Analysis):**
Hardened baseline dosyasında yerel `Administrators` grubunun izin verilen üyeleri (Whitelist) açıkça tanımlanır:
`["BUILTIN\\Administrator", "DOMAIN\\Domain Admins", "DOMAIN\\Workstation-Admins"]`

Eğer canlı sistem taranırken grupta whitelist dışı bir üye tespit edilirse:
1. `DriftResult` doğrudan `CRITICAL` seviyesinde işaretlenir.
2. Ceza puanı en yüksek seviyeden (30 puan) kesilir ve sistem uyumluluktan düşürülür (`FAIL`).

**Saf Karşılaştırmanın Ötesindeki Derin Kontroller:**
1. **SID Geçmişi ve Taklit Tespiti:** Saldırgan izin verilen bir hesabın adını taklit edebilir (örn. `Administrator` yerine benzer isimler veya devre dışı bırakılmış yerel hesapların yeniden aktif edilmesi). Bu nedenle yalnızca kullanıcı adı değil, hesabın Güvenlik Tanımlayıcısı (SID) doğrulanmalıdır.
2. **LAPS (Local Administrator Password Solution) Entegrasyonu:** Yerel `Administrator` hesabının parolası her uç noktada benzersiz olmalı ve düzenli olarak LAPS tarafından döndürülmelidir.
3. **Hesap Oluşturulma Zamanı ve Olay Günlüğü Korelasyonu:** Windows Event ID 4720 (Kullanıcı hesabı oluşturuldu) ve Event ID 4728/4732 (Güvenlik grubuna üye eklendi) anlık olarak SIEM ile eşleştirilmeli; bu işlemi yapan sürecin ebeveyni (Parent Process) incelenmelidir (örn. `cmd.exe` veya `powershell.exe` tarafından mı yapıldı?).
4. **Otomatik İyileştirme:** Yapılandırma sapma motorumuz, bilinmeyen üyeyi gruptan derhal çıkaran (`net localgroup Administrators <kullanici> /delete` veya PowerShell `Remove-LocalGroupMember`) güvenli düzeltme betiğini otomatik olarak üretir ve uygular.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat! Yerel yöneticiler grubu bir otel lobisi değildir, giren çıkan belli olmalıdır. Bir uç noktanın yerel yönetici grubunda yetkisiz bir hesap gördüğün an, o makinenin ele geçirildiğini varsayacaksın. Asla "belki stajyer açmıştır" deyip geçiştirme; o hesabı derhal devre dışı bırak, grubundan at ve makineyi ağdan izole et!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2022'de bir finans kuruluşuna yapılan hedefli siber saldırıda, tehdit aktörleri SolarWinds benzeri bir üçüncü parti yazılım güncelleme mekanizmasını suistimal ederek 150 uç noktaya uzaktan kod çalıştırdı. Saldırganlar kalıcılık sağlamak için her bilgisayarda yerel `Administrators` grubuna `svc_backup_loc` adında görünüşte masum bir yerel servis hesabı ekledi. EDR yazılımı bu işlemi meşru bir yönetim komutu olarak algıladığı için alarm üretmedi. Ancak kurumun her gece çalışan yapılandırma sapma denetim motoru (baseline auditor), yerel grup üyeliği whitelist'i ile canlı sistemi karşılaştırdığında 150 makinede birden `svc_backup_loc` sapmasını yakaladı ve `CRITICAL DRIFT` alarmı üretti. Olay müdahale ekibi bu sayede saldırıyı 4. saatinde, saldırganlar etki alanı denetleyicisine (Domain Controller) ulaşamadan başarıyla püskürttü.
