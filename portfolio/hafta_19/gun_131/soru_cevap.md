# GÜN 131: WINDOWS FIREWALL PROFİLLERİ SORU - CEVAP
**Tarih:** 2 Kasım 2026  
**Format:** Usta - Çırak / Hoca Dersi  

---

### SORU 1: Windows Filtering Platform (WFP), Network Location Awareness (NLA) Servisi ve Ağ Profillerinin Dinamik Geçiş Mekanizması

#### 1. Soru Başlığı ve Tanımı
Windows işletim sisteminde Network Location Awareness (NLA) servisi bağlı olunan ağın türünü (Domain, Private, Public) dinamik olarak nasıl belirler? Windows Filtering Platform (WFP) çekirdeği, ağ profili değiştiğinde filtreleme kurallarını paket seviyesinde nasıl yeniden düzenler?

#### 2. Derinlemesine Teknik Analiz
Windows ağ yığını, TCP/IP protokol katmanı ile donanım bağdaştırıcısı arasına yerleştirilmiş **Windows Filtering Platform (WFP)** çekirdek sürücüsü (`tcpip.sys`, `bfe.dll`) üzerinden çalışır.
- **NLA Doğrulama Süreci:**
  1. Bir ağ bağdaştırıcısına IP adresi atandığında, `nlasvc` servisi ağın etki alanı (Active Directory) ağı olup olmadığını anlamak için DNS üzerinden `_ldap._tcp.dc._msdcs.<DomainName>` SRV kaydını arar.
  2. Bir etki alanı denetleyicisi (DC) bulunursa, NLA makinenin Active Directory bilgisayar hesabı ile DC arasında bir kimlik doğrulama el sıkışması gerçekleştirir.
  3. Bu el sıkışma başarılı olursa ağ bağdaştırıcısına **Domain Profile** atanır.
  4. Eğer makine etki alanında değilse veya DC ile el sıkışma başarısız olursa; kullanıcının Network & Internet ayarlarında bu ağ için seçtiği profil atanır: `Private` veya `Public`.
  5. Tanınmayan veya yeni bağlanan her ağ için varsayılan olarak daima **Public Profile** devreye alınır (Fail-Secure prensibi).
- **WFP Dinamik Kural Geçişi:** NLA profili güncellediğinde, Base Filtering Engine (BFE) servisine bir RPC bildirimi gönderir. BFE, kayıt defterinde saklanan kuralları profille filtreleyerek WFP çekirdek katmanındaki hafıza tablolarını günceller. Paketler anında yeni profildeki kurallara ve varsayılan eyleme göre süzülmeye başlar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir dizüstü bilgisayar ofisteyken Domain profilindedir ve yerel yönetim amaçlı RDP (3389) portu açıktır. Çalışan akşam evine gittiğinde ev modemi geçici bir DNS hatası vermiş veya DC'ye erişemediği için NLA ağı `Public` olarak sınıflandırmıştır. Eğer kurumsal güvenlik duvarı kuralı `Profile: Any` olarak yazılmış olsaydı, RDP portu evdeki veya dışarıdaki tüm ağa açık kalacaktı.
**Çözüm:**
Tüm yönetimsel gelen izin kuralları profillerle sınırlandırılmalıdır:
```powershell
# RDP kuralını yalnızca Domain ve Private profillerine bağla:
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Profile Domain,Private
# Public profilde gelen kuralların uygulanmasını tamamen kapat:
Set-NetFirewallProfile -Profile Public -AllowInboundRules False
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Ağ profili ataması bir güvenlik duvarının ilk savunma hattıdır. Bir kural yazarken 'nasılsa şirket bilgisayarı' deyip `Profile: Any` yazan mühendis, o bilgisayar bir kafeye gittiğinde şirketin kapısını tüm kafeye açmış olur. Her kuralın etki alanını cerrah titizliğiyle profillere bağlayacaksın!"

---

### SORU 2: Kamusal Ağda (Public Profile) Port Sızıntıları (RDP 3389, SMB 445) ve Solucan/Fidye Yazılımı Yayılım Dinamikleri (CWE-284 / MITRE T1021)

#### 1. Soru Başlığı ve Tanımı
Bir Windows istemcisinde Public profil devredeyken SMB (445) veya RDP (3389) portlarının açık bırakılması neden feci bir güvenlik açığıdır (`CWE-284`)? WannaCry ve BlueKeep gibi ağ solucanları (worms) bu açık portları nasıl sömürür?

#### 2. Derinlemesine Teknik Analiz
Kamusal ağlar (Public Wi-Fi, otel ağları veya doğrudan genel IP alan makineler), herhangi bir ağ düzeyinde çevre güvenliğine (firewall/IDS) sahip değildir.
- **SMB (Port 445 / 139) Sızıntısı:**
  - SMB protokolü dosya, yazıcı ve adlandırılmış boru (Named Pipes) iletişimi sağlar.
  - 2017 yılındaki WannaCry ve NotPetya salgınları, SMBv1 protokolündeki bir bellek taşması zafiyetini (EternalBlue - MS17-010 / CVE-2017-0144) sömürerek yayılmıştır.
  - Güvenlik duvarında SMB portu açık olan bir makine, ağa bağlandığı ilk saniyelerde gönderilen tek bir kötü amaçlı SMB paketi ile kullanıcı hiçbir şeye tıklamadan ve hiçbir oturum açmadan SYSTEM yetkisiyle enfekte edilebilir.
- **RDP (Port 3389) Sızıntısı:**
  - RDP portunun açık olması, saldırganların internet üzerinden kaba kuvvet (brute-force) veya parola püskürtme (password spraying) saldırısı yapmasına imkan tanır.
  - Ayrıca BlueKeep (CVE-2019-0708) gibi kimlik doğrulaması gerektirmeyen uzaktan kod yürütme (RCE) zafiyetlerine zemin hazırlar (`MITRE T1021.001`).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yazılım mühendisi evinde çalışırken test yapmak için `New-NetFirewallRule -DisplayName "OpenSMB" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445` komutunu çalıştırmış ve profil belirtmediği için kural Public profilde de aktif kalmıştır. Mühendis bir havalimanı bekleme salonundaki Wi-Fi ağına bağlandığında, yerel ağda dinleme yapan bir saldırgan tarafından port taramasında yakalanmış ve saniyeler içinde SMB üzerinden sızma denenmiştir.
**Çözüm:**
1. Public profilde tüm gelen yönetim portları derhal kapatılır veya Public profil kapsamından çıkarılır:
   ```powershell
   Get-NetFirewallRule | Where-Object {
       $_.Profile -match "Public" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -in @("445", "139", "3389"))
   } | Disable-NetFirewallRule
   ```
2. NetBIOS ve SMB paylaşımları bağdaştırıcı bazında kapatılır ve `Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block` zorunlu kılınır.

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kamusal Wi-Fi ağı bir savaş alanıdır. Oradaki her cihaz potansiyel bir düşmandır. Public profilde 445 veya 3389 portunu açık bırakmak, savaş meydanına çelik yeleksiz ve sırtında hedef tahtasıyla çıkmaya benzer. Public profilde dışarıdan gelen her şeyi bloklayacaksın; sıfır tolerans!"

---

### SORU 3: Windows Güvenlik Duvarı Kütüklemesi (`pfirewall.log`), Düşürülen Paketlerin Analizi ve SIEM Korelasyonu (CWE-778 / MITRE T1562.004)

#### 1. Soru Başlığı ve Tanımı
Windows Güvenlik Duvarı'nda engellenen paketlerin kütüklenmesi (`LogBlocked=True`) neden zorunlu bir güvenlik denetimidir (`CWE-778`)? `pfirewall.log` dosyasının yapısı nasıldır ve SOC analistleri bu kütükleri ağ taraması ve C2 iletişimini tespit etmek için nasıl kullanır?

#### 2. Derinlemesine Teknik Analiz
Varsayılan Windows kurulumunda güvenlik duvarı düşürdüğü paketleri kaydetmez. Bu durum bir saldırgan makineye karşı port taraması (SYN scan, connect scan) yaptığında sistemin tamamen kör kalmasına (`CWE-778`) sebep olur.
- **Kütük Dosyası Yapısı (`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`):**
  Güvenlik duvarı W3C genişletilmiş kütük formatında metin satırları üretir:
  `date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpmwin icmptype icmpcode info path`
  Örnek Kütük Satırı:
  `2026-11-02 10:25:01 DROP TCP 192.168.1.150 192.168.1.50 54321 445 48 S 1234567890 0 8192 - - - RECEIVE`
- **SOC Analizi ve Tehdit Avcılığı:**
  - **Port Taraması Tespiti:** Aynı `src-ip` adresinden kısa sürede (örn. 5 saniye içinde) 50 farklı `dst-port` adresine gelen `DROP TCP` kayıtları açık bir Nmap veya port tarama atağını işaret eder.
  - **Yanal Hareket Girişimi:** Ağdaki bir istemcinin diğer istemcilerin 445 veya 3389 portlarına sürekli düşen paket göndermesi, içeride bir solucanın veya saldırganın yayılmaya çalıştığını gösterir.
  - **Kütük Boyutu (LogMaxSizeKilobytes):** CIS Benchmark kütük dosyasının en az 16.384 KB (16 MB) olmasını şart koşar; aksi takdirde yoğun bir tarama altında eski kütükler hızla silinir (Log exhaustion).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kurumda SOC analistleri, etki alanındaki bazı makinelerin garip davrandığından şüphelenmiş ancak istemcilerde firewall logları kapalı olduğu için içeriden dışarıya veya istemciden istemciye yapılan port taramalarını kanıtlayamamıştır.
**Çözüm:**
1. Merkezi GPO veya PowerShell ile tüm profillerde düşürülen paket kütüklemesi etkinleştirilir:
   ```powershell
   Set-NetFirewallProfile -Profile Domain,Private,Public `
       -LogBlocked True `
       -LogMaxSizeKilobytes 16384 `
       -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
   ```
2. Windows Event Forwarding (WEF) veya SIEM ajanı (Sysmon / Splunk UF / Wazuh) ile `pfirewall.log` dosyası gerçek zamanlı olarak merkezi SIEM platformuna aktarılır ve `action == 'DROP'` alarmları korele edilir.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak! Güvenlik duvarının sadece kapıyı kapatması yetmez; kapıyı kimin zorladığını da yazması gerekir. Kütük tutmayan bir güvenlik duvarı, kör bir gece bekçisine benzer: hırsızı içeri almaz ama hırsızın kapıyı kaç kez zorladığını sana asla söyleyemez. Kütükleri daima açık tutacaksın!"
