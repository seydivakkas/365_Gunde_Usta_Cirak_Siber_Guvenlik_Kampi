# GÜN 022: Soru & Cevap — Komut Satırı: PowerShell Temelleri

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu soru-cevap dokümanı Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## G022-SC1: Komut satırı: PowerShell temelleri: Temel mekanizmayı ve güvenlik önemini açıkla.

### Temel Mekanizma ve Güvenlik Önemi
PowerShell, geleneksel metin akışlı (raw text stream) kabuklardan farklı olarak **.NET tabanlı nesne boru hattı (Object Pipeline)** mimarisine sahiptir. Bir komutun çıktısı diğer komuta aktarılırken (`|`), karakter dizisi yerine güçlü tipli özellikler (`Properties`) ve işlevler (`Methods`) barındıran nesneler (`PSObject`) taşınır. Örneğin `Get-Process` çalıştırıldığında dönen veri bir metin tablosu değil, `System.Diagnostics.Process` nesnelerinden oluşan bir koleksiyondur. Bu sayede `Where-Object { $_.Handles -gt 1000 }` filtresi metin kırpma (`grep`/`awk`) hatalarına yol açmadan doğrudan tamsayı karşılaştırması yapar.

Güvenlik açısından PowerShell'in önemi iki yönlüdür:
1. **Savunma ve Adli Bilişim Boyutu:** Güvenlik analistleri ve olay müdahale ekipleri, sisteme yetkisiz müdahale veya durum değişikliği yapmamak adına her zaman `Get-` önekli salt-okunur (read-only) cmdlet'lerle başlar (`Get-Process`, `Get-Service`, `Get-ItemProperty`). Bu yaklaşım delil bütünlüğünü (chain of custody) korur.
2. **Saldırı ve İstismar Boyutu (Living off the Land):** Saldırganlar sistemde harici zararlı ikili bırakmadan meşru PowerShell kabuğu üzerinden bellek içi kod yürütme (`Invoke-Expression`), gizli pencere (`-WindowStyle Hidden`) ve kodlanmış komut (`-EncodedCommand`) taktiklerini kullanırlar (MITRE ATT&CK T1059.001).

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Windows ortamında süreç ve servis nesnelerini modelleyen JSON veri setleri (`ornek_veri/ps_process_samples.json`, `ornek_veri/ps_service_samples.json`).
- **İşlem:** `powershell_security_pipeline_auditor.py` aracı canlı sistemden veya örnek veriden nesneleri toplayarak nesne filtreleme ve güvenlik denetimini icra eder.
- **Beklenen Çıktı:** Salt-okunur sorgularla sistemdeki süreç ve servislerin çekildiği, şüpheli argümanların (`-executionpolicy bypass`, `mimikatz`) yakalandığı ve terminalde risk seviyeleriyle raporlandığı gözlenir.
- **Negatif Kontrol:** Hatalı sözdizimine sahip bozuk bir JSON dosyası verildiğinde sistemin güvenli biçimde `ValueError` fırlatması doğrulanır (`test_06_bozuk_json_negatif_kontrol`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** PowerShell'in varsayılan kısıtlamasız çalıştırılabilmesi ve Execution Policy'nin bir güvenlik sınırı olmadığı gerçeğinin bilinmemesi sonucu yetkisiz betiklerin yürütülmesi.
- **Tespit Sinyali:** Windows Olay Günlüklerinde (Event Viewer) Event ID 4104 (Script Block Logging) altında `-enc`, `IEX`, `DownloadString` içeren betik bloklarının görülmesi.
- **Savunma Kontrolü:** Constrained Language Mode (CLM) etkinleştirilmesi, Script Block ve Transkripsiyon loglamasının GPO ile merkezi SIEM'e aktarılması ve AppLocker / WDAC ile kısıtlanması.

### Etik ve Yasal Sınırlar
PowerShell komutları ve cmdlet sorgulamaları yalnızca yetkilendirilmiş sistemlerde, güvenlik denetimi veya sistem yöneticisi izni dahilinde çalıştırılmalıdır. Üçüncü taraf sistemlerde yetkisiz komut yürütme girişimi yasal olarak suçtur (TCK Madde 243/244).

---

## G022-SC2: Komut satırı: PowerShell temelleri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

### Temel Mekanizma ve Güvenlik Önemi
Bağımsız laboratuvar yaklaşımı, harici kütüphanelere veya öncül günlere bağımlı kalmaksızın `Get-Process` ve `Get-Service` çıktılarını filtreleyip siber güvenlik analizine uygun standart bir CSV tablosuna aktarmayı amaçlar. Filtreleme aşamasında nesne özellikleri (PID, bellek, handle, servis durumu, ikili dosya yolu) değerlendirilir; güvensiz servisler ve şüpheli komut satırları süzülür.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:**
  1. `ps_process_samples.json`: Şüpheli ve meşru süreçleri içeren nesne listesi (powershell, explorer, lsass, mimikatz_test, notepad).
  2. `ps_service_samples.json`: Güvenli, güvensiz (TlntSvr, RemoteRegistry) ve tırnaksız servis yolu içeren servis nesneleri.
  3. `ps_audit_rules.json`: Şüpheli kalıplar ve kaynak limitleri kural seti.
- **İşlem:**
  `PowerShellSecurityPipelineAuditor` çalıştırılarak süreçler ve servisler `Where-Object` mantığıyla taranır; riskli bulunan nesneler `Select-Object` formatında süzülerek `export_filtered_to_csv()` ile CSV dosyasına yazılır.
- **Beklenen Çıktı:**
  `kanit/gercek/filtrelenmis_surec_ve_servisler.csv` dosyası üretilir. CSV içinde `nesne_tipi`, `isim`, `id_veya_durum`, `metrik_veya_hesap`, `risk_seviyesi`, `guvenlik_gerekcesi` kolonları altında bypass bayraklı powershell, aşırı kaynak tüketen explorer, mimikatz ve TlntSvr servisleri listelenir.
- **Negatif Kontrol:**
  1. Var olmayan dosya istendiğinde `FileNotFoundError` üretilmesi (`test_05`).
  2. Zararsız, temiz süreçlerin analize sokulduğunda 0 bulgu üretmesi (`test_07_temiz_surec_denetimi`).
  3. Tırnaksız servis yolunda (CWE-428) sistemin `YUKSEK` risk üretmesi (`test_12`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Süreç ve servis listelerindeki şüpheli anormalliklerin metin karmaşası içinde gözden kaçması; sistemde yetki yükseltmeye açık tırnaksız servislerin fark edilmemesi.
- **Tespit Sinyali:** CSV raporunda risk seviyesi `KRITIK` veya `YUKSEK` olan kayıtların filtrelenmesi; tırnaksız yollar için dosya sistemi dizinlerinde sahte ikililerin (`Program.exe`) varlığının araştırılması.
- **Savunma Kontrolü:** Regedit üzerinden servis binary yollarının çift tırnak (`"..."`) içine alınması; CIS kuralları gereği kullanılmayan tüm servislerin `Disabled` konumuna getirilmesi.

### Etik ve Yasal Sınırlar
Laboratuvarda kullanılan süreç ve servis verileri kontrollü test nesneleridir. Canlı kurumsal ağlarda `Stop-Process` veya `Stop-Service` gibi müdahaleci cmdlet'ler yürütülmeden önce hizmet kesintisi riskine karşı mutlaka değişiklik onay süreci (Change Management) işletilmelidir.

---

## G022-SC3: 'Komut satırı: PowerShell temelleri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

### Temel Mekanizma ve Güvenlik Önemi
PowerShell bağlamında güvenlik riski üç temel alandan kaynaklanır:
1. **Gereksiz İzinler ve Güvensiz Servisler:** Telnet (`TlntSvr`), Remote Registry gibi şifresiz veya saldırganlara uzaktan sistem kaydı değiştirme imkanı tanıyan eski servislerin çalışır durumda bırakılması.
2. **Yanlış Yapılandırma ve Tırnaksız Servis Yolları (CWE-428):** Servis yürütülebilir dosya yolunda boşluk bulunması ve tırnak içine alınmaması sonucu yerel yetki yükseltme (Privilege Escalation) açığı doğması.
3. **Şüpheli Komut Satırı Yürütümü:** Saldırganların meşru PowerShell kabuğunu `Bypass`, `-w hidden`, `-enc` bayraklarıyla çağırarak kötü niyetli betikleri gizlemesi.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Güvensiz servis ve şüpheli argümanlar barındıran girdi verileri.
- **İşlem:** `audit_processes()` ve `audit_services()` filtreleme fonksiyonları icra edilir.
- **Beklenen Çıktı:** 
  - `powershell.exe -ExecutionPolicy Bypass ...` -> `KRITIK` risk (MITRE T1059.001).
  - `mimikatz_test.exe` -> `KRITIK` risk (Bellek Dökümü / Parola Hırsızlığı).
  - `TlntSvr` -> `KRITIK` risk (CIS Karaliste Protokolü).
  - `C:\Program Files\Enterprise Software\...` -> `YUKSEK` risk (CWE-428 Tırnaksız Yol).
- **Negatif Kontrol:** Sınır değerleri aşmayan standart bir sistem sürecinde kaynak anomalisi uyarısı üretilmemesi (`test_07`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk Analizi:** Bir saldırgan, sistemde yerel kullanıcı yetkisi elde ettiğinde ilk olarak `Get-Service` ile tırnaksız servis yollarını tarar veya PowerShell ile bellekte Mimikatz çalıştırarak LSASS sürecinden parola hash'lerini çeker.
- **Tespit Sinyalleri:**
  - EDR / Sysmon Event ID 1 (Process Creation): `powershell.exe` komut satırı argümanlarında `-enc` veya `-w hidden` görülmesi.
  - Windows Event ID 4104: Betik bloğu loglarında `sekurlsa::logonpasswords` veya `Invoke-Expression` çağrısı.
- **Savunma Kontrolleri:**
  - **En Az Ayrıcalık:** Servis hesaplarının `LocalSystem` yerine kısıtlı hizmet hesaplarıyla (Managed Service Accounts - gMSA) çalıştırılması.
  - **Geri Alınabilir Yapılandırma (Hardening):** PowerShell Script Block Logging, Module Logging ve Transcription'ın GPO ile zorunlu kılınması.
  - **Uygulama Denetimi:** AppLocker veya Windows Defender Application Control (WDAC) ile PowerShell'in yalnızca Constrained Language Mode'da çalışmasına izin verilmesi.

### Etik ve Yasal Sınırlar
PowerShell güvenlik denetimleri yalnızca yetkilendirilmiş varlıklar üzerinde icra edilmelidir. Mimikatz veya bellek dökümü komutları yalnızca sızma testi sözleşmesi kapsamındaki izole laboratuvarlarda çalıştırılmalıdır; aksi takdirde veri güvenliğini ihlal suçu oluşur.
