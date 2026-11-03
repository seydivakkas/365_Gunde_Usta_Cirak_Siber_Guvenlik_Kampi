# GÜN 133: Mini Proje 18 — Windows Güvenlik Denetimi Soru-Cevap

## Soru 1: Kurumsal Bir Windows Uç Noktasında Güvenlik Duruşu (Security Posture) Denetlenirken Neden Tek Bir Kontrol Yerine Bütünleşik 5 Boyutlu Değerlendirme Modeli Uygulanmalıdır?

### 1. Soru Başlığı ve Tanımı
Kurumsal Windows uç noktalarında güvenlik denetimi gerçekleştirilirken izole bir bileşenin (örneğin sadece antivirüs veya sadece güvenlik duvarı) incelenmesi yanıltıcı bir güvenlik hissi yaratır. Bütünleşik 5 Boyutlu Güvenlik Modeli; Defender, UAC/Hesaplar, NTFS Dosya Sistemi, Ağ Güvenlik Duvarı ve Windows Hizmetlerini tek bir korelasyon çatısında birleştirerek sistemin Savunma Derinliği (Defense-in-Depth) dayanıklılığını ölçer.

### 2. Derinlemesine Teknik Analiz
Saldırganlar kurumsal bir sisteme sızarken doğrusal tek bir zafiyetten değil, zayıf yapılandırmaların zincirleme bileşiminden (vulnerability chaining) faydalanır:
1. **İhlal Zinciri:** Bir saldırgan kimlik avı (phishing) yoluyla standart kullanıcı yetkisiyle kod çalıştırdığında; antivirüs (Defender) ilk aşamada şüpheli davranışı yakalayamazsa, saldırgan yerel yetki yükseltme (LPE) yollarını arar.
2. **Yetki Yükseltme Katmanı:** Eğer sistemde UAC devre dışıysa (`EnableLUA=0`) veya tırnaksız bir servis yolu (`Unquoted Service Path - CWE-428`) varsa, saldırgan anında `NT AUTHORITY\SYSTEM` haklarına ulaşır.
3. **Kalıcılık ve Yatay İlerleme (Lateral Movement):** SYSTEM haklarını alan saldırgan, Windows Firewall Public profilinde RDP veya SMB portlarının açık olduğunu keşfederse etki alanı içerisindeki diğer sistemlere sıçrar ve Defender servislerini kayıt defterinden kapatır.

Bu sebeple, her bir kontrol alanı diğerinin sigortasıdır. Ağırlıklı puanlama modelinde her bir alana %20 ağırlık verilerek hiçbir alanın ihmal edilmemesi garanti edilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir finans kurumunda uç noktaların tamamında gelişmiş EDR ve Defender yüklüdür. Ancak BT operasyon ekibi, kurum içi eski bir muhasebe yazılımının hata vermesini önlemek için yerel sunucularda `ConsentPromptBehaviorAdmin` değerini `0` (Sessizce yükselt) yapmış ve `C:\Program Files\Muhasebe` klasörüne `Users` grubuna tam yetki vermiştir. Düşük yetkili bir banka çalışanının bilgisayarına sızan saldırgan, klasördeki bir DLL'i değiştirerek (DLL Hijacking) tek bir UAC uyarısı dahi tetiklenmeden SYSTEM olmuş ve EDR servislerini bellekten düşürmüştür.

**Pratik Çözüm:**
Bütünleşik denetim betiği ile tüm alanlar eş zamanlı taranır ve eksiklikler tek bir raporda gösterilir:
```powershell
# Bütünleşik Windows Denetim ve Sıkılaştırma Yürütmesi
python uygulama/windows_audit_cli.py audit -i ornek_veri/enterprise_windows_spec.json -o kanit/gercek/windows_denetim_raporu.json
python uygulama/windows_audit_cli.py remediate -i ornek_veri/enterprise_windows_spec.json -o kanit/gercek/master_remediation.ps1
# Master sıkılaştırma betiği PowerShell üzerinden tetiklenir
powershell.exe -ExecutionPolicy Bypass -File kanit/gercek/master_remediation.ps1
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, tek bir kale kapısına yüz kilit vurup arka bahçenin çitini açık bırakırsan kaleni koruyamazsın. Antivirüsüne güvenip dosya izinlerini boşlama; güvenlik duvarına güvenip servislerini başıboş bırakma. Uç nokta güvenliği bir senfonidir; tek bir enstrüman detone olursa tüm savunman çöker.

---

## Soru 2: Windows Uç Nokta Denetimlerinde Tespit Edilen Zafiyetlerin Önceliklendirilmesinde Hangi Kriterler Kullanılmalıdır ve CVSS/CWE ile Eşleştirme Nasıl Yapılır?

### 1. Soru Başlığı ve Tanımı
Denetim esnasında yüzlerce yapılandırma parametresi taranır. Güvenlik ekiplerinin sınırlı operasyonel kaynakları sebebiyle bulguların önem derecelerine (Severity: CRITICAL, HIGH, MEDIUM, LOW) ayrılması, ilgili CWE ve MITRE ATT&CK teknikleriyle eşleştirilerek risk tabanlı bir aksiyon planı oluşturulması zorunludur.

### 2. Derinlemesine Teknik Analiz
Zafiyet önceliklendirmesinde şu üç temel parametre değerlendirilir:
1. **İstismar Edilebilirlik Kolaylığı (Exploitability):** Zafiyetin tetiklenmesi için kullanıcı etkileşimi, özel araçlar veya karmaşık bellek manipülasyonu gerekiyor mu? (Örn: Tırnaksız servis yolu veya `ConsentPromptBehaviorAdmin=0` tek bir komutla anında istismar edilir).
2. **Doğrudan Etki Kapsamı (Impact Scope):** Zafiyet saldırgana doğrudan tam sistem kontrolü (`SYSTEM` / `Full Compromise`) mi sağlıyor, yoksa sadece bilgi sızıntısı mı? (Örn: Servis DACL üzerinde `SERVICE_CHANGE_CONFIG` verilmesi doğrudan CRITICAL'dır; SACL günlüğünün kapalı olması ise LOW/MEDIUM denetim eksikliğidir).
3. **Maruziyet Alanı (Exposure):** Zafiyet yerel bir kullanıcı tarafından mı yoksa ağ üzerinden uzaktaki bir saldırgan tarafından mı tetiklenebilir? (Örn: Public ağda RDP 3389 veya SMB 445 portunun açık olması uzaktan erişim riski yarattığı için CRITICAL'dır).

**Standart Eşleştirme Tablosu:**
- `CWE-693` (Protection Mechanism Failure) -> Defender RTP / Tamper Protection kapalı -> MITRE `T1562.001`
- `CWE-250` (Execution with Unnecessary Privileges) -> UAC LUA=0 / Aşırı Yetkili Servis -> MITRE `T1548.002`
- `CWE-732` (Incorrect Permission Assignment) -> Zayıf NTFS ACL / Zayıf Servis DACL -> MITRE `T1574.009` / `T1543.003`
- `CWE-428` (Unquoted Search Path) -> Tırnaksız Servis Yolu -> MITRE `T1574.009`
- `CWE-284` (Improper Access Control) -> Firewall Kapalı / Port Açık -> MITRE `T1562.004` / `T1021.001`

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Denetim sonucunda 8 adet bulgu üretilmiştir: 2 adet CRITICAL, 3 adet HIGH, 2 adet MEDIUM, 1 adet LOW. Operasyon ekibinin aynı gün içinde tüm bulguları düzeltme imkanı yoktur. Denetçi, CISO'ya sunduğu raporda önce uzaktan kod yürütme ve anında SYSTEM yükseltme riski taşıyan CRITICAL bulguları (Public RDP maruziyeti ve Writable Service Binary) ilk 2 saat içinde kapatılacak "Acil Yama Paketi" olarak sunar; LOW bulguları ise bir sonraki bakım penceresine planlar.

**Pratik Çözüm:**
Betiğimizin JSON çıktısı filtrelenerek öncelikli aksiyon listesi çıkarılır:
```powershell
# Kritik ve Yüksek bulguları ayıklama
$report = Get-Content kanit/gercek/windows_denetim_raporu.json | ConvertFrom-Json
$urgentFindings = $report.findings_detail | Where-Object { $_.severity -in @('CRITICAL', 'HIGH') }
Write-Host "[!] ACİL MÜDAHALE GEREKTİREN ZAFİYETLER:" -ForegroundColor Red
$urgentFindings | ForEach-Object {
    Write-Host "  * [$($_.severity)] $($_.title) -> $($_.remediation)" -ForegroundColor Yellow
}
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, operasyon ekibinin önüne 100 sayfalık taranmış ham log yığarsan hiçbirini yapmazlar; ama onlara "İşte sisteminizi hemen bugün çökertebilecek 2 kritik açık ve bunları 30 saniyede kapatacak 2 satır PowerShell kodu" dersen, güvenliğin kahramanı olursun. Doğru önceliklendirme, güvenlik mühendisliğinin aklıdır.

---

## Soru 3: Otomatik Sıkılaştırma (Remediation) Betikleri Hazırlanırken Kurumsal Üretim Süreçlerinin (Business Continuity) Kesintiye Uğramaması İçin Hangi Güvenlik İlkelerine Dikkat Edilmelidir?

### 1. Soru Başlığı ve Tanımı
Güvenlik sıkılaştırması (Hardening) sırasında uygulanan katı kurallar; meşru kurumsal uygulamaların, veri tabanı servislerinin veya kullanıcı oturumlarının çökmesine yol açabilir. Başarılı bir iyileştirme mimarisi; geri alınabilirlik (rollback), adım adım doğrulama ve en az etki prensiplerini barındırmalıdır.

### 2. Derinlemesine Teknik Analiz
Sıkılaştırma betikleri uygulanırken karşılaşılan temel operasyonel tuzaklar:
1. **Firewall Kural Kesintileri:** Public ve Private profillerde gelen bağlantılar bloklanırken, kurumun uzaktan yönetim veya izleme araçlarının (Zabbix, SCCM, WinRM) IP blokları istisna (Whitelist) olarak tanımlanmazsa sunucu ağdan düşer ve uzaktan erişim tamamen kaybolur.
2. **UAC Zorlaması:** `ConsentPromptBehaviorAdmin=2` yapıldığında, arka planda kullanıcı arayüzü olmadan çalışan eski yönetim otomasyonları ve görev zamanlayıcıları (Task Scheduler) onay alamadığı için sessizce durabilir.
3. **NTFS İzin Budaması:** `C:\Program Files\` veya `C:\Windows\` dizinlerindeki izinler düzeltilirken `inheritance:r` ile kalıtım kırıldığında, uygulamanın çalışması için gereken temel DLL okuma hakları silinebilir.

**Kritik Prensipler:**
- **İdempotentlik:** Betik birden fazla kez çalıştırıldığında sistemi bozmamalı, var olan güvenli durumu korumalıdır.
- **Hata Yakalama ve Günlükleme:** Başarısız olan her adım `$ErrorActionPreference = 'Continue'` ile kaydedilmeli, tüm süreç bir hata yüzünden durmamalıdır.
- **Geri Alınabilirlik (Rollback Planı):** Değiştirilen her kayıt defteri değeri ve servis yapılandırması öncesinde yedeklenmelidir (`reg export`, `sc sdshow`).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Sistem yöneticisi internetten bulduğu bir "Windows Hardening Script"i canlı ERP sunucusunda çalıştırmıştır. Betik, tüm portları körlemesine kapatmış ve `NT AUTHORITY\SYSTEM` haricindeki servis hesaplarının haklarını silmiştir. Sonuç olarak ERP veri tabanı bağlantısı kopmuş, fabrika üretimi 4 saat durmuş ve şirkete yüz binlerce lira zarar vermiştir.

**Pratik Çözüm:**
Mini Proje 18 motorumuz, körlemesine yıkıcı komutlar yerine her bir zafiyet için hedefe odaklı (surgical), sadece ilgili servisi ve dizini onaran hassas komutlar üretir:
```powershell
# Hedefe Yönelik ve Güvenli Sıkılaştırma Örneği:
# 1. Kayıt defteri yedeği alınır
reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\HedefServis" "C:\Backups\HedefServis_pre_harden.reg" /y
# 2. Yalnızca ilgili servisin yolu tırnak içine alınır
sc.exe config "HedefServis" binPath= "\"C:\Program Files\App\service.exe\" -arg"
# 3. Servisin durumu doğrulanır
Get-Service -Name "HedefServis" | Select-Object Name, Status, StartType
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, çalışan bir fabrikayı durduran güvenlikçi, güvenlikçi değil felakettir. Asla test ortamında denemediğin, geri alma planı (rollback) hazırlamadığın ve etkisini öngöremediğin bir sıkılaştırma betiğini canlı sunucuda çalıştırma. Önce ölç, sonra yalıt, en son dikkatle sıkılaştır!
