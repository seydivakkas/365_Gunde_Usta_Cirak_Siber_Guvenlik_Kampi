# GÜN 022: Komut Satırı: PowerShell Temelleri ve Nesne Boru Hattı Güvenliği

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu eğitim materyali Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır. İzinsiz kopyalanamaz, çoğaltılamaz ve ticari amaçla kullanılamaz.*

---

## 1. Derse Giriş ve Kavramsal Çerçeve: Windows'ta Komut Satırının Evrimi

Sevgili öğrencim, bugün eğitim programımızın dördüncü haftasına (**Hafta 04**) adım atıyoruz. Artık işletim sistemlerinin temel teorisini arkamızda bıraktık; bugünden itibaren bu sistemlerin nasıl yönetildiğini, nasıl sorgulandığını ve saldırganların sistem araçlarını kullanarak nasıl gizlendiğini komut satırı derinliğinde inceleyeceğiz.

İlk durağımız **PowerShell**. Geleneksel Windows komut istemcisi `cmd.exe` (DOS kökenli), yalnızca ilkel metin çıktıları üreten ve modern otomasyon gereksinimlerini karşılamaktan uzak bir kabuktu. 2006 yılında Jeffrey Snover ve Microsoft mühendisleri tarafından geliştirilen PowerShell, komut satırı paradigmasında bir devrim yarattı. PowerShell, Unix kabuklarının boru hattı (`|`) konseptini aldı ancak içine **.NET Nesne Modeli**'ni yerleştirdi.

Bugün siber güvenlik dünyasında PowerShell hem savunucunun (Blue Team) en güçlü otomasyon ve adli bilişim (forensics) aracı hem de saldırganın (Red Team / APT) sistemde harici zararlı dosya indirmeden mevcut araçlarla hareket ettiği **"Living off the Land" (LotL)** taktiğinin bir numaralı aktörüdür.

---

## 2. PowerShell Nesne Boru Hattı (Object Pipeline): "Metin Değil, Nesne Akışı" (G022-SC1)

Geleneksel Unix/Linux kabuklarında (bash, zsh), komutlar arasındaki boru hattı (`|`) **salt metin (raw string stream)** taşır. Örneğin çalışan bir sürecin PID'sini almak için:
```bash
ps aux | grep nginx | awk '{print $2}'
```
Burada `awk` ve `grep` metin satırları üzerinde karakter indekslerine ve boşluklara göre filtreleme yapar. Eğer bir program çıktısındaki boşluk sayısı değişirse betik çöker.

**PowerShell Farkı:**
PowerShell'de boru hattından metin değil, zengin özelliklere (`Properties`) ve metotlara (`Methods`) sahip **.NET Nesneleri (`PSObject`)** akar!
```powershell
Get-Process | Where-Object { $_.Handles -gt 1000 } | Select-Object ProcessName, Id, CPU
```
Bu komutta:
1. `Get-Process`, sistemdeki her bir süreç için bellekte `System.Diagnostics.Process` tipinde güçlü bir nesne üretir.
2. Boru hattı (`|`), bu nesneleri tek tek `Where-Object` cmdlet'ine aktarır.
3. `$_.Handles`, nesnenin doğrudan tamsayı (integer) türündeki handle özelliğine erişir; metin ayrıştırma (`string parsing`) yapılmaz.
4. `Select-Object`, yalnızca istenen alanları seçerek yeni bir nesne koleksiyonu oluşturur.

Güvenlik açısından nesne akışının anlamı şudur: **Veri tipi güvenliği tamdır, çıktı formatındaki değişiklikler analiz betiklerini yanıltamaz ve filtrelenen nesneler doğrudan güvenlik kurallarıyla kıyaslanabilir.**

---

## 3. Cmdlet Standartları ve Güvenli Komut Yazımı

PowerShell komutlarına **Cmdlet** (command-let) adı verilir ve standart bir `Verb-Noun` (Eylem-İsim) sözdizimine sahiptir:
- `Get-` : Salt-okunur bilgi alma (`Get-Process`, `Get-Service`, `Get-LocalUser`)
- `Set-` / `New-` : Yapılandırma değiştirme veya oluşturma (`Set-Service`, `New-Item`)
- `Start-` / `Stop-` : Yaşam döngüsü yönetimi (`Start-Service`, `Stop-Process`)

> **Güvenlik Kuralı (Salt-Okunur Komutlarla Başlama):**  
> Bir güvenlik denetçisi veya olay müdahale uzmanı, canlı bir sisteme bağlandığında sisteme yetkisiz müdahale veya durum değişikliği yapmamak adına her zaman `Get-` önekli salt-okunur komutlarla başlamalıdır. Böylece adli bilişim delillerinin kirlenmesi (tampering) engellenir.

---

## 4. PowerShell Güvenlik Mekanizmaları: Execution Policy Efsanesi

Siber güvenlikte en çok yanlış anlaşılan konulardan biri PowerShell'in **Execution Policy** (Yürütme İlkesi) kavramıdır.

### Execution Policy Bir Güvenlik Sınırı Değildir!
Microsoft belgelerinde açıkça belirtildiği üzere: **"Execution policy is not a security boundary."**
Bu ilke (Restricted, AllSigned, RemoteSigned, Unrestricted), standart kullanıcıların çift tıklayarak kazara zararlı bir `.ps1` betiği çalıştırmasını önlemek için tasarlanmış bir "güvenlik korkuluğudur" (safety rail).

Bir saldırgan veya yetkili bir kullanıcı bunu tek bir bayrakla atlayabilir:
```powershell
powershell.exe -ExecutionPolicy Bypass -File script.ps1
# veya
powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('...')"
```

### Gerçek Güvenlik Katmanları Nelerdir?
1. **Script Block Logging (Event ID 4104):** Bellekte yürütülen kodun tamamını (obfuscate edilmiş, base64 kodlanmış olsa bile) deobfuscate edilmiş ham haliyle Windows Olay Günlüklerine kaydeder.
2. **Module Logging (Event ID 4103):** Çağrılan cmdlet'leri ve parametreleri kaydeder.
3. **Transcription (Diske Loglama):** Tüm komut satırı oturumunu zaman damgalı metin dosyalarına döker.
4. **Constrained Language Mode (CLM):** PowerShell'in doğrudan Win32 API'lerine ve rastgele .NET türlerine erişimini sınırlar; AppLocker / WDAC ile entegre çalışır.
5. **AMSI (Antimalware Scan Interface):** Bellekte yürütülmek üzere olan kod bloklarını anlık olarak Microsoft Defender veya kurulu EDR motoruna taratır.

---

## 5. Saldırı Vektörleri ve Kötüye Kullanım Senaryoları

Saldırganların PowerShell kullanım kalıpları (MITRE ATT&CK T1059.001):
1. **Gizli ve Kodlanmış Çalıştırma:**
   `powershell -nop -w hidden -enc SUVY...`
   `-NoProfile` (`-nop`) profil dosyalarını yüklemez; `-WindowStyle Hidden` (`-w hidden`) pencereyi gizler; `-EncodedCommand` (`-enc`) Base64 UTF-16LE kodlu zararlı yükü yürütür.
2. **Bellekte Kod Çalıştırma (Fileless Malware):**
   `IEX (Invoke-Expression)` kullanarak diske hiçbir dosya yazmadan ağdan indirilen betiği doğrudan RAM'de çalıştırır.
3. **Tırnaksız Servis Yolu İstismarı (CWE-428 / MITRE T1574.009):**
   Servis binary yolu `C:\Program Files\Enterprise App\service.exe` gibi boşluk içerip tırnak içine alınmadığında (`"..."`), Windows sırasıyla `C:\Program.exe`, `C:\Program Files\Enterprise.exe` dosyalarını aramaya başlar. Düşük yetkili bir saldırgan bu dizinlere yazma iznine sahipse, root/SYSTEM yetkisinde kendi zararlısını çalıştırabilir.

---

## 6. Savunma, Denetim ve Telemetri Stratejileri (G022-SC2 & SC3)

Geliştirdiğimiz denetim motoru `powershell_security_pipeline_auditor.py`, bu saldırı vektörlerini tespit etmek için şu boru hattı kontrollerini uygular:
- `Get-Process` nesnelerinden şüpheli parametreleri (`-enc`, `Bypass`, `mimikatz`) yakalar.
- Handle sayısı 2000'i veya RAM tüketimi 150 MB'ı aşan anormal süreçleri listeler.
- `Get-Service` nesnelerinden karalistedeki güvensiz protokolleri (`TlntSvr`, `RemoteRegistry`) ve tırnaksız servis yollarını (CWE-428) süzerek standart bir CSV raporuna aktarır.

---

## 7. Usta Notu, Özet ve Çıkarımlar

> **Usta Diyor ki:**  
> "Çırak, PowerShell Windows dünyasının asasıdır; asayı tutan el bilgiliyse kale savunulur, bilgisizse kale içeriden fethedilir. Bir SIEM ekranında `powershell.exe -enc` veya `-ExecutionPolicy Bypass` gördüğünde paniğe kapılma; hemen Event ID 4104 kayıtlarına bakarak saldırganın deobfuscate edilmiş gerçek amacını oku. Nesne boru hattını iyi kullanan bir analist, saniyeler içinde tüm çalışan sistem süreçlerinin ve servislerinin güvenlik röntgenini CSV olarak önüne alabilir."

Yarın **Gün 023** dersimizde, PowerShell ile dosya ve dizin işlemleri, ACL sorgulamaları ve gizli dosya analizlerini derinleştireceğiz.
