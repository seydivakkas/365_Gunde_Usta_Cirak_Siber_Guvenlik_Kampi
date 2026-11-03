# G086: PowerShell Betik Parametreleri ve Gelişmiş Savunma Mimarisi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## Ustanın Giriş Dersi: Parametre Bir Girdi Değil, Güvenlik Hudududur

Evlat, siber güvenlikte ve sistem otomasyonunda en çok kan kaybedilen yerler, komut satırı ile işletim sistemi çekirdeği arasındaki sınır kapılarıdır. Birçok acemi yönetici ve yazılımcı, PowerShell betiği yazarken parametreleri yalnızca dışarıdan değişken alan sıradan argümanlar olarak görür:
```powershell
param($LogPath, $TargetHost, $Password)
```
İşte bu satır, bir güvenlik analistinin gözünde açık bırakılmış bir kale kapısıdır! Neden mi?
1. **Tip Belirtilmemiştir (Untyped - CWE-20):** `$LogPath` içerisine bir metin yerine zararlı bir script block, bir nesne dizisi veya belleği şişirecek devasa bir veri yapısı enjekte edilebilir.
2. **Doğrulama Yoktur (Missing Validation - CWE-22):** Hedef dosya yolu olarak `../../Windows/System32/config/SAM` verildiğinde betik itiraz etmeden çalışmaya başlar.
3. **Parola Açık Metindir (Cleartext Storage - CWE-312):** `$Password` parametresi `[string]` türünde olduğunda, PowerShell komut geçmişinde (`ConsoleHost_history.txt`), bellek dökümlerinde ve Script Block Logging (Event ID 4104) kayıtlarında açık metin olarak parlar!
4. **Argüman Enjeksiyonu Riski (CWE-88):** `$TargetHost` değişkeni alt süreçlere (örneğin `ping.exe $TargetHost`) gönderildiğinde `127.0.0.1 && whoami` gibi bir girdi komut zincirlemeye yol açar.

Usta der ki: **"Bir PowerShell fonksiyonunun ilk satırı, onun güvenlik kalkanıdır. Doğrulanmamış parametre, işletim sistemine verilmiş açık çektir."**

---

## 1. Gelişmiş Fonksiyon Bildirimi: `[CmdletBinding()]`

Basit bir PowerShell fonksiyonunu birinci sınıf bir cmdlet seviyesine yükselten ilk sihirli dokunuş `[CmdletBinding()]` özniteliğidir.

```powershell
[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'Medium',
    DefaultParameterSetName = 'PathSet'
)]
param (
    ...
)
```

### `[CmdletBinding()]` Ne Sağlar?
- **Ortak Parametre Desteği (Common Parameters):** `-Verbose`, `-Debug`, `-ErrorAction`, `-WarningAction`, `-WhatIf`, `-Confirm` parametreleri otomatik olarak fonksiyonunuza eklenir.
- **Kritik Eylemler İçin `ShouldProcess`:** Betiğiniz kritik bir işlem yapmadan önce (`$PSCmdlet.ShouldProcess("Hedef Sunucu", "Yapılandırma Değişikliği")`) kullanıcının onayını zorunlu kılabilir veya `-WhatIf` ile simülasyon yaptırabilir.
- **Konumsal Parametre Disiplini:** Hangi parametrenin hangi sırada kabul edileceğini katılaştırır, parametre karmaşasını önler.

---

## 2. Savunma Derinliği Sağlayan Doğrulama Öznitelikleri (`Validate*`)

PowerShell çalışma zamanı (runtime), parametreleri fonksiyona girmeden önce denetleyen son derece güçlü yerleşik özniteliklere (Attributes) sahiptir:

| Öznitelik | Güvenlik Amacı | Örnek Sözdizimi |
| :--- | :--- | :--- |
| `[ValidateNotNullOrEmpty()]` | Boş veya `$null` girdiyle mantık hatalarını ve DoS girişimlerini önler | `[ValidateNotNullOrEmpty()][string]$User` |
| `[ValidateScript({...})]` | Dosya varlığı, dizin sınırları veya karmaşık iş mantığını doğrular | `[ValidateScript({ Test-Path $_ -PathType Leaf })]` |
| `[ValidateRange(min, max)]` | Sayısal girdilerin sınır dışına çıkmasını ve bellek aşımını engeller | `[ValidateRange(1, 65535)][int]$Port` |
| `[ValidateSet('A', 'B')]` | Yalnızca izin verilen beyaz liste (whitelist) değerlerini kabul eder | `[ValidateSet('Audit', 'Enforce')][string]$Mode` |
| `[ValidatePattern('^regex$')]` | Komut ayırıcı, tırnak veya kaçış karakterlerini regex ile filtreler | `[ValidatePattern('^[a-zA-Z0-9_\-\.]+$')]` |
| `[ValidateCount(min, max)]` | Dizi parametrelerinin aşırı elemanla taşırılmasını engeller | `[ValidateCount(1, 10)][string[]]$Servers` |

---

## 3. Açık Metin Parola Tuzağı ve `[SecureString]` / `[PSCredential]`

Siber güvenlik denetimlerinde bulunan en yaygın zafiyetlerden biri açık metin kimlik bilgileridir.

### Hatalı Yaklaşım (Zafiyetli):
```powershell
param (
    [string]$DbPassword # KRİTİK ZAFİYET (CWE-312)
)
```
Bu kod çalıştırıldığında:
- Konsol ekranında parola görünür.
- `Get-History` veya `PSReadLine` dosyasında parola kaydedilir.
- Parametre bağlama aşamasında bellek alanında düz metin olarak yerleşir.

### Güvenli Yaklaşım (Usta Standartı):
```powershell
param (
    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$DbPassword
)
```
Ya da kullanıcı ve parola ikilisi için doğrudan yerleşik kimlik nesnesi:
```powershell
param (
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]$Credential
)
```
`SecureString`, veriyi Windows DPAPI (Data Protection API) ile şifreler, düz metin dizgisi gibi bellekte gezdirmez ve çöp toplayıcı (Garbage Collector) tarafından anında serbest bırakılır.

---

## 4. Dış Süreç Yürütme ve Argüman Enjeksiyonu (CWE-88)

Birçok PowerShell betiği, yerel komutları (`ping.exe`, `net.exe`, `curl.exe`, `git.exe`) tetikler:
```powershell
# ZAAFİYETLİ: Dize birleştirme ile komut çalıştırma
cmd.exe /c "ping $HostToPing"
```
Eğer saldırgan `$HostToPing` değerine `127.0.0.1 && net user hacker Password123 /add` girerse, `cmd.exe` ikinci komutu yönetici ayrıcalıklarıyla koşturur!

### Savunma: Güvenli Parametre Splatting (Hashtable Parametrizasyonu)
```powershell
# GÜVENLİ: Dizi halinde argüman listesi ve Start-Process
$sanitizedHost = $HostToPing -replace '[;&|`$]', ''
$procParams = @{
    FilePath     = 'ping.exe'
    ArgumentList = @('-n', '1', $sanitizedHost)
    NoNewWindow  = $true
    Wait         = $true
}
Start-Process @procParams
```
Argümanlar dizi (`string[]`) olarak iletildiğinde, işletim sistemi argüman ayrıştırıcısı girdiyi tek bir parametre olarak algılar; `&&` veya `|` gibi karakterler komut ayırıcı olarak yorumlanamaz.

---

## Ustanın Altın Öğütleri
1. **Her parametreye katı bir tip ata:** `[string]`, `[int]`, `[FileInfo]`, `[IPAddress]`.
2. **Beyaz liste (Whitelist) kullan:** Değer seçenekleri kısıtlıysa mutlaka `[ValidateSet()]` kullan.
3. **Parolayı asla string yapma:** Ya `[SecureString]` ya da `[PSCredential]`.
4. **Dış komut çağırırken dize birleştirme:** Argümanları her zaman dizi (`ArgumentList`) ve splatting (`@params`) ile aktar.
