# G086: PowerShell Betik Parametreleri Soru ve Cevap Rehberi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

### Soru 1: PowerShell Gelişmiş Fonksiyonlarında `[CmdletBinding()]` ve `Validate*` Özniteliklerinin Güvenlik Açısından Rolü Nedir?

#### 1. Soru Başlığı ve Tanımı
PowerShell betiklerinde basit fonksiyon tanımları yerine `[CmdletBinding()]` kullanılmasının güvenlik mimarisindeki yeri nedir ve `Validate*` öznitelikleri girdi doğrulama zafiyetlerini (CWE-20) nasıl çalışma zamanında engeller?

#### 2. Derinlemesine Teknik Analiz
PowerShell motoru bir fonksiyonu yorumlarken iki farklı yürütme modeli kullanır:
1. **Basit Fonksiyon (Simple Function):** Girdiler gevşek bağlanır, ortak parametreler desteklenmez ve parametre doğrulama hataları geliştiricinin manuel kontrollerine terk edilir.
2. **Gelişmiş Fonksiyon (Advanced Function):** Fonksiyon başına `[CmdletBinding()]` eklendiğinde, PowerShell yürütme motoru cmdlet altyapısını (`Cmdlet` veya `PSCmdlet` temel sınıfını) devreye sokar. Bu sayede:
   - Parametre bağlama (Parameter Binding) motoru, fonksiyon gövdesi çalışmadan önce tüm girdileri doğrular.
   - `[ValidateScript({ Test-Path $_ })]` özniteliği, dosya varlığını fonksiyon içine girmeden sınar; geçersiz veya dizin atlama (`../`) içeren bir girdi durumunda yürütme derhal durdurulur ve `ParameterBindingValidationException` üretilir.
   - `[ValidatePattern()]` girdi dizesini Regex doğrulamasına tabi tutarak komut enjeksiyonu (`&&`, `|`, `;`) içeren bayrakların filtrelenmesini sağlar.
   - `[ValidateRange(min, max)]` tam sayı taşmalarını ve mantık dışı port veya boyut değerlerini engeller.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sistem yöneticisi, sunucu üzerindeki log dosyalarını analiz eden bir betik yazar. Ancak dosya yolu parametresini doğrulamadığı için saldırgan `--FilePath "C:\Windows\System32\cmd.exe"` veya `../../secret.key` gibi girdilerle yetkisiz dosya okuma/yürütme gerçekleştirir.

**Pratik Çözüm (Usta Yaklaşımı):**
```powershell
function Invoke-AuditLog {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Path $_ -PathType Leaf)) {
                throw "Hedef dosya bulunamadi veya bir dizin belirtildi: $_"
            }
            if ($_ -match '\.\.[/\\]') {
                throw "Dizin atlama (Path Traversal) tespit edildi: $_"
            }
            $true
        })]
        [string]$LogFilePath
    )

    process {
        Get-Content -Path $LogFilePath -Tail 50
    }
}
```

#### 4. Ustanın Çırağa Tavsiyesi
Çırak, fonksiyona gelen her girdi potansiyel olarak bir saldırganın elinden çıkmış gibi değerlendirilmelidir. Asla fonksiyon gövdesinde `if ($path -ne $null)` gibi ilkel kontrollerle vakit kaybetme; doğrulamayı PowerShell motorunun kapısında, `Validate*` öznitelikleriyle yap.

---

### Soru 2: Parametre Bildirimlerinde `[string]$Password` Kullanımının Yol Açtığı Riskler ve `[SecureString]` Çözümü Nedir?

#### 1. Soru Başlığı ve Tanımı
Betik parametrelerinde hassas kimlik bilgilerinin (parola, API anahtarı, gizli token) `[string]` türünde tanımlanması neden CWE-312 kapsamında kritik bir güvenlik açığıdır ve `[System.Security.SecureString]` ile `[PSCredential]` bu riski nasıl bertaraf eder?

#### 2. Derinlemesine Teknik Analiz
.NET ve PowerShell mimarisinde `System.String` nesneleri **değiştirilemezdir (immutable)**. Bir kez belleğe yazıldığında, Garbage Collector (Çöp Toplayıcı) belleği temizleyene kadar düz metin (plaintext) olarak RAM'de kalır. Üstelik:
1. **Bellek Dökümü Analizi:** LSASS dökümü veya işlem bellek analizi yapan saldırganlar açık metin parolaları anında okur.
2. **PSReadLine ve Komut Geçmişi:** Kullanıcı konsoldan `.\betik.ps1 -Password "Gizli123"` yazdığında, bu komut `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` dosyasına düz metin kaydedilir.
3. **Script Block Logging (Event ID 4104):** Windows Olay Günlükleri, komut satırı argümanlarını denetim kayıtlarına açık metin olarak düşürür.

`System.Security.SecureString` ise:
- Bellekte Windows DPAPI (CryptProtectMemory) ile şifrelenmiş halde tutulur.
- Bellekte tutulduğu süre boyunca düz metin okunamaz.
- `IDisposable` arayüzünü uygular; nesne sonlandığında bellek güvenli biçimde sıfırlanır (`ZeroFreeBSTR`).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Uzak bir veritabanına bağlanıp yedek alan bir otomasyon betiğinde parola düz metin parametre olarak alınmaktadır. Bir saldırgan sistemde düşük yetkili kullanıcı elde ettikten sonra PSReadLine geçmişini açarak veritabanı parolasını ele geçirir.

**Pratik Çözüm (Usta Yaklaşımı):**
```powershell
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Guvenli parola giriniz")]
    [System.Security.SecureString]$DatabasePassword
)

# Parola bellekten guvenli BSTR yontemiyle yalnizca hedef baglanti icin cozulur
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DatabasePassword)
try {
    # Baglanti nesnesine aktarim
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    # Kritik islem yapilir...
}
finally {
    # Bellek aninda sifirlanir ve serbest birakilir
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
```

#### 4. Ustanın Çırağa Tavsiyesi
Parola, API anahtarı veya gizli sertifika asla `[string]` olamaz! Eğer kullanıcıdan parola alacaksan ya `[PSCredential]` kullanıp Windows'un güvenli kimlik giriş penceresini açtır ya da `[SecureString]` ile belleği zırhlandır.

---

### Soru 3: PowerShell İçerisinden Dış Süreç Çağrılarında Argüman Enjeksiyonu (CWE-88) Nasıl Oluşur ve Güvenli Splatting ile Nasıl Engellenir?

#### 1. Soru Başlığı ve Tanımı
PowerShell betiklerinde harici komutlar (`cmd.exe`, `ping.exe`, `curl.exe`) çağrılırken parametrelerin dize birleştirme ile geçirilmesi nasıl argüman enjeksiyonuna (CWE-88) yol açar ve Parametre Splatting tekniği bu riski nasıl sıfırlar?

#### 2. Derinlemesine Teknik Analiz
PowerShell bir dizeyi `cmd.exe /c "komut $arg"` şeklinde çağırdığında, dize enterpolasyonu komut yürütülmeden önce gerçekleşir. Eğer `$arg` değişkeni `;`, `&&`, `|`, `` ` `` veya `>` gibi komut ayırıcıları içeriyorsa:
```text
cmd.exe /c "ping 127.0.0.1 && whoami"
```
Burada Windows Shell, `&&` karakterini iki ayrı bağımsız komut zinciri olarak yorumlar ve `whoami` komutunu çalıştırır.
Buna karşılık **Splatting ve `ArgumentList` dizisi** kullanıldığında:
- Argümanlar işletim sistemi API'sine (`CreateProcessW`) tek bir blok yerine ayrı diziler halinde iletilir.
- Ayrıştırıcı, `&& whoami` dizesini `ping.exe` programına ait geçersiz bir hedef ana bilgisayar adı olarak değerlendirir ve ikinci bir komut olarak asla yorumlamaz.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir ağ denetim betiği kullanıcıdan alınan host bilgisini `ping` komutuna aktarmaktadır. Kullanıcı girdi olarak `localhost | net user badguy /add` gönderdiğinde sistemde yetkisiz kullanıcı oluşturulur.

**Pratik Çözüm (Usta Yaklaşımı):**
```powershell
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9_\-\.]+$')]
    [string]$TargetHost
)

# Guvenli Splatting Yapilandirmasi
$pingParams = @{
    FilePath               = 'ping.exe'
    ArgumentList           = @('-n', '2', $TargetHost)
    NoNewWindow            = $true
    Wait                   = $true
    RedirectStandardOutput = 'audit_ping.log'
}

# Start-Process ile guvenli surec izolasyonu
Start-Process @pingParams
```

#### 4. Ustanın Çırağa Tavsiyesi
Evlat, hiçbir zaman string birleştirerek (`"cmd.exe /c $komut"`) süreç başlatma! Bu yöntem güvenlik dünyasında intihardır. Süreçleri her zaman izole `Start-Process` ile, parametreleri ise `@hashTable` splatting dizisi olarak aktar. Ayrıştırıcıyı kandıramayan saldırgan asla sisteme sızamaz.
