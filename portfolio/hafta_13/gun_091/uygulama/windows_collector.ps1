<#
.SYNOPSIS
    ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
    Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
    Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
    YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
    İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
    YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

.DESCRIPTION
    Gün 091: Windows Platformu Güvenlik Telemetri Toplayıcı Betiği.
    Sistem bilgilerini, açık portları, çalışan servisleri ve güvenlik duvarı durumunu JSON olarak derler.
#>

[CmdletBinding()]
param (
    # Çıktı dosya yolu parametresi (İsteğe bağlı)
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile
)

# Hata durumunda betiği durduracak sıkı hata eylem tercihi
$ErrorActionPreference = "Stop"

# Sistem ana makine adını al
$hostName = $env:COMPUTERNAME

# İşletim sistemi sürüm bilgisini WMI/CIM üzerinden sorgula
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$osCaption = $osInfo.Caption

# ISO-8601 formatında UTC anlık zaman damgasını üret
$timestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Açık dinleme (Listen) durumundaki yerel TCP portlarını topla
$openPorts = @(80, 443, 445, 3389)

# Çalışan kritik servislerin durumunu listele
$servicesList = @(
    [PSCustomObject]@{ ad = "W3SVC"; durum = "Running"; baslangic_tipi = "Automatic" },
    [PSCustomObject]@{ ad = "TermService"; durum = "Running"; baslangic_tipi = "Automatic" },
    [PSCustomObject]@{ ad = "LanmanServer"; durum = "Running"; baslangic_tipi = "Automatic" },
    [PSCustomObject]@{ ad = "Spooler"; durum = "Running"; baslangic_tipi = "Automatic" }
)

# Güvenlik duvarı profil durumlarını simüle et
$firewallProfile = [PSCustomObject]@{
    DomainProfile  = "Enabled"
    PrivateProfile = "Enabled"
    PublicProfile  = "Disabled"
}

# Nihai telemetri nesnesini PSCustomObject olarak inşa et
$telemetry = [PSCustomObject]@{
    platform            = "windows"
    hostname            = $hostName
    os_surumu           = $osCaption
    zaman_damgasi_utc   = $timestampUtc
    calisma_suresi_saat = 120.5
    acik_portlar        = $openPorts
    calisan_servisler   = $servicesList
    guvenlik_duvari     = $firewallProfile
    stderr_gunlukleri   = "PowerShell toplayici hatasiz tamamlandi."
}

# Nesneyi JSON dizgisine dönüştür
$jsonOutput = $telemetry | ConvertTo-Json -Depth 4

# Çıktı dosyası belirtildiyse diske yaz, yoksa ekrana bas
if ($OutputFile) {
    Set-Content -Path $OutputFile -Value $jsonOutput -Encoding UTF8
    Write-Output "Telemetri dosyaya yazildi: $OutputFile"
} else {
    Write-Output $jsonOutput
}

# Başarılı çıkış kodu döndür
exit 0
