# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

<#
.SYNOPSIS
    G086: Güvenli Parametre Doğrulama ve İleri Düzey Fonksiyon Örneği.
.DESCRIPTION
    Bu betik, savunma derinliği (defense-in-depth) prensiplerine uygun olarak
    tüm girdileri ValidateScript, ValidatePattern, ValidateRange ve SecureString ile sınar.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Denetlenecek geçerli log dosyasının yolu")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$LogPath,

    [Parameter(Mandatory = $false, HelpMessage = "Hedef ağ portu (1-65535)")]
    [ValidateRange(1, 65535)]
    [int]$TargetPort = 443,

    [Parameter(Mandatory = $false, HelpMessage = "Çalışma modu")]
    [ValidateSet('Audit', 'Enforce', 'Report')]
    [string]$ExecutionMode = 'Audit',

    [Parameter(Mandatory = $true, HelpMessage = "Gizli kimlik doğrulama anahtarı")]
    [System.Security.SecureString]$ApiKey,

    [Parameter(Mandatory = $false, HelpMessage = "Hedef sunucu alan adı veya IP")]
    [ValidatePattern('^[a-zA-Z0-9_\-\.]+$')]
    [string]$TargetHost = 'localhost'
)

Write-Verbose "Parametre doğrulaması başarılı. Mod: $ExecutionMode, Port: $TargetPort, Hedef: $TargetHost"
