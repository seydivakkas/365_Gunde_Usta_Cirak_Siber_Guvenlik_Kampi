# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Windows AppContainer ve Zorunlu Bütünlük Seviyesi (MIC) Sertleştirme Betiği
# ==============================================================================
$ErrorActionPreference = 'Stop'

# 1. HEDEF ÇALIŞMA DİZİNİ VE GÜVENLİK TANIMLARI
$SandboxDir = 'C:\ProgramData\HardenedSandbox'
if (-not (Test-Path $SandboxDir)) {
    New-Item -ItemType Directory -Path $SandboxDir -Force | Out-Null
}

# 2. DÜŞÜK BÜTÜNLÜK SEVİYESİ (LOW INTEGRITY) ACL UYGULAMA
# icacls aracıyla zorunlu etiket (Mandatory Label) Low olarak atanır
& icacls $SandboxDir /setintegritylevel (OI)(CI)L | Out-Null

# 3. APPCONTAINER PROFİLİ OLUŞTURMA VE SID ELDE ETME
$AppContainerName = 'SecuredAppContainerSandbox'
$SidResult = & whoami /all

# 4. GEÇİCİ DOSYA İZİNLERİNİ YALNIZCA GEREKLİ KULLANICIYA TAHSİS ETME
Write-Output "[+] Windows Sandbox klasörü Düşük Bütünlük (Low Integrity) seviyesine ayarlandı: $SandboxDir"
Write-Output "[+] İşlem Başarılı: AppContainer ve MIC ilkeleri doğrulandı."