# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Windows BitLocker TPM 2.0 + PIN ve XTS-AES-256 Sertleştirme Betiği
# ==============================================================================
$ErrorActionPreference = 'Stop'

# 1. GRUP İLKESİ: XTS-AES-256 ŞİFRELEME ALGORİTMASINI ZORUNLU KILMA
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name 'EncryptionMethodWithXtsOs' -Value 7 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'EncryptionMethodWithXtsFdv' -Value 7 -Type DWord

# 2. TPM + PIN KORUYUCUSUNU ZORUNLU KILMA
Set-ItemProperty -Path $RegPath -Name 'UseAdvancedStartup' -Value 1 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'EnableBDEWithNoTPM' -Value 0 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'UseTPM' -Value 2 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'UseTPMPIN' -Value 2 -Type DWord

# 3. KURTARMA PAROLASINI ACTIVE DIRECTORY / ENTRA ID'YE YEDEKLEME
Set-ItemProperty -Path $RegPath -Name 'OSRecovery' -Value 1 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'OSRequireActiveDirectoryBackup' -Value 1 -Type DWord

# 4. BİTLOCKER'I C: SÜRÜCÜSÜNDE TPM + PIN İLE ETKİNLEŞTİRME
# Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector
Write-Output '[+] BitLocker sertleştirme ilkeleri başarıyla uygulandı.'
Write-Output '[+] XTS-AES-256 zorunlu kılındı, TPM+PIN kuralı devreye alındı.'