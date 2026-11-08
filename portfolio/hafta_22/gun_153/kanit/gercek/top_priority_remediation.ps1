# PowerShell Otomatik İyileştirme Betiği - Kurumsal Uç Nokta Risk Panosu
# Hedef: Yüksek ve Kritik Riskli Uç Noktaların Güvenlik Açıklarını Giderme
# Üretim Zamanı: Filo Ortalama Risk: 24.5/100
$ErrorActionPreference = 'Stop'

Write-Host '[*] Kurumsal Uç Nokta İyileştirme Başlatılıyor...' -ForegroundColor Cyan

# -------------------------------------------------------------
# Uç Nokta: ENG-DEV-002 (10.0.30.22) - Risk Skoru: 84.8 (KRITIK)
# -------------------------------------------------------------
Write-Host '[!] ENG-DEV-002: EDR servisi başlatılıyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'ENG-DEV-002' -ScriptBlock {
    Start-Service -Name 'Sense' -ErrorAction SilentlyContinue
    Set-Service -Name 'Sense' -StartupType Automatic
}
Write-Host '[!] ENG-DEV-002: BitLocker şifrelemesi tetikleniyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'ENG-DEV-002' -ScriptBlock {
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
}
Write-Host '[!] ENG-DEV-002: UAC ve Güvenli Yapılandırma zorlanıyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'ENG-DEV-002' -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
}

# -------------------------------------------------------------
# Uç Nokta: CONTR-LAP-09 (10.0.50.88) - Risk Skoru: 91.8 (KRITIK)
# -------------------------------------------------------------
Write-Host '[!] CONTR-LAP-09: EDR servisi başlatılıyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'CONTR-LAP-09' -ScriptBlock {
    Start-Service -Name 'Sense' -ErrorAction SilentlyContinue
    Set-Service -Name 'Sense' -StartupType Automatic
}
Write-Host '[!] CONTR-LAP-09: BitLocker şifrelemesi tetikleniyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'CONTR-LAP-09' -ScriptBlock {
    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
}
Write-Host '[!] CONTR-LAP-09: UAC ve Güvenli Yapılandırma zorlanıyor...' -ForegroundColor Yellow
Invoke-Command -ComputerName 'CONTR-LAP-09' -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
}

Write-Host '[+] Tüm kritik uç noktalar için iyileştirme komutları tamamlandı.' -ForegroundColor Green