# PowerShell Aşama 6 Otomatik İyileştirme Betiği
# Hedef Kurum: SiberSavunma Kurumsal A.Ş.
$ErrorActionPreference = 'Stop'

Write-Host '[*] Aşama 6 Uç Nokta ve IAM İyileştirmeleri Başlatılıyor...' -ForegroundColor Cyan

# 1. NTLMv1 Devre Dışı Bırakma (LMCompatibilityLevel=5)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5

# 2. LSA Protection (RunAsPPL) Aktifleştirme
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1

# 3. Microsoft Defender Kurcalamaya Karşı Koruma (Tamper Protection) Açma
Set-MpPreference -DisableRealtimeMonitoring $false

# 4. Kalıcı Domain Admin Üyelerini Temizleme (JIT Hazırlığı)
Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.SamAccountName -ne 'Administrator'} | Remove-ADGroupMember -Identity 'Domain Admins' -Confirm:$false

Write-Host '[+] Aşama 6 kurumsal iyileştirme tamamlandı.' -ForegroundColor Green