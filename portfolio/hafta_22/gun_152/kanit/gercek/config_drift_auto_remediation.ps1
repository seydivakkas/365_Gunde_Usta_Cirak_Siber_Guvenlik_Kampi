# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Güvenli Yapılandırma Sapması Otomatik Düzeltme (Remediation) Betiği
# ==============================================================================
$ErrorActionPreference = 'Stop'

Write-Output '[*] Güvenli yapılandırma temel hattına geri döndürme başlatılıyor...'

# Kural: CIS-WIN-1.1 - Kullanıcı Hesabı Denetimi (UAC) Etkin Olmalıdır [CRITICAL]
# Hedef: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord

# Kural: CIS-WIN-1.4 - Yerel Yöneticiler Grubunda Yalnızca Onaylı Hesaplar Bulunmalıdır [CRITICAL]
# Hedef: Administrators_Members
Remove-LocalGroupMember -Group 'Administrators' -Member 'backdoor_admin'

# Kural: CIS-WIN-1.5 - Windows Güvenlik Duvarı Etki Alanı Profili Açık Olmalıdır [HIGH]
# Hedef: DomainProfile_Enabled
Set-NetFirewallProfile -Profile Domain -Enabled True

Write-Output '[+] Tüm yapılandırma sapmaları başarıyla giderildi (100% Compliance).'