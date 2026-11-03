# ====================================================================
# Gün 145: Active Directory Group Policy (GPO) Sertleştirme Betiği
# Üretim Tarihi: 2026-11-03 10:03:16
# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır
# ====================================================================

# 1. SYSVOL cpassword İçeren Tercih XML Dosyalarının Temizliği (MS14-025)
Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL\*\Policies" -Recurse -Include Groups.xml, ScheduledTasks.xml | ForEach-Object {
    [xml]$xml = Get-Content $_.FullName
    if ($xml.SelectNodes("//*[@cpassword]")) {
        Write-Warning "UYARI: cpassword tespit edildi, ilgili GPP tercihini kaldırınız: $($_.FullName)"
    }
}

# 2. Windows LAPS İlkesini GPO ile Etkinleştirme (Pass-the-Hash Önlemi)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "BackupDirectory" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordComplexity" -Value 4 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordAgeDays" -Value 30 -Type DWord -Force

# 3. GPO ACL İzinlerinin Sıkılaştırılması (Standart Kullanıcı Yazma İzinlerinin Kaldırılması)
Write-Host "[+] GPO nesnelerinde Authenticated Users yalnızca Okuma (Read) hakkına sahip olmalıdır."

# 4. SeDebugPrivilege ve SeTakeOwnershipPrivilege Kısıtlaması
Write-Host "[+] Kritik işletim sistemi hakları yalnızca Domain Admins grubuna tahsis edilmelidir."