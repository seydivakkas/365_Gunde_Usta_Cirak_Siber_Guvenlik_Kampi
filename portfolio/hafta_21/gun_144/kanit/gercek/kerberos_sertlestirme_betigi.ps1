# ====================================================================
# Gün 144: Active Directory ve Kerberos Güvenlik Sertleştirme Betiği
# Üretim Tarihi: 2026-11-03 06:54:40
# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır
# ====================================================================

# 1. Kerberos Şifreleme Türleri: DES ve RC4 Devre Dışı, Yalnızca AES Zorunlu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord -Force

# 2. DONT_REQ_PREAUTH Bayraklı Kullanıcıları Düzeltme (AS-REP Roasting Savunması)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false

# 3. Maksimum Saat Sapması (MaxClockSkew) ve NTP Senkronizasyonu
w32tm /config /manualpeerlist:"0.tr.pool.ntp.org,1.tr.pool.ntp.org" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync /force

# 4. KRBTGT Çift Sıfırlama Hatırlatması (Golden Ticket Kalıcılığı Önleme)
Write-Host "[+] KRBTGT hesabı için kontrollü çift sıfırlama periyodik icra edilmelidir."

# 5. Servis Hesaplarında gMSA (Group Managed Service Accounts) Kullanımı
Write-Host "[+] SPN tanımlı kritik hesaplar gMSA mimarisine geçirilmelidir."