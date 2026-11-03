# ===========================================================================
# Windows Hizmet Güvenliği Otomatik Sıkılaştırma ve İyileştirme Betiği
# Telif Hakkı (c) 2026 Seydi Eryılmaz - Tüm Hakları Saklıdır
# ===========================================================================
# Bu betik Yönetici (Run as Administrator) olarak çalıştırılmalıdır.
$ErrorActionPreference = 'Continue'
Write-Host '[*] Windows Servis Güvenlik Sıkılaştırma Başlatılıyor...' -ForegroundColor Cyan

# Adım 1: InsecureBackupSvc - Tırnaksız Servis Yolu (Unquoted Service Path) (CWE-428)
Write-Host '[>] Sıkılaştırılıyor: InsecureBackupSvc (Tırnaksız Servis Yolu (Unquoted Service Path))...' -ForegroundColor Yellow
sc.exe config "InsecureBackupSvc" binPath= "\"C:\Program Files\Enterprise Backup Suite\backup_engine.exe -daemon\""

# Adım 2: InsecureBackupSvc - Aşırı Yetkili Servis Hesabı (En Az Ayrıcalık Prensibi İhlali) (CWE-250)
Write-Host '[>] Sıkılaştırılıyor: InsecureBackupSvc (Aşırı Yetkili Servis Hesabı (En Az Ayrıcalık Prensibi İhlali))...' -ForegroundColor Yellow
Servisi 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService' veya bir gMSA hesabı ile çalışacak şekilde yapılandırın.

# Adım 3: LegacyDbAgent - Zayıf Servis DACL İzni (Hizmet Yapılandırma Yetkisi) (CWE-732)
Write-Host '[>] Sıkılaştırılıyor: LegacyDbAgent (Zayıf Servis DACL İzni (Hizmet Yapılandırma Yetkisi))...' -ForegroundColor Yellow
sc.exe sdset "LegacyDbAgent" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

# Adım 4: LegacyDbAgent - Aşırı Yetkili Servis Hesabı (En Az Ayrıcalık Prensibi İhlali) (CWE-250)
Write-Host '[>] Sıkılaştırılıyor: LegacyDbAgent (Aşırı Yetkili Servis Hesabı (En Az Ayrıcalık Prensibi İhlali))...' -ForegroundColor Yellow
Servisi 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService' veya bir gMSA hesabı ile çalışacak şekilde yapılandırın.

# Adım 5: CustomLogger - Zayıf Servis İkili Dosya İzni (Binary Hijacking) (CWE-732)
Write-Host '[>] Sıkılaştırılıyor: CustomLogger (Zayıf Servis İkili Dosya İzni (Binary Hijacking))...' -ForegroundColor Yellow
icacls "C:\CustomApps\Logger\logger.exe" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)"

# Adım 6: RemoteRegistry - Gereksiz ve Riskli Servis Aktif (RemoteRegistry) (CWE-16)
Write-Host '[>] Sıkılaştırılıyor: RemoteRegistry (Gereksiz ve Riskli Servis Aktif (RemoteRegistry))...' -ForegroundColor Yellow
Set-Service -Name "RemoteRegistry" -StartupType Disabled; Stop-Service -Name "RemoteRegistry" -Force

Write-Host '[+] Servis sıkılaştırma işlemleri tamamlandı!' -ForegroundColor Green