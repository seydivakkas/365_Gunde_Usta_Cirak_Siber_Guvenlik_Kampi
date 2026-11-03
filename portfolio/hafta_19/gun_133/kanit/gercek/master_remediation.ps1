# ===========================================================================
# Mini Proje 18: Bütünleşik Windows Güvenlik Sıkılaştırma Master Betiği
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır
# ===========================================================================
# Bu betik yükseltilmiş ayrıcalıklarla (Run as Administrator) çalıştırılmalıdır.
$ErrorActionPreference = 'Continue'
Write-Host '[*] Kurumsal Windows Güvenlik Sıkılaştırma Başlatılıyor...' -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# BÖLÜM: DEFENDER ALANI İYİLEŞTİRMELERİ (1 Adet)
# ---------------------------------------------------------------------------
# Adım 1: [HIGH] Kurcalama Koruması (Tamper Protection) Kapalı (CWE-693)
Write-Host '[>] Uygulanıyor: Kurcalama Koruması (Tamper Protection) Kapalı...' -ForegroundColor Yellow
Windows Güvenlik Merkezi üzerinden Tamper Protection özelliğini aktifleştirin.

# ---------------------------------------------------------------------------
# BÖLÜM: UAC ALANI İYİLEŞTİRMELERİ (1 Adet)
# ---------------------------------------------------------------------------
# Adım 2: [MEDIUM] Yerel Guest (Konuk) Hesabı Etkin (CWE-284)
Write-Host '[>] Uygulanıyor: Yerel Guest (Konuk) Hesabı Etkin...' -ForegroundColor Yellow
Disable-LocalUser -Name 'Guest'

# ---------------------------------------------------------------------------
# BÖLÜM: NTFS ALANI İYİLEŞTİRMELERİ (1 Adet)
# ---------------------------------------------------------------------------
# Adım 3: [CRITICAL] Kritik Sistem Dizinlerinde Kullanıcı Yazma İzni (CWE-732)
Write-Host '[>] Uygulanıyor: Kritik Sistem Dizinlerinde Kullanıcı Yazma İzni...' -ForegroundColor Yellow
icacls "C:\Program Files\LegacySuite" /remove:g "BUILTIN\Users" /grant:r "BUILTIN\Users:(RX)"

# ---------------------------------------------------------------------------
# BÖLÜM: FIREWALL ALANI İYİLEŞTİRMELERİ (1 Adet)
# ---------------------------------------------------------------------------
# Adım 4: [CRITICAL] Public Profilde Tehlikeli Yönetim Portları Açık (CWE-284)
Write-Host '[>] Uygulanıyor: Public Profilde Tehlikeli Yönetim Portları Açık...' -ForegroundColor Yellow
Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -Profile Public

# ---------------------------------------------------------------------------
# BÖLÜM: SERVICE ALANI İYİLEŞTİRMELERİ (2 Adet)
# ---------------------------------------------------------------------------
# Adım 5: [HIGH] Tırnaksız Servis Yolu (BackupAgentSvc) (CWE-428)
Write-Host '[>] Uygulanıyor: Tırnaksız Servis Yolu (BackupAgentSvc)...' -ForegroundColor Yellow
sc.exe config "BackupAgentSvc" binPath= "\"C:\Program Files\Enterprise Backup\agent.exe -run\""

# Adım 6: [HIGH] Riskli RemoteRegistry Servisi Aktif (CWE-16)
Write-Host '[>] Uygulanıyor: Riskli RemoteRegistry Servisi Aktif...' -ForegroundColor Yellow
Set-Service -Name "RemoteRegistry" -StartupType Disabled; Stop-Service -Name "RemoteRegistry" -Force

Write-Host '[+] Tüm Windows güvenlik alanları başarıyla sıkılaştırıldı!' -ForegroundColor Green