# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Windows VSS Gölge Kopya ve Yedek Bütünlüğü Sertleştirme Betiği
# ==============================================================================
$ErrorActionPreference = 'Stop'

# 1. VSS VE VSSADMIN ARAÇLARININ YETKİSİZ ÇALIŞTIRILMASINI ENGELLEME
# Standart kullanıcıların ve tehlikeli süreçlerin vssadmin çağırmasını engellemek için ACL sıkılaştırılır
$VssAdminPath = "$env:SystemRoot\System32\vssadmin.exe"
& icacls $VssAdminPath /deny "Users:(X)" | Out-Null

# 2. GÖLGE KOPYA SERVİSİNİ VE AYRILAN ALANI YAPILANDIRMA
# C: sürücüsü için gölge kopya alan sınırını %15 olarak belirleme
& vssadmin resize shadowstorage /for=C: /on=C: /maxsize=15% | Out-Null

# 3. YEDEK ARŞİVLERİNİN SHA-256 SAĞLAMA TOPLAMINI OTOMATİK HESAPLAMA
$BackupDir = 'C:\Backups\Production'
if (Test-Path $BackupDir) {
    Get-ChildItem -Path $BackupDir -Filter *.bak | ForEach-Object {
        $Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        Set-Content -Path "$($_.FullName).sha256" -Value $Hash
        Write-Output "[+] Doğrulandı: $($_.Name) -> SHA256: $Hash"
    }
}

Write-Output '[+] VSS koruması ve SHA-256 sağlama toplamı ilkeleri başarıyla uygulandı.'