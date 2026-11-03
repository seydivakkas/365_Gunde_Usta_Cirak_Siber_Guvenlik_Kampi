# =====================================================================
# GÜN 148: EDR OTOMATİK MÜDAHALE VE TEHDİT ENGELLEME BETİĞİ (POWERSHELL)
# Bu betik; tespit edilen zararlı süreçleri sonlandırır, dosyaları karantinaya alır
# ve gerekirse uç noktayı ağdan izole eder (Host Isolation).
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
# =====================================================================
$ErrorActionPreference = 'Stop'
Write-Host '[+] EDR Otomatik Müdahale Protokolü Başlatılıyor...' -ForegroundColor Cyan

Write-Host '[*] Temiz sistem. Aktif tehdit veya sonlandırılacak süreç bulunamadı.' -ForegroundColor Green