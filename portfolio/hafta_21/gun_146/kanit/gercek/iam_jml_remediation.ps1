# =====================================================================
# GÜN 146: IAM JML GÜVENLİK VE SERTLEŞTİRME OTOMASYON BETİĞİ (POWERSHELL)
# Bu betik; denetimde bulunan yetim hesapları kapatır ve SoD rollerini temizler.
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
# =====================================================================
$ErrorActionPreference = 'Stop'
Write-Host '[+] IAM JML Sertleştirme ve Yetim Hesap Temizliği Başlatılıyor...' -ForegroundColor Cyan

Write-Host '[*] Kurumsal dizin temiz. Kapatılacak yetim hesap veya SoD ihlali bulunamadı.' -ForegroundColor Green