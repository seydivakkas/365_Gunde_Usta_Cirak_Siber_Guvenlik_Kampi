# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

<#
.SYNOPSIS
    G085: Güvenli PowerShell Nesne Boru Hattı Örnek İnceleme Betiği.
.DESCRIPTION
    Bu betik, nesne boru hattını (object pipeline) güvenli filtreleme,
    tür güvenliği ve bellek akışı prensiplerine uygun olarak kullanır.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$MemoryThresholdMB = 100
)

# 1. Bellek tüketimi eşiğin üzerinde olan süreçleri nesne boru hattında filtrele
Get-Process | 
    Where-Object { $_.WorkingSet64 -gt ($MemoryThresholdMB * 1MB) } | 
    Select-Object -Property Id, ProcessName, @{Name='MemoryMB'; Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}} | 
    Sort-Object -Property MemoryMB -Descending

# 2. Dinamik kod çalıştırmadan güvenli toplama işlemi (Measure-Object)
Get-Process | 
    Measure-Object -Property CPU -Sum -Average -Maximum | 
    Select-Object -Property Count, Sum, Average, Maximum
