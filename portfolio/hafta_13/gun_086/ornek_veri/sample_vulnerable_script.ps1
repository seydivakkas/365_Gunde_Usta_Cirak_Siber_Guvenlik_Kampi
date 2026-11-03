# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

<#
.SYNOPSIS
    G086: Güvenlik Zaafiyetleri İçeren Örnek Parametre Bloğu (Denetim Amaçlı).
#>

param (
    [string]$Password,
    $TargetFile,
    [string]$HostToPing,
    [int]$Port
)

# Zaafiyet 1: Açık metin parola parametresi (CWE-312)
# Zaafiyet 2: Doğrulanmamış dosya yolu parametresi (CWE-22)
# Zaafiyet 3: Doğrulanmamış argüman enjeksiyonu (CWE-88)
cmd.exe /c "ping $HostToPing"
