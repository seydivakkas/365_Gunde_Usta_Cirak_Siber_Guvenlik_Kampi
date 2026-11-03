# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

<#
.SYNOPSIS
    G085: PowerShell Nesne Boru Hattı Güvenlik ve Tehdit Avcılığı Modülü.
.DESCRIPTION
    Bu modül, PowerShell nesne boru hattı (pipeline) mekanizmasını kullanarak
    süreçleri, ağ bağlantılarını ve betikleri statik/dinamik güvenlik denetiminden geçirir.
#>

function Get-SecureProcessAudit {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [psobject]$InputProcess,
        [int]$CpuThreshold = 5
    )

    begin {
        # Boru hattı akışı başlamadan önce sonuç dizisi hazırlanır
        $auditResults = [System.Collections.Generic.List[psobject]]::new()
    }

    process {
        # Eğer boru hattından nesne verilmemişse yerel süreçler sorgulanır
        $targets = if ($InputProcess) { @($InputProcess) } else { Get-Process }

        foreach ($p in $targets) {
            # CPU veya imza kontrolü boru hattı filtresiyle gerçekleştirilir
            $isHighCpu = $p.CPU -gt $CpuThreshold
            $isSuspiciousName = $p.ProcessName -match '(?i)mimikatz|rubeus|chisel|nc'

            $status = if ($isSuspiciousName) { "CRITICAL" } elseif ($isHighCpu) { "WARNING" } else { "HEALTHY" }

            $customObj = [PSCustomObject]@{
                ProcessId   = $p.Id
                ProcessName = $p.ProcessName
                CPU         = [math]::Round([double]($p.CPU), 2)
                WorkingSetMB = [math]::Round(($p.WorkingSet64 / 1MB), 2)
                Status      = $status
            }
            $auditResults.Add($customObj)
        }
    }

    end {
        # Boru hattına sıralı nesneler akıtılır
        $auditResults | Sort-Object -Property ProcessId
    }
}

function Test-PipelineScriptSafety {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptContent
    )

    # IEX ve EncodedCommand gibi tehlikeli boru hattı kalıpları denetlenir
    $hasIex = $ScriptContent -match '\|\s*(?:Invoke-Expression|iex)\b'
    $hasEncoded = $ScriptContent -match '-(?:EncodedCommand|enc|e)\s+'

    $isSafe = -not ($hasIex -or $hasEncoded)

    [PSCustomObject]@{
        IsSafe       = $isSafe
        HasIex       = $hasIex
        HasEncoded   = $hasEncoded
        CheckDateUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}
