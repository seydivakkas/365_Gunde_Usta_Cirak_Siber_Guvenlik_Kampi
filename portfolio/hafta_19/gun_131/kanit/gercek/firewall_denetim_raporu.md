# WINDOWS DEFENDER G�VENL�K DUVARI (FIREWALL) DENET�M RAPORU
**Hedef Sistem:** `CORP-LAPTOP-042`  
**Denetim Kimli�i:** `AUD-FW-8E04BC63`  
**Tarih / Saat:** `2026-11-02T10:21:53.249782`  
**Denet�i Otoritesi:** `Enterprise Windows Firewall Auditor`  

---

## 1. Y�netici �zeti ve G�venlik Skoru

- **G�venlik Duvar� Duru� Skoru:** `65.0 / 100`
- **Duru� Durumu:** **ORTA_R�SK (�Y�LE�T�RME GEREKL�)**
- **Tespit Edilen G�venlik A��kl���:** `3 Adet`

---

## 2. Tespit Edilen G�venlik Duvar� A��kl�klar� Tablosu

| No | Ciddiyet | Zafiyet Ba�l��� | CWE | MITRE ATT&CK | Mevcut De�er | �nerilen De�er |
|---|---|---|---|---|---|---|
| 1 | **Orta** | Private Profilinde Engellenen Paket K�t�klemesi Kapal� | `CWE-778` | `T1562.004` | `False` | `True` |
| 2 | **D���k** | Private Profil K�t�k Boyutu Yetersiz (< 16 MB) | `CWE-778` | `T1562.004` | `8192 KB` | `>= 16384 KB` |
| 3 | **Kritik** | Public Profilde RDP (Uzak Masa�st�) (Port 3389) A��k: 'Insecure-Public-RDP' | `CWE-284` | `T1021.001` | `Public Profile, Port 3389` | `Public Profilde Y�netim Portlar� Kesinlikle Kapat�lmal�d�r` |

---

## 3. PowerShell ve netsh Otomatik S�k�la�t�rma (Hardening) Beti�i

```powershell
# ====================================================================
# WINDOWS DEFENDER FIREWALL CIS BENCHMARK SERTLE�T�RME BET���
# Hedef Sistem: CORP-LAPTOP-042 | Tarih: 2026-11-02T10:21:53.249782
# ====================================================================

# 1. T�m Profilleri A� ve Varsay�lan Gelen Trafi�i Blokla
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow

# 2. G�venlik Duvar� K�t�kleme (Logging) Politikalar�n� Yap�land�r
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True
Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'

# 3. Public Profilde Gelen �stisnalar� S�n�rla
Set-NetFirewallProfile -Profile Public -AllowInboundRules False

# 4. Tehlikeli A��k Kurallar� Kapat / S�n�rla
Set-NetFirewallRule -DisplayName 'Insecure-Public-RDP' -Profile Domain,Private

Write-Host '[+] Windows G�venlik Duvar� CIS Sertle�tirmesi Ba�ar�yla Tamamland�!' -ForegroundColor Green
```

---

> [!NOTE]
> Bu denetim raporu **CIS Microsoft Windows 11 / Server Benchmark (Section 9)** ve **MITRE ATT&CK T1562.004 / T1021** standartlar�na dayal� olarak �retilmi�tir.
