# WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC DENET�M RAPORU
**Hedef Sistem:** `CORP-CLIENT-088`  
**Denetim Kimli�i:** `AUD-UAC-A3363D7D`  
**Tarih / Saat:** `2026-11-02T09:53:34.241574`  
**Denet�i Otoritesi:** `Enterprise UAC & Account Auditor`  

---

## 1. Y�netici �zeti ve G�venlik Skoru

- **UAC ve Hesap G�venlik Skoru:** `5.0 / 100`
- **Duru� Durumu:** **KR�T�K_ZAF�YET (SAVUNMASIZ DURUMDA)**
- **Tespit Edilen G�venlik A��kl���:** `7 Adet`

---

## 2. Tespit Edilen Zafiyet ve Risk Tablosu

| No | Ciddiyet | Zafiyet Ba�l��� | CWE | MITRE ATT&CK | Mevcut De�er | �nerilen De�er |
|---|---|---|---|---|---|---|
| 1 | **Y�ksek** | Yerle�ik Y�netici Onay Modu (Admin Approval Mode) Kapal� | `CWE-250` | `T1548.002` | `False` | `True` |
| 2 | **Y�ksek** | UAC G�venli Masa�st� �stemi (PromptOnSecureDesktop) Devre D��� | `CWE-284` | `T1548.002` | `False` | `True` |
| 3 | **Y�ksek** | Y�neticiler i�in Zay�f UAC Y�kseltme �stemi Davran��� | `CWE-250` | `T1548.002` | `5` | `2` |
| 4 | **Orta** | Standart Kullan�c�lar i�in G�vensiz Y�kseltme �stemi | `CWE-284` | `T1548.002` | `1` | `0` |
| 5 | **Y�ksek** | Yerle�ik Administrator Hesab� Varsay�lan Adda ve Etkin | `CWE-1188` | `T1078.003` | `Ad: Administrator (Etkin)` | `Yeniden Adland�r�lmal� ve Devre D��� B�rak�lmal�` |
| 6 | **Orta** | Hatal� Oturum A�ma Kilitleme E�i�i Yetersiz veya S�f�r | `CWE-307` | `T1110 (Brute Force)` | `0` | `<= 5 Ge�ersiz Deneme` |
| 7 | **Orta** | Windows LAPS (Local Administrator Password Solution) Etkin De�il | `CWE-1188` | `T1078.003` | `False` | `True` |

---

## 3. PowerShell Otomatik S�k�la�t�rma (Hardening) Beti�i

```powershell
# ====================================================================
# WINDOWS YEREL HESAPLAR VE UAC CIS BENCHMARK SERTLE�T�RME BET���
# Hedef Sistem: CORP-CLIENT-088 | Olu�turulma: 2026-11-02T09:53:34.241574
# ====================================================================

# 1. Kullan�c� Hesab� Denetimi (UAC) Politikalar�n� S�k�la�t�rma
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Value 1 -Type DWord

# 2. Yerel Hesap G�venli�i ve Kilitleme Politikalar�
Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15

Write-Host '[+] Windows Yerel Hesaplar ve UAC CIS S�k�la�t�rmas� Ba�ar�yla Tamamland�!' -ForegroundColor Green
```

---

> [!NOTE]
> Bu denetim raporu **CIS Microsoft Windows 11 Benchmark v3.0.0 (Section 2.3)** ve **MITRE ATT&CK T1548.002 / T1078.003** standartlar�na dayal� olarak �retilmi�tir.
