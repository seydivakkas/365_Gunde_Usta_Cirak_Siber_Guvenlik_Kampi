# NTFS ER���M KONTROL L�STELER� (ACL/DACL/SACL) DENET�M RAPORU
**Hedef Sistem:** `CORP-FILESERVER-01`  
**Denetim Kimli�i:** `AUD-NTFS-9DA7908A`  
**Tarih / Saat:** `2026-11-02T10:12:34.872988`  
**Denet�i Otoritesi:** `Enterprise NTFS ACL Auditor`  

---

## 1. Y�netici �zeti ve G�venlik Skoru

- **NTFS G�venlik Skoru:** `0.0 / 100`
- **Duru� Durumu:** **KR�T�K_ZAF�YET (SAVUNMASIZ DURUMDA)**
- **Tespit Edilen G�venlik A��kl���:** `6 Adet`

---

## 2. Tespit Edilen NTFS �zin Zafiyetleri Tablosu

| No | Ciddiyet | Zafiyet Ba�l��� | Yol | Hesap | Haklar | CWE | MITRE ATT&CK |
|---|---|---|---|---|---|---|---|
| 1 | **Kritik** | Zay�f NTFS �zni: 'BUILTIN\Users' -> 'Modify, Write' (service.exe) | `service.exe` | `BUILTIN\Users` | `Modify, Write` | `CWE-732` | `T1574.009 (Hijack Execution Flow / Unquoted Path / Binary Overwrite)` |
| 2 | **Kritik** | T�rnak ��ine Al�nmam�� Servis Yolu �stismar� (Unquoted Path): 'C:\Program Files\CustomCRM\service.exe' | `service.exe` | `BUILTIN\Users` | `Write/Modify on Unquoted Path Ancestor` | `CWE-428` | `T1574.009` |
| 3 | **Kritik** | Zay�f NTFS �zni: 'Everyone' -> 'Write' (agent service.exe) | `agent service.exe` | `Everyone` | `Write` | `CWE-732` | `T1574.009 (Hijack Execution Flow / Unquoted Path / Binary Overwrite)` |
| 4 | **Kritik** | T�rnak ��ine Al�nmam�� Servis Yolu �stismar� (Unquoted Path): 'C:\Program Files\Unquoted App\agent service.exe' | `agent service.exe` | `Everyone` | `Write/Modify on Unquoted Path Ancestor` | `CWE-428` | `T1574.009` |
| 5 | **Y�ksek** | Kritik Yolda Standart Kullan�c� Sahipli�i: 'C:\ProgramData\BackupData\secrets.bak' | `secrets.bak` | `Guest` | `Owner (Sahiplik)` | `CWE-284` | `T1078.003` |
| 6 | **Kritik** | Zay�f NTFS �zni: 'Everyone' -> 'FullControl' (secrets.bak) | `secrets.bak` | `Everyone` | `FullControl` | `CWE-732` | `T1574.009 (Hijack Execution Flow / Unquoted Path / Binary Overwrite)` |

---

## 3. icacls ve PowerShell Otomatik S�k�la�t�rma (Hardening) Beti�i

```powershell
# ====================================================================
# NTFS ER���M KONTROL L�STELER� (DACL) CIS SERTLE�T�RME BET���
# Hedef Sistem: CORP-FILESERVER-01 | Tarih: 2026-11-02T10:12:34.872988
# ====================================================================

# 1. G�vensiz ve Yetkisiz �zinleri Kald�rma (icacls komutlar�)
# Zay�f NTFS �zni: 'BUILTIN\Users' -> 'Modify, Write' (service.exe) (CWE-732)
icacls "C:\Program Files\CustomCRM\service.exe" /remove:g "BUILTIN\Users"
# T�rnak ��ine Al�nmam�� Servis Yolu �stismar� (Unquoted Path): 'C:\Program Files\CustomCRM\service.exe' (CWE-428)
icacls "C:\Program Files\CustomCRM\service.exe" /inheritance:r /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Users:(OI)(CI)RX"
# Zay�f NTFS �zni: 'Everyone' -> 'Write' (agent service.exe) (CWE-732)
icacls "C:\Program Files\Unquoted App\agent service.exe" /remove:g "Everyone"
# T�rnak ��ine Al�nmam�� Servis Yolu �stismar� (Unquoted Path): 'C:\Program Files\Unquoted App\agent service.exe' (CWE-428)
icacls "C:\Program Files\Unquoted App\agent service.exe" /inheritance:r /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Users:(OI)(CI)RX"
# Kritik Yolda Standart Kullan�c� Sahipli�i: 'C:\ProgramData\BackupData\secrets.bak' (CWE-284)
icacls "C:\ProgramData\BackupData\secrets.bak" /setowner "BUILTIN\Administrators"
# Zay�f NTFS �zni: 'Everyone' -> 'FullControl' (secrets.bak) (CWE-732)
icacls "C:\ProgramData\BackupData\secrets.bak" /remove:g "Everyone"

# 2. Standart CIS G�venli �zin �ablonunu Uygulama
# Y�neticiler ve SYSTEM: Tam Yetki (F), Standart Kullan�c�lar: Yaln�zca Okuma ve Y�r�tme (RX)
Write-Host '[+] NTFS ACL Sertle�tirmesi Ba�ar�yla Tamamland�!' -ForegroundColor Green
```

---

> [!NOTE]
> Bu denetim raporu **CIS Microsoft Windows 11 Benchmark v3.0.0 (Section 18/19)** ve **MITRE ATT&CK T1574.009 / T1068** standartlar�na dayal� olarak �retilmi�tir.
