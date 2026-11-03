# Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Raporu

**Denetçi:** Seydi Eryılmaz (@seydivakkas)  
**Tarih:** 2026-11-02T07:54:57.949318+00:00  
**Standart:** CIS Microsoft Windows Server 2022 / Windows 11 Enterprise  
**Genel Durum:** **WARNING** (74.0 / 100.0)  

---

## 1. Yönetici Özeti ve Alan Puan Dağılımı

| Denetim Alanı | Alınan Puan | Maksimum | Zafiyet Sayısı | Alan Durumu |
|---|---|---|---|---|
| **Windows Defender ve Uç Nokta Koruması** | 17.0 | 20.0 | 1 | COMPLIANT |
| **Yerel Hesaplar, Gruplar ve UAC** | 17.0 | 20.0 | 1 | COMPLIANT |
| **NTFS Erişim Kontrol Listeleri** | 14.0 | 20.0 | 1 | WARNING |
| **Windows Firewall Profilleri** | 15.0 | 20.0 | 1 | WARNING |
| **Windows Hizmet Güvenliği** | 11.0 | 20.0 | 2 | CRITICAL |
| **TOPLAM** | **74.0** | **100.0** | **6** | **WARNING** |

---

## 2. Tespit Edilen Zafiyetlerin Dağılımı

- **Kritik (CRITICAL):** 2
- **Yüksek (HIGH):** 3
- **Orta (MEDIUM):** 1
- **Düşük (LOW):** 0

---

## 3. Ayrıntılı Zafiyet Kataloğu ve İyileştirme Planı

### 1. [HIGH] Kurcalama Koruması (Tamper Protection) Kapalı
- **Alan:** `DEFENDER` | **Hedef:** `TamperProtection`
- **Standart:** `CWE-693` | MITRE ATT&CK: `T1562.001`
- **Teknik Açıklama:** Saldırganlar kayıt defterinden güvenlik ayarlarını değiştirebilir.
- **Düzeltici Aksiyon:**
  ```powershell
  Windows Güvenlik Merkezi üzerinden Tamper Protection özelliğini aktifleştirin.
  ```

### 2. [MEDIUM] Yerel Guest (Konuk) Hesabı Etkin
- **Alan:** `UAC` | **Hedef:** `GuestAccount`
- **Standart:** `CWE-284` | MITRE ATT&CK: `T1078.001`
- **Teknik Açıklama:** Konuk hesabı yetkisiz anonim oturumlara imkan tanır.
- **Düzeltici Aksiyon:**
  ```powershell
  Disable-LocalUser -Name 'Guest'
  ```

### 3. [CRITICAL] Kritik Sistem Dizinlerinde Kullanıcı Yazma İzni
- **Alan:** `NTFS` | **Hedef:** `SystemDirectoriesACL`
- **Standart:** `CWE-732` | MITRE ATT&CK: `T1574.009`
- **Teknik Açıklama:** Standart kullanıcılar şu sistem dizinlerine yazabilmektedir: C:\Program Files\LegacySuite
- **Düzeltici Aksiyon:**
  ```powershell
  icacls "C:\Program Files\LegacySuite" /remove:g "BUILTIN\Users" /grant:r "BUILTIN\Users:(RX)"
  ```

### 4. [CRITICAL] Public Profilde Tehlikeli Yönetim Portları Açık
- **Alan:** `FIREWALL` | **Hedef:** `PublicPortExposure`
- **Standart:** `CWE-284` | MITRE ATT&CK: `T1021.001`
- **Teknik Açıklama:** Kamusal ağda şu kritik servis portları açıktır: 3389 (RDP)
- **Düzeltici Aksiyon:**
  ```powershell
  Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -Profile Public
  ```

### 5. [HIGH] Tırnaksız Servis Yolu (BackupAgentSvc)
- **Alan:** `SERVICE` | **Hedef:** `BackupAgentSvc`
- **Standart:** `CWE-428` | MITRE ATT&CK: `T1574.009`
- **Teknik Açıklama:** 'BackupAgentSvc' hizmetinin yolu tırnaksızdır ve boşluk içerir: C:\Program Files\Enterprise Backup\agent.exe -run
- **Düzeltici Aksiyon:**
  ```powershell
  sc.exe config "BackupAgentSvc" binPath= "\"C:\Program Files\Enterprise Backup\agent.exe -run\""
  ```

### 6. [HIGH] Riskli RemoteRegistry Servisi Aktif
- **Alan:** `SERVICE` | **Hedef:** `RemoteRegistry`
- **Standart:** `CWE-16` | MITRE ATT&CK: `T1003.002`
- **Teknik Açıklama:** Uzaktan kayıt defteri manipülasyonu riski oluşturan servis etkindir.
- **Düzeltici Aksiyon:**
  ```powershell
  Set-Service -Name "RemoteRegistry" -StartupType Disabled; Stop-Service -Name "RemoteRegistry" -Force
  ```
