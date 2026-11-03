# GÜN 129: WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC GÜVENLİK DERSİ
**Eğitmen:** Usta Siber Güvenlik Mimarı  
**Öğrenci:** Çırak Güvenlik Mühendisi  
**Tarih:** 2 Kasım 2026  
**Konu:** Windows Split-Token Mimarisi, Kullanıcı Hesabı Denetimi (UAC), Yerel Hesap Sertleştirmesi ve LAPS  

---

## 1. GİRİŞ VE USTADAN ÇIRAĞA TAVSİYELER

**Usta:** Evlat, dün Microsoft Defender ve Güvenlik Merkezi'ni konuşurken uç noktanın dış tehditlere karşı nasıl kalkanlandığını gördük. Bugün ise işletim sisteminin tam merkezindeki en kritik güvenlik bariyerine iniyoruz: **Yetki Ayrımı, Yerel Hesaplar ve Kullanıcı Hesabı Denetimi (User Account Control - UAC)**.

Pek çok güvenlikçi veya yazılımcı UAC'yi "ekrana çıkan ve işimizi yavaşlatan can sıkıcı mavi/sarı kutucuk" sanır. Hatta kullanıcıların şikayetlerinden bıkan acemi sistem yöneticileri Denetim Masası'ndan UAC kaydırıcısını en alta çeker (`EnableLUA=0`) veya yerel yönetici için onay istemini kapatır. Bu hareket, işletim sisteminin kapısındaki çelik sürgüyü söküp çöpe atmakla eşdeğerdir!

**Çırak:** Hocam, kullanıcı zaten yerel yönetici (Local Administrator) grubundaysa, bir program çalıştırırken UAC'nin araya girmesi pratikte neyi koruyor?

**Usta:** İşte meselenin can alıcı noktası burası evlat! Windows Vista'dan beri hayatımızda olan **Split-Token (Ayrık Belirteç)** mimarisi sayesinde, yerel yönetici olan bir kullanıcı sisteme oturum açtığında Windows ona doğrudan tam yetki vermez. Kullanıcıya kısıtlanmış (Medium Integrity Level) bir standart kullanıcı belirteci verir. 

Kullanıcının tıkladığı bir web tarayıcısı, e-posta istemcisi veya indirdiği bir Word belgesi o kısıtlı belirteçle çalışır. Böylece o uygulamada bir sıfır-gün açığı çalışsa bile saldırgan doğrudan işletim sistemini ele geçiremez. Ta ki sistem dosyasını değiştirecek bir işlem yapılmak istendiğinde **UAC Consent (Onay)** penceresi açılana kadar. Bugün UAC'nin arka planındaki kernel mekanizmalarını, kayıt defteri anahtarlarını, bypass taktiklerini ve kurumsal sertleştirme kurallarını adım adım inceleyeceğiz.

---

## 2. WINDOWS TOKEN VE UAC İÇ MİMARİSİ

```
+---------------------------------------------------------------------------------------+
|                    WINDOWS SPLIT-TOKEN VE UAC YÜKSELTIM MİMARİSİ                      |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|  [YEREL YÖNETİCİ OTURUM AÇAR]                                                        |
|           │                                                                           |
|           ├───► [Kısıtlanmış Belirteç - Medium Integrity Level]                      |
|           │     (Explorer.exe, Tarayıcılar, Ofis Uygulamaları, Normal Kullanıcı)      |
|           │                                                                           |
|           └───► [Tam Yönetici Belirteci - High Integrity Level]                       |
|                 (Yalnızca UAC Onayı Verildiğinde İşleme Bağlanır)                     |
|                                                                                       |
|  [YÜKSELTME TALEBİ GELDİĞİNDE]                                                       |
|           │                                                                           |
|           ▼                                                                           |
|  [Application Information Hizmeti (AppInfo - svchost)]                               |
|           │                                                                           |
|           ▼                                                                           |
|  [Consent.exe Çalıştırılır] ──► [GÜVENLİ MASAÜSTÜ (Winlogon Desktop Switch)]          |
|                                 (Zararlı Yazılımın SendKeys İle Tıklaması Engellenir) |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

### 2.1 Split-Token (Ayrık Belirteç) ve Integrity Levels (Bütünlük Seviyeleri)
Windows güvenlik modelinde süreçler belirli bütünlük seviyelerinde (Integrity Levels) çalışır:
- **Untrusted (0x0000):** Anonim süreçler.
- **Low (0x1000):** Sandbox edilmiş tarayıcı sekmeleri (Edge, Chrome korumalı alanları).
- **Medium (0x2000):** Standart kullanıcılar ve yöneticilerin varsayılan uygulamaları (`explorer.exe`).
- **High (0x3000):** UAC onayından geçmiş yükseltilmiş yönetici süreçleri (`cmd.exe`, `regedit.exe`).
- **System (0x4000):** İşletim sistemi çekirdek servisleri (`lsass.exe`, `services.exe`).

Bir süreç kendisinden daha yüksek bütünlük seviyesindeki bir sürece `OpenProcess` ile erişemez, kod enjekte edemez ve pencere mesajı (`WM_DROPFILES`, `SendMessage`) gönderemez (UIPI - User Interface Privilege Isolation).

### 2.2 UAC Kayıt Defteri Parametreleri ve CIS Standartları
UAC politikaları `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` altında tutulur:

| Kayıt Defteri Değeri | Açıklama | Güvenli CIS Ayarı | Güvensiz Değer & Risk |
|---|---|---|---|
| **`EnableLUA`** | UAC motorunu açar veya kapatır | `1` (DWord) | `0`: UAC tamamen kapalıdır (`CWE-693`). Tüm süreçler doğrudan High IL ile başlar. |
| **`FilterAdministratorToken`** | Yerleşik Administrator hesabı için Yönetici Onay Modu | `1` (DWord) | `0`: SID 500 Administrator UAC istemi görmez, doğrudan High IL alır (`CWE-250`). |
| **`PromptOnSecureDesktop`** | Onay penceresinin Güvenli Masaüstünde açılması | `1` (DWord) | `0`: Normal masaüstünde açılır. Saldırgan yazılımlar SendKeys ile onay butonuna tıklayabilir (`CWE-284`). |
| **`ConsentPromptBehaviorAdmin`** | Yöneticiler için yükseltme davranışı | `2` (Güvenli masaüstünde izin) veya `1` (Parola) | `0`: Sessiz yükseltme (`T1548.002`). `5`: Yalnızca Windows dışı ikililer için onay (Bypass riski). |
| **`ConsentPromptBehaviorUser`** | Standart kullanıcılar için yükseltme davranışı | `0` (Otomatik Reddet) veya `3` (Güvenli Parola) | `1`: Normal masaüstünde kimlik bilgisi istemi. |
| **`EnableVirtualization`** | Eski 32-bit uygulamaların `C:\Windows` veya `HKLM` yazmalarını kullanıcı dizinine yönlendirme | `1` (DWord) | `0`: Eski programların çökmesine veya hatalı izin istemelerine sebep olur. |

---

## 3. UAC BYPASS TEKNİKLERİ VE KARŞI SAVUNMALAR (MITRE T1548.002)

**Usta:** Çırak, UAC varsayılan olarak (Varsayılan Kaydırıcı Konumu: Level 2 / `ConsentPromptBehaviorAdmin=5`) ayarlandığında, Microsoft tarafından dijital olarak imzalanmış bazı sistem ikilileri (örn: `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, `slui.exe`) **auto-elevate (otomatik yükselme)** yeteneğine sahiptir.

### Otomatik Yükselme İstismarı Nasıl Çalışır?
1. Saldırgan Medium IL seviyesinde çalışmaktadır.
2. `HKCU\Software\Classes\ms-settings\Shell\Open\command` kayıt defteri yoluna kendi zararlı `.exe` veya PowerShell komutunu yazar.
3. Ardından `fodhelper.exe` (Windows Özellik Yönetimi) ikilisini çalıştırır.
4. `fodhelper.exe` bir Microsoft bileşeni olduğu için Windows UAC ekranı göstermeden onu doğrudan High IL ile başlatır.
5. `fodhelper.exe` açılırken HKCU altındaki ilgili komutu arar ve saldırganın zararlısını High IL ile çalıştırır!

### Bu Açık Nasıl Kapatılır?
İşte bu yüzden CIS Windows Benchmark, `ConsentPromptBehaviorAdmin=2` (Always Prompt on Secure Desktop) veya `ConsentPromptBehaviorAdmin=1` (Prompt for Credentials) ayarını zorunlu kılar! Kural `2` veya `1` olduğunda, Microsoft imzalı ikililer de dahil olmak üzere **hiçbir süreç sessizce yükseltilemez**, ekranda mutlaka kullanıcı onayı veya parola istenir.

---

## 4. YEREL HESAPLAR VE HASSAS GRUPLARIN SERTLEŞTİRİLMESİ

### 4.1 Yerleşik Administrator (SID 500) Hesabı
- Windows kurulduğunda oluşan ilk hesabın SID'si `S-1-5-21-...-500` ile biter.
- Kaba kuvvet (Brute-Force) ve Pass-the-Hash saldırganlarının ilk hedefidir.
- **CIS Kuralı 2.3.1.1 & 2.3.1.2:** Yerleşik Administrator hesabı yeniden adlandırılmalı (örn: `SecAdmin_Lcl`), devre dışı bırakılmalı veya **Windows LAPS** ile yönetilmelidir.

### 4.2 Yerleşik Konuk (Guest - SID 501) Hesabı
- `S-1-5-21-...-501` SID'li bu hesap parolasız oturum açma imkanı tanır.
- **Kesinlikle devre dışı bırakılmalıdır** (`Disable-LocalUser -Name 'Guest'`). Aksi takdirde ağ üzerinden anonim SMB erişimlerine ve keşiflere zemin hazırlar (`CWE-284`).

### 4.3 Windows LAPS (Local Administrator Password Solution)
Kurumsal ağlarda tüm bilgisayarlarda aynı yerel yönetici parolası kullanılıyorsa, saldırgan bir bilgisayarı ele geçirdiğinde elde ettiği NTLM hash'i ile ağdaki tüm 5.000 bilgisayarda yanal hareket (Lateral Movement - T1021.002) yapabilir.
- **Windows LAPS Çözümü:** Her bilgisayarın yerel yönetici parolasını periyodik olarak (örn: 30 günde bir) rastgele ve karmaşık bir değerle otomatik değiştirir ve Active Directory / Azure AD üzerinde şifreli olarak saklar.

### 4.4 Hassas Yerel Gruplar
Bir istemcinin yerel `Administrators`, `Remote Desktop Users` ve `Backup Operators` grupları titizlikle denetlenmelidir. `Everyone`, `Domain Users` veya genel kullanıcı hesaplarının bu gruplara eklenmesi doğrudan bir felakettir (`CWE-250`).

---

## 5. CIS UYUMLU POWERSHELL SERTLEŞTİRME BETİĞİ

```powershell
# ====================================================================
# WINDOWS YEREL HESAPLAR VE UAC CIS HARDENING SCRIPT
# ====================================================================

# 1. Kullanıcı Hesabı Denetimini (UAC) En Üst Güvenliğe Çıkar
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Value 1 -Type DWord

# 2. Yerel Guest Hesabını Kapat ve Kilitleme Politikası Tanımla
Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15

# 3. Yerleşik Administrator Hesabını Yeniden Adlandır
$adminAccount = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
if ($adminAccount.Name -eq 'Administrator') {
    Rename-LocalUser -Name 'Administrator' -NewName 'SecAdmin_Local'
    Disable-LocalUser -Name 'SecAdmin_Local'
}

Write-Host "[+] Yerel Hesaplar ve UAC CIS Standartlarına Göre Sıkılaştırıldı." -ForegroundColor Green
```

---

## 6. ÖZET VE KAZANIMLAR

Bugün:
- Windows Split-Token ve Integrity Level mantığını kavradık.
- UAC'nin arkasındaki `EnableLUA`, `ConsentPromptBehaviorAdmin`, `PromptOnSecureDesktop` kayıt defteri anahtarlarını öğrendik.
- Otomatik yükselme (Auto-elevation) ve UAC Bypass açıklarının nasıl engelleneceğini gördük.
- Guest, Administrator ve hassas grupların kurumsal sertleştirme protokollerini başarıyla uyguladık.
