# GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ (ACL / DACL / SACL) DERSİ
**Eğitmen:** Usta Siber Güvenlik Mimarı  
**Öğrenci:** Çırak Güvenlik Mühendisi  
**Tarih:** 2 Kasım 2026  
**Konu:** Windows NTFS Güvenlik Tanımlayıcıları, DACL Değerlendirme Algoritması, DLL Hijacking ve icacls Sertleştirmesi  

---

## 1. GİRİŞ VE USTADAN ÇIRAĞA TAVSİYELER

**Usta:** Evlat, dün Windows işletim sisteminde hesapların ve UAC yükseltim mekanizmasının nasıl çalıştığını öğrendik. Bugün ise işletim sisteminde çalışan her sürecin, her kullanıcının ve her servisin temas ettiği en somut güvenlik sınırına iniyoruz: **NTFS Dosya Sistemi Erişim Kontrol Listeleri (Access Control Lists - ACL)**.

Bir sistemde antivirüs açık olabilir, EDR kurulmuş olabilir, hatta UAC en üst seviyede çalışıyor olabilir. Ancak `C:\Program Files` altındaki bir servis ikilisinde veya DLL kütüphanesinde `BUILTIN\Users` veya `Everyone` grubuna **Modify (Değiştirme)** veya **Write (Yazma)** izni verilmişse, o sistem fiilen ele geçirilmiştir! 

**Çırak:** Hocam, saldırgan standart kullanıcı haklarına sahipken bir servis dosyasına yazabildiğinde tam olarak ne yapabilir?

**Usta:** Bak evlat, bir Windows servisi genellikle en yüksek yetki olan `NT AUTHORITY\SYSTEM` kimliğiyle çalışır. Eğer o servisin çalıştırdığı `.exe` dosyası veya o dosyanın aradığı bir `.dll` dosyası standart kullanıcı tarafından üzerine yazılabilir durumdaysa (CWE-732), saldırgan kendi hazırladığı tersine kabuk (reverse shell) kodunu o dosyanın yerine koyar. Servis yeniden başladığında veya sistem reboot edildiğinde saldırganın kodu doğrudan SYSTEM yetkisiyle çalışır (MITRE T1574.009 / T1068). Buna **Privilege Escalation via Insecure Service Binary** denir.

Bugün NTFS Güvenlik Tanımlayıcısı'nın (Security Descriptor) anatomisini, DACL ve SACL ayrımını, ACE değerlendirme algoritmasını ve `icacls` aracıyla endüstri standardı sertleştirmeyi santim santim öğreneceksin.

---

## 2. NTFS GÜVENLİK TANIMLAYICISI (SECURITY DESCRIPTOR) MİMARİSİ

```
+---------------------------------------------------------------------------------------+
|                    NTFS GÜVENLİK TANIMLAYICISI (SECURITY DESCRIPTOR)                  |
+---------------------------------------------------------------------------------------+
|  [OWNER SID]  : Nesnenin sahibi (örn: BUILTIN\Administrators veya TrustedInstaller)   |
|  [GROUP SID]  : Birincil grup (POSIX uyumluluğu için kullanılır)                      |
|  [CONTROL]    : SE_DACL_PRESENT, SE_DACL_PROTECTED (Miras Bloklama) vb.               |
+---------------------------------------------------------------------------------------+
|  [DACL] (Discretionary Access Control List - İsteğe Bağlı Erişim Kontrol Listesi):    |
|    ├── ACE 1: Explicit Deny  (Açık Reddetme)  ──► [ÖNCELİK 1]                          |
|    ├── ACE 2: Explicit Allow (Açık İzin Verme) ──► [ÖNCELİK 2]                          |
|    ├── ACE 3: Inherited Deny (Miras Reddetme)  ──► [ÖNCELİK 3]                          |
|    └── ACE 4: Inherited Allow (Miras İzin Verme) ──► [ÖNCELİK 4]                        |
+---------------------------------------------------------------------------------------+
|  [SACL] (System Access Control List - Sistem Denetim ve Kütükleme Listesi):           |
|    └── Audit ACE'leri: Başarısız/Başarılı okuma-yazma girişimlerini Event Log'a yazar|
+---------------------------------------------------------------------------------------+
```

### 2.1 DACL vs SACL Ayrımı
- **DACL (Discretionary Access Control List):** Nesneye **kimin hangi hakla (Okuma, Yazma, Yürütme, Tam Denetim)** erişebileceğini belirler. Eğer bir nesnenin DACL'ı boşsa (NULL DACL), herkes her şeyi yapabilir. Eğer DACL var ancak içinde hiç ACE yoksa (Empty DACL), hiç kimse erişemez.
- **SACL (System Access Control List):** Erişim kararı vermez; nesneye yapılan erişim denemelerinin denetlenmesini (Audit) sağlar. Örneğin `secrets.kdbx` dosyasına yapılan her başarısız okuma denemesi Windows Güvenlik Günlüğü'ne (Event ID 4663 / 4656) yazılır. SACL'ı yalnızca `SeSecurityPrivilege` ayrıcalığına sahip yöneticiler okuyup değiştirebilir.

### 2.2 ACE (Access Control Entry) Türleri ve Hakları
DACL içerisindeki her kural bir ACE'dir:
- **Haklar (Rights):**
  - `F (Full Control)`: Dosyayı silme, izinlerini değiştirme (`WRITE_DAC`) ve sahipliğini alma (`WRITE_OWNER`) dahil sınırsız yetki.
  - `M (Modify)`: Dosyayı okuma, yazma, çalıştırma ve silme.
  - `RX (Read and Execute)`: Dosyayı okuma ve ikili olarak yürütme.
  - `R (Read)`: Yalnızca dosya içeriğini okuma.
  - `W (Write)`: Dosyaya yeni veri ekleme ve dosya özniteliklerini değiştirme.
- **Miras Bayrakları (Inheritance Flags):**
  - `(OI) - Object Inherit`: Klasör altındaki dosyalar kuralı devralır.
  - `(CI) - Container Inherit`: Klasör altındaki alt klasörler kuralı devralır.
  - `(IO) - Inherit Only`: Kural mevcut klasöre uygulanmaz, yalnızca devralan alt nesnelere geçer.
  - `(NP) - Do Not Propagate`: Kural yalnızca bir alt seviyeye devredilir, daha derine inmez.

### 2.3 Windows Çekirdeği DACL Değerlendirme Algoritması
Windows Security Reference Monitor (SRM), bir işlem dosya açmak istediğinde DACL'ı şu katı sırayla yukarıdan aşağıya tarar:
1. **Explicit Deny (Açık Reddetme) ACE'leri:** İstenen hak açıkça reddedilmişse, işlem anında `ACCESS_DENIED` ile sonlanır.
2. **Explicit Allow (Açık İzin Verme) ACE'leri:** İstenen hak açıkça verilmişse ve reddedilmemişse işlem onaylanır.
3. **Inherited Deny (Miras Reddetme) ACE'leri.**
4. **Inherited Allow (Miras İzin Verme) ACE'leri.**
5. **Varsayılan Karar:** Liste sonuna kadar talep edilen tüm haklar karşılanmamışsa, erişim reddedilir (Default Deny).

> [!WARNING]
> Eğer bir yazılım DACL'ı kanonik olmayan (Non-Canonical) sırada yazarsa (örneğin Explicit Allow kuralını Explicit Deny'nin üstüne koyarsa), Windows GUI kural listesini açarken uyarı verir; çünkü reddetme kuralı beklenen korumayı sağlamayabilir (`CWE-284`).

---

## 3. EN KRİTİK NTFS İZİN ZAFİYETLERİ VE SALDIRI SENARYOLARI

### 3.1 Zayıf Servis İkilisi İzinleri (CWE-732 / MITRE T1068)
- **Problem:** Üçüncü parti bir yedekleme yazılımı `C:\Program Files\BackupAgent\agent.exe` altına kurulurken kurulum betiği `BUILTIN\Users:(F)` vermiştir.
- **İstismar:** Saldırgan `agent.exe` dosyasını siler veya adını değiştirir, yerine kötü amaçlı kendi `agent.exe` ikilisini koyar. Sistem yeniden başladığında servis SYSTEM olarak ayağa kalkar ve saldırgana SYSTEM kabuğu verir.

### 3.2 Tırnak İçine Alınmamış Boşluklu Servis Yolları (Unquoted Service Path - CWE-428 / MITRE T1574.009)
- **Problem:** Servis kayıt defteri yolu `ImagePath` çift tırnak olmadan tanımlanmıştır:  
  `C:\Program Files\My Antivirus Suite\agent.exe`
- **İstismar:** Windows bir servis yolunda boşluk gördüğünde ve tırnak yoksa şu sırayla çalıştırmayı dener:
  1. `C:\Program.exe`
  2. `C:\Program Files\My.exe`
  3. `C:\Program Files\My Antivirus.exe`
  4. `C:\Program Files\My Antivirus Suite\agent.exe`
- Eğer standart kullanıcının `C:\` kök dizinine veya `C:\Program Files` altına yazma hakkı varsa, saldırgan oraya `My.exe` adında zararlı bir dosya bırakır. Servis ilk olarak bu sahte dosyayı çalıştırır!

### 3.3 DLL Hijacking ve Arama Yolu Zehirleme (MITRE T1574.001)
- Sistem `PATH` ortam değişkeninde yer alan bir klasör (örneğin `C:\Python39\Scripts` veya `C:\Tools`) `BUILTIN\Users` tarafından yazılabilir durumdaysa, yüksek yetkili bir uygulama eksik bir sistem DLL'ini ararken sırayla PATH dizinlerine bakar.
- Saldırgan sahte DLL'i bu yazılabilir dizine bırakır ve yüksek yetkili süreç tarafından yüklenmesini sağlar.

---

## 4. ICACLS VE POWERSHELL İLE CIS NTFS SERTLEŞTİRME REÇETESİ

Bir kurumsal Windows ortamında dosya ve dizin izinlerini sertleştirmek için kullanılan altın standart komutlar şunlardır:

```powershell
# ====================================================================
# MICROSOFT WINDOWS NTFS CIS SERTLEŞTİRME PROTOKOLÜ (ICACLS)
# ====================================================================

# 1. Miras Alınan Güvensiz İzinleri Kır ve Temiz Bir DACL Başlat
# /inheritance:r -> Üst dizinden gelen tüm miras izinlerini kaldırır
# /grant:r       -> Mevcut izinleri sıfırlayarak sadece belirtilenleri tanımlar
icacls "C:\Program Files\VendorApp" /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
    /grant:r "BUILTIN\Users:(OI)(CI)RX"

# 2. Yetkisiz 'Everyone' Grubunu Tamamen Kaldır
icacls "C:\Program Files\VendorApp" /remove:g "Everyone" /T /C

# 3. Kritik Dosyanın Sahipliğini Administrators Grubuna Devret
takeown /f "C:\Program Files\VendorApp\service.exe" /a
icacls "C:\Program Files\VendorApp\service.exe" /setowner "BUILTIN\Administrators"

# 4. Boşluklu Servis Yollarının Kayıt Defterinde Çift Tırnaklanması
# Örnek: Get-CimInstance Win32_Service ile tırnaksız servisleri tespit edip düzeltme
Write-Host "[+] NTFS ACL Sertleştirmesi Başarıyla Tamamlandı." -ForegroundColor Green
```

---

## 5. BİR GÜVENLİK MÜHENDİSİNİN DİKKAT ETMESİ GEREKEN HUSUSLAR

1. **`C:\` Kök Dizin Tuzağı:** Windows'ta `C:\` kök dizininin varsayılan ACL'inde `BUILTIN\Users:(CI)(IO)(WD)` bulunur. Bu "Kullanıcılar kök dizine dosya oluşturamaz ama alt klasör oluşturabilir" anlamına gelir. Yanlışlıkla `(OI)` bayrağı verilirse kullanıcılar doğrudan `C:\Program.exe` bırakabilir.
2. **`CREATOR OWNER` Rolü:** Klasörlerde `CREATOR OWNER:(OI)(CI)(IO)F` kuralı varsa, o klasörde bir dosya oluşturan standart kullanıcı kendi oluşturduğu dosyanın tam denetim sahibi olur. Güvenlik araçlarının log klasörlerinde bu kural saldırganın kendi loglarını silmesine zemin hazırlayabilir.
3. **ACL Doğrulama (`icacls /verify`):** Büyük ölçekli dosya sunucularında kanonik olmayan kural sıralamaları veya bozuk SID'leri tespit etmek için periyodik olarak `icacls C:\ /verify /T` çalıştırılmalıdır.

---

## 6. ÖZET VE KAZANIMLAR

Bugünkü çalışmamızla:
- NTFS Security Descriptor, DACL ve SACL mimarisini derinlemesine kavradık.
- Windows çekirdeğinin DACL kurallarını tarama mantığını ve kanonik sıra gereksinimini öğrendik.
- Zayıf NTFS izinlerinin DLL Hijacking, servis ikilisi manipülasyonu ve yetki yükseltmeye (Privilege Escalation) nasıl yol açtığını gördük.
- `icacls` ve PowerShell ile kurumsal sistemlerde kusursuz izin şablonlarını modelledik ve test ettik.
