# Gün 145: Group Policy Güvenlik Etkileri — Usta-Çırak Dersi

**Modül:** Hafta 21 / Gün 145 (Excel Satır 149)  
**Konu:** Active Directory Group Policy (GPO) Güvenlik Mimarisi, Miras (LSDOU), Zafiyetler ve Sertleştirme  
**Standartlar:** CIS Microsoft Windows Server Benchmark, MS14-025 (cpassword), MITRE ATT&CK T1484.001 (GPO Modification), NIST SP 800-53 AC-3 / CM-6  
**Usta:** Seydi Eryılmaz (@seydivakkas)  

---

## 1. Ustanın Giriş Dersi: "Merkezi Yönetimin İki Ucu Keskin Kılıcı: GPO"

> **Usta:** "Dinle evlat! Bir sistem yöneticisi için Group Policy (GPO), binlerce bilgisayarı tek bir tıkla yapılandırmayı sağlayan bir cennettir. Fakat bir siber güvenlik uzmanı veya saldırgan için GPO, tüm kaleyi tek bir darbeyle düşürebilecek en ölümcül silah deposudur.
>
> Bir etki alanında tek bir GPO nesnesine yazma yetkisi (WriteDacl veya GenericAll) elde eden bir saldırgan, etki alanındaki tüm sunucu ve iş istasyonlarında en yüksek ayrıcalık olan **NT AUTHORITY\SYSTEM** haklarıyla kod çalıştırabilir. Dahası, eski yöneticilerin SYSVOL içine unuttuğu bir XML dosyası (cpassword), sana tek satır kod çalıştırmadan yerel yönetici parolasını teslim edebilir.
>
> Bu derste Group Policy'nin miras çarklarını (LSDOU), Enforced ve Block Inheritance kurallarını, cpassword felaketini ve LAPS mimarisiyle Pass-the-Hash saldırılarını nasıl tamamen bitireceğimizi öğreneceksin."

---

## 2. GPO Miras Hiyerarşisi ve LSDOU Öncelik Sırası

Active Directory ortamında Group Policy ilkeleri rastgele uygulanmaz. Microsoft'un **LSDOU** kuralına göre belirli bir hiyerarşik sırayla işlenir:

```text
   [L] LOCAL POLICY  (Yerel Bilgisayar İlkesi - En düşük öncelik)
           │
           ▼
   [S] SITE POLICY   (Active Directory Site düzeyinde bağlanan GPO)
           │
           ▼
   [D] DOMAIN POLICY (Etki alanı kökü: Default Domain Policy)
           │
           +──────────────────────────────────────────+
           │                                          │
           ▼                                          ▼
   [OU-1] Workstations OU                      [OU-2] Isolated OU
   (Miras Açık: Domain + OU ilkeleri)          (Block Inheritance: AÇIK)
           │                                          │
           ├───> GPO-Enforce-Windows-LAPS             ├───> Yalnızca 'ENFORCED'
           ├───> CIS-Workstations-Baseline            │     Domain GPO'ları uygulanır!
           ▼                                          ▼
   [İş İstasyonları]                          [İzole Özel Sunucular]
```

### LSDOU Çalışma Mantığı:
1. **L (Local):** Makinenin yerel `gpedit.msc` ayarları ilk önce okunur (en zayıf).
2. **S (Site):** AD Sites and Services üzerinden bağlanan GPO'lar uygulanır.
3. **D (Domain):** Etki alanı köküne bağlanan ilkeler (örn. `Default Domain Policy`) uygulanır ve Local/Site ayarlarını ezer.
4. **OU (Organizational Unit):** Bilgisayarın veya kullanıcının bulunduğu OU'ya bağlı GPO'lar uygulanır. **En son uygulanan ilke önceki tüm ilkelerdeki çakışan ayarları ezer!**

### Kritik Miras İstisnaları:
- **Block Inheritance (Miras Engelleme):** Alt bir OU'da miras engellendiğinde, yukarıdan (Domain veya üst OU) gelen tüm GPO'lar reddedilir.
- **Enforced (Zorunlu / NoOverride):** Eğer üst seviyedeki bir GPO 'Enforced' olarak işaretlenirse, alt OU'lar 'Block Inheritance' yapmış olsa bile bu ilkeyi engellemez! Güvenlik taban çizgileri (Security Baselines) daima Enforced yapılmalıdır.

---

## 3. Tarihin En Meşhur GPO Zafiyeti: cpassword ve MS14-025

2008 yılında Microsoft, Group Policy Preferences (GPP) ile yerel kullanıcı hesapları oluşturma veya şifre değiştirme özelliğini getirdi. Bu özellik parolayı `Groups.xml` dosyasında `cpassword` adlı bir öznitelikte AES-256 ile şifreleyerek saklıyordu.

### Felaketin Sebebi:
1. `SYSVOL` paylaşımı (`\\domain.local\sysvol`), etki alanındaki **tüm kullanıcılar (Authenticated Users)** tarafından okunabilir durumdadır.
2. Microsoft, geliştirici belgelerinde (MSDN) bu AES-256 şifrelemesinde kullanılan **genel özel anahtarı (private key)** yanlışlıkla yayınlamıştır:
   `4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`
3. Sonuç: Ağdaki en düşük yetkili stajyer veya misafir kullanıcı dahi SYSVOL'deki `Groups.xml` dosyasını açıp içindeki `cpassword` değerini tek bir satır Python/PowerShell koduyla çözerek yerel yönetici parolasını elde edebilir!

**Çözüm:** MS14-025 (KB2962486) ile bu özellik devre dışı bırakılmıştır. Ancak eski etki alanlarında SYSVOL içinde geçmişten kalan XML dosyaları taranıp temizlenmeli ve ilgili parolalar derhal değiştirilmelidir.

---

## 4. GPO Yetkilendirme Suistimali (GPO Hijacking)

Active Directory nesnelerinin arkasında Discretionary Access Control List (DACL) yatar:
- Eğer bir GPO üzerinde standart bir kullanıcıya veya gruba `WriteDacl`, `WriteOwner`, `GenericAll` veya `WriteProperty` izni verilmişse;
- Saldırgan GPO nesnesinin içine zararlı bir **Immediate Scheduled Task (Anında Çalışan Zamanlanmış Görev)** veya **Startup Script** ekler.
- 90 dakika içinde (veya `gpupdate /force` ile) o GPO'nun bağlı olduğu tüm sunucular ve bilgisayarlar saldırganın komutunu `SYSTEM` yetkileriyle çalıştırır.

---

## 5. LAPS (Local Administrator Password Solution) Devrimi

Eski kurumsal ağlarda sistem yöneticileri kolaylık olsun diye 5.000 bilgisayara aynı yerel yönetici parolasını verirdi (Örn: `Sirket2024!`).
- Bir iş istasyonu phishing ile ele geçirildiğinde, saldırgan Mimikatz ile yerel yönetici hash'ini çeker.
- Bu hash ile **Pass-the-Hash (PtH)** saldırısı yaparak ağdaki diğer 4.999 bilgisayarın tamamına sıçrar!

**LAPS ve Windows LAPS Çözümü:**
- Her bilgisayar için rastgele, en az 16 karakterlik, karmaşık benzersiz bir parola üretir.
- Bu parolayı Active Directory'deki bilgisayar nesnesinin korumalı özniteliğinde (`ms-Mcs-AdmPwd`) saklar.
- Parola her 30 günde bir otomatik olarak değiştirilir.
- Saldırgan bir makinenin yerel yönetici hash'ini çalsa bile, bu hash ağdaki başka hiçbir bilgisayarda geçerli değildir!

---

## 6. Ustanın Çırağa Öğütleri

> "Çırak, kulağına küpe olsun:
> 1. **SYSVOL'ü periyodik tara:** `gpp-decrypt` gibi araçlarla SYSVOL'de cpassword arayan ilk kişi saldırgan olmasın; sen ol ve hemen temizle.
> 2. **LAPS'sız etki alanı çıplak etki alanıdır:** Her iş istasyonunda farklı parola olmadan uç nokta güvenliği sağlayamazsın. Windows LAPS'ı varsayılan yap.
> 3. **GPO izinlerini sıkı tut:** Authenticated Users grubunun GPO'lar üzerinde sadece 'Read' ve 'Apply Group Policy' hakkı olmalıdır. Asla 'Write' verme!"
