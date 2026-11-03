# Hafta 05 — Gün 029: Windows Event Viewer'a Giriş ve Adli Günlük Mimarisi

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## 1. Giriş ve Felsefi Temel

### Usta ile Çırak Arasında Bir Mavi Takım Diyaloğu
*Çırak:* "Ustam, geçen hafta işletim sisteminin komut satırını, izinlerini ve süreçlerini inceledik. Bir analist sunucuya girdiğinde o anda olup biteni görebiliyor. Peki ama ya dün gece sisteme sızan bir saldırgan bugün sunucuda hiçbir işlem yapmıyorsa? Ya da bir servis arka planda sessizce kurulup çekildiyse? Geçmişi nasıl göreceğiz?"

*Usta:* "Evlat, işletim sistemleri yaşayan organizmalar gibidir; attıkları her adımı, aldıkları her nefesi bir hafızaya kaydederler. Bu hafızanın adı Windows dünyasında **Windows Olay Günlükleridir (Windows Event Logs)**. Siber güvenlikte temel bir aforizma vardır: **'Kayıt altına alınmayan bir ihlal, hiç yaşanmamış sayılır.'**"

"Fakat çırak, acemi analistlerin düştüğü en büyük tuzak şudur: Ekranda kırmızı bir alarm veya başarısız bir oturum açma (Event 4625) gördüklerinde hemen 'Sistem hacklendi!' diye bağırırlar. Oysa tek bir olay kimliği, arkasındaki bağlam (context) bilinmeden hiçbir şey ifade etmez! Belki kullanıcının klavyesinde Caps Lock açık kalmıştır; belki de bir parola püskürtme (password spraying) saldırısı yapılıyordur. Bugün 5. Haftaya adım atarken Windows'un adli kayıt mimarisini, kanallarını ve en önemlisi **bağlamsal korelasyon sanatını** öğreneceksin!"

---

## 2. Windows Olay Günlüğü Anatomisi ve EVTX Mimarisi

Modern Windows işletim sistemlerinde olaylar, ikili (binary) XML formatında saklanan `.evtx` dosyalarında tutulur. Bu mimarinin arkasında yüksek performanslı **Event Tracing for Windows (ETW)** motoru yer alır.

```
+-------------------------------------------------------------------+
|               WINDOWS OLAY GÜNLÜĞÜ KANALLARI (CHANNELS)            |
+---------------------------------+---------------------------------+
| 1. Security.evtx                | Güvenlik denetimi (SACL),       |
|    (%SystemRoot%\System32\Winevt\Logs) | oturumlar, yetki kullanımı.   |
+---------------------------------+---------------------------------+
| 2. System.evtx                  | Aygıt sürücüleri, çekirdek,     |
|                                 | donanım ve Windows servisleri.  |
+---------------------------------+---------------------------------+
| 3. Application.evtx             | Üçüncü taraf yazılımlar, SQL,   |
|                                 | web sunucuları ve hata logları. |
+---------------------------------+---------------------------------+
| 4. Setup.evtx                   | İşletim sistemi ve güncelleme   |
|                                 | kurulum kayıtları.              |
+---------------------------------+---------------------------------+
```

### Standart Bir Olay Kaydının Zorunlu Alanları (EVTX / XML):
- **ProviderName (Sağlayıcı Adı):** Olayı üreten sistem bileşeni veya sürücü (örn: `Service Control Manager`, `USER32`, `EventLog`).
- **EventID (Olay Kimliği):** Olayın türünü belirten benzersiz sayısal kod (örn: `7045`, `4624`, `1074`).
- **TimeCreated (Zaman Damgası):** Olayın gerçekleştiği kesin an (milisaniye hassasiyetinde ISO 8601 UTC).
- **Level (Önem Düzeyi):** Kritik (1), Hata (2), Uyarı (3), Bilgi (4), Ayrıntılı (5).
- **RecordId (Kayıt Numarası):** Günlük kanalı içinde sıralı, değiştirilemez sıra numarası. Adli incelemede log silinmesi veya aradaki kayıtların eksilmesini tespit etmek için kullanılır.
- **EventData (Olay Yükü):** Olay türüne özel parametreler (ServiceName, ImagePath, TargetUserName, IpAddress vb.).

---

## 3. Bağlamsal Korelasyon İlkesi (G029-SC1)

> **Altın Kural (G029-SC1):**  
> *"Tek bir olay kimliği, bağlam olmadan saldırı kanıtı değildir."*

Bir güvenlik analisti tek bir log satırına bakarak karar veremez. Olayı çevreleyen parametreler incelenmelidir:

```
[Olay Kimliği: 4625] (Başarısız Oturum Açma)
         |
         +--> [Senaryo A: Günde 1-2 kez, aynı kullanıcı, mesai saati]
         |    ==> Karar: NORMAL (Kullanıcı parola yazım hatası)
         |
         +--> [Senaryo B: 5 dakikada 500 kez, farklı kullanıcı adları (admin, root, test)]
              ==> Karar: SALDIRI (Kaba Kuvvet / Parola Püskürtme - T1110)
```

Benzer şekilde **Event 7045 (Yeni Servis Kurulumu)** meşru bir Windows güncellemesi veya antivirüs kurulumu olabileceği gibi, saldırganın `C:\Users\...\AppData\Local\Temp\` altından çalıştırdığı bir arka kapı (backdoor) da olabilir! Bu nedenle dosya yolu (`ImagePath`), başlatan kullanıcı (`AccountName`) ve başlatma türü (`StartType`) birlikte incelenmelidir.

---

## 4. Üç Temel Sistem Olayının Derinlemesine İncelenmesi (G029-SC2)

Laboratuvarımızda gizli veri içermeyen 3 temel sistem olayı alanlarıyla analiz edilmiştir:

### 1. Event ID 6005 (Olay Günlüğü Servisi Başlatıldı)
- **Sağlayıcı:** `EventLog`
- **Kanal:** `System`
- **Anlamı:** İşletim sistemi önyüklenmiş ve olay günlüğü servisi faaliyete geçmiştir.
- **Adli Önemi:** Sistemin açılış anını (boot timeline) kesinleştirir. Event 6006 (servis durduruldu) kaydıyla eşleştirilerek sistemin kapalı kaldığı aralık ve beklenmeyen çökmeler (BSOD) tespit edilir.

### 2. Event ID 7045 (Sistemde Yeni Bir Servis Kuruldu)
- **Sağlayıcı:** `Service Control Manager (SCM)`
- **Kanal:** `System`
- **Adli Alanlar:** `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `AccountName`.
- **Tehdit Modeli:** MITRE ATT&CK **T1543.003 (Create or Modify System Process: Windows Service)**. Saldırganların en sık başvurduğu kalıcılık (persistence) ve `SYSTEM` yetkisine yükselme yöntemidir.

### 3. Event ID 1074 (Sistem Kapatma veya Yeniden Başlatma)
- **Sağlayıcı:** `USER32`
- **Kanal:** `System`
- **Adli Alanlar:** `ProcessName`, `Reason`, `ReasonCode`, `ShutdownType`, `InitiatingUser`.
- **Tehdit Modeli:** MITRE ATT&CK **T1529 (System Shutdown/Reboot)**. Sistemin yetkili bir kullanıcı tarafından mı, yoksa fidye yazılımı (ransomware) veya kötücül bir betik tarafından mı kapatıldığını kanıtlar.

---

## 5. Güvenlik Günlüğü Riskleri, İz Silme ve Tehdit Senaryoları (G029-SC3)

1. **İz Silme ve Günlük Temizleme (Event ID 1102 / 104):**
   - Saldırgan sisteme sızdıktan sonra arkasında iz bırakmamak için `wevtutil cl Security` komutunu çalıştırabilir.
   - Bu durum güvenlik günlüğüne **Event 1102 (The audit log was cleared)** olarak düşer. Bu olay tek başına istisnasız **Kritik İhlal (Defense Evasion - T1070.001)** sayılır.
2. **Yetersiz Denetim Politikası (CWE-778 - Insufficient Logging):**
   - Varsayılan Windows kurulumunda süreç oluşturma (Process Creation - 4688) ve komut satırı argümanı kaydetme kapalıdır. Bu durum gelişmiş saldırıların loglara yansımasını engeller.
3. **Log Enjeksiyonu ve Manipülasyonu (CWE-117):**
   - Uygulama loglarına kaçış karakterleri (`\r\n`) eklenerek sahte log satırları basılabilir.

---

## 6. Geliştirilen Analiz Motorunun Satır Satır Mimarisi

`windows_event_viewer_analyzer.py` aracımız şu modüler bileşenlerden oluşur:
- **`WindowsEventValidator`:** Gelen kaydın `provider_name`, `event_id`, `time_created`, `channel` ve `computer` alanlarını denetler. Hatalı olanları reddederek negatif kontrol sağlar (G029-SC2).
- **`ContextualCorrelationEngine`:** Olayı EventID, dosya yolu ve kullanıcı bağlamında değerlendirir; MITRE ATT&CK tekniğini ve risk derecesini belirler.
- **`SHA-256 Mühürleme`:** Her olayın adli bütünlüğü için benzersiz 64 karakterlik kriptografik hash üretilir.

---

## 7. Çırağa Tavsiyeler, Mavi Takım Kontrolleri ve Gelecek Güne Köprü

1. **Merkezi Loglama Zorunludur (WEC / WEF):** Loglar yalnızca yerel makinede tutulursa, makineyi ele geçiren saldırgan logları da imha edebilir. Loglar derhal merkezi bir SIEM sistemine (Splunk, Elastic, Microsoft Sentinel) aktarılmalıdır.
2. **Sysmon Gücü:** Standart Windows loglarının yetersiz kaldığı yerlerde Microsoft Sysmon (System Monitor) kurularak ağ bağlantıları, DLL yüklemeleri ve bellek enjeksiyonları izlenmelidir.
3. **Gelecek Güne Köprü (Gün 030):** Yarın, Windows Olay Günlüklerinin en büyük veri kaynağı olan ve sistemin kalbi sayılan **Windows Registry (Kayıt Defteri) Güvenliği ve Analizine** geçiş yapacağız!
