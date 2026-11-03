# GÜN 133: Mini Proje 18 — Bütünleşik Windows Güvenlik Denetim ve Raporlama Platformu

## Usta-Çırak / Hoca Dersi: Hafta 19 Windows Güvenliği Sentezi

Evlat, Hafta 19 boyunca seninle bir Windows sisteminin en mahrem, en kritik savunma kalelerini tek tek fethettik:
- **Gün 127:** Windows Olay Günlükleri (Event Viewer / Sysmon / Audit Policies)
- **Gün 128:** Windows Güvenlik Merkezi ve Defender (RTP, ASR Kuralları, Tamper Protection, PUA)
- **Gün 129:** Yerel Hesaplar, Gruplar ve UAC (Split-Token, AdminApprovalMode, LAPS, Gizli Hesaplar)
- **Gün 130:** NTFS Erişim Kontrol Listeleri (DACL, SACL, Kalıtım Bütünlüğü, Kanonik Sıralama)
- **Gün 131:** Windows Firewall Profilleri (Domain, Private, Public, Default Inbound Block, Port İzolasyonu)
- **Gün 132:** Windows Hizmet Güvenliği (SCM, Tırnaksız Servis Yolları, Servis DACL, En Az Ayrıcalık)

Bugün, bu 6 günün tüm bilgi ve yeteneğini tek bir çatı altında birleştiren **Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Platformu**nu inşa ediyoruz. 

Bir siber güvenlik uzmanının en büyük gücü, izole bir ayara bakmak değil; uç noktanın savunma derinliğini (Defense-in-Depth) bir bütün olarak görüp tek bir skor kartına ve otomatik aksiyon planına dönüştürebilmektir.

---

### 1. Savunma Derinliği (Defense-in-Depth) Neden Tek Bir Alanla Sağlanamaz?

Evlat, saldırganlar asla senin en güçlü savunma hattına saldırmaz; en zayıf halkanı ararlar:
1. Defender'ın mükemmel çalışıyor olabilir; ama `EnableLUA=0` ise veya yöneticiler için onay istemi kapalıysa (`ConsentPromptBehaviorAdmin=0`), sıradan bir makro sessizce SYSTEM olur ve Defender'ı kayıt defterinden devre dışı bırakır.
2. UAC ve Defender sıkılaştırılmış olabilir; ancak `C:\Program Files\App` dizininde `Users` grubuna yazma yetkisi verilmişse ve o dizindeki servis tırnaksızsa (`Unquoted Service Path - CWE-428`), saldırgan araya bir `Program.exe` bırakır ve UAC'yi tamamen atlatır.
3. Servisler ve izinler kusursuz olabilir; ama Windows Firewall'un Public profilinde `3389 RDP` veya `445 SMB` açık bırakılmışsa, saldırgan kahve dükkanındaki ortak Wi-Fi üzerinden doğrudan makineye saldırır (Lateral Movement / Brute-force).

İşte bu yüzden kurumsal güvenlik denetimi **5 Bütünleşik Boyut** üzerinden yapılmalıdır.

---

### 2. Bütünleşik Denetim Modeli ve Ağırlıklandırma Mimarisi

Geliştirdiğimiz platform, sistemi 5 eşit ağırlıklı güvenlik alanına böler (Her biri 20.0 puan, Toplam 100.0 puan):

```text
+--------------------------------------------------------------------------+
|                  100.0 PUANLIK WINDOWS GÜVENLİK MODELİ                   |
+--------------------------------------------------------------------------+
|  [1] Defender ve Uç Nokta Koruması       : 20 Puan (RTP, ASR, Tamper)    |
|  [2] Yerel Hesaplar, Gruplar ve UAC      : 20 Puan (Split-Token, Admin)  |
|  [3] NTFS Erişim Kontrol Listeleri (ACL) : 20 Puan (Sistem Dizin, SACL)  |
|  [4] Windows Firewall Profilleri         : 20 Puan (Inbound Block, Port) |
|  [5] Windows Hizmet Güvenliği (SCM)      : 20 Puan (Unquoted, SDDL DACL) |
+--------------------------------------------------------------------------+
```

#### Eşik Değerleri ve Uyum Statüleri:
- **COMPLIANT (Uyumlu):** 85.0 – 100.0 Puan (Kurumsal standartlara uygun, üretime hazır).
- **WARNING (Uyarı Gerektirir):** 60.0 – 84.9 Puan (Riskli alanlar mevcut, sıkılaştırma şart).
- **CRITICAL (Kritik Tehlike):** 0.0 – 59.9 Puan (Sistem yerel veya uzaktan kolayca ele geçirilebilir).

---

### 3. Master PowerShell Sıkılaştırma Orkestrasyonu

Bir denetçi sadece "şurası bozuk" deyip kenara çekilmez. Usta denetçi, tespit ettiği her zafiyet için operasyon ekiplerinin tek tıkla çalıştırabileceği, test edilmiş ve hatasız bir **Master Sıkılaştırma Betiği (Master Remediation Script)** teslim eder.

Geliştirdiğimiz motor:
1. Tespit edilen her zafiyeti ilgili güvenlik alanına (`DEFENDER`, `UAC`, `NTFS`, `FIREWALL`, `SERVICE`) göre gruplar.
2. PowerShell komutlarını doğru sırada dizer (Önce UAC ve Defender sıkılaştırılır, ardından Güvenlik Duvarı kapatılır, en son NTFS ve Servis izinleri kilitlenir).
3. Hata toleransı (`$ErrorActionPreference = 'Continue'`) ve renkli konsol geri bildirimleriyle operasyonel şeffaflık sağlar.

---

### 4. Yönetici Seviyesi (Executive) Raporlama Sanatı

Evlat, şirket yönetim kuruluna veya CISO'ya gidip binlerce satırlık registry dökümü gösteremezsin. Onlara net bir özet lazımdır:
- Kaç puan aldık?
- Hangi alan sınıfta kaldı?
- En kritik zafiyetlerimiz neler ve bunların iş etkisi (Business Impact) nedir?

`windows_audit_platform_engine.py` motorumuz, `generate_executive_markdown_report` fonksiyonuyla hem CISO'nun okuyabileceği yönetici özet tablolarını hem de sistem yöneticisinin uygulayacağı PowerShell kod bloklarını tek bir Markdown belgesinde birleştirir.

---

### Ustanın Çırağa Öğüdü
> *"Evlat, Hafta 19'u alnının akıyla tamamladın. Windows'un kalbine indin; olay günlüklerini okudun, Defender'ı zırhladın, UAC'yi aşılamaz kıldın, NTFS izinlerini mühürledin, güvenlik duvarını ördün ve servisleri zincirledin. Şimdi bu yeteneklerini birleştirip kurumsal bir denetim platformu kurdun. Unutma: En iyi güvenlik uzmanı, sadece delikleri bulan değil; o delikleri kapatacak mimariyi de inşa edendir!"*
