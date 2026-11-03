# Gün 127: Uç Nokta Tehdit Modeli (Endpoint Threat Model)

> **Usta-Çırak / Hoca Dersi: Hafta 19 & Aşama 6 Başlangıcı — Uç Nokta Savunması**  
> *"Evlat; kriptografiyle kapıyı kilitledin, mimariyle surları ördün. Ama unutma ki bir kurumun en savunmasız, en çok kurcalanan ve saldırganların en sevdiği cephesi son kullanıcının elindeki bilgisayardır: Uç Nokta (Endpoint)! Saldırgan kapıdan giremezse bir çalışanın dikkatsizce açtığı oltalama e-postasından, güvensiz bir USB bellekten veya internete açık unutulmuş bir RDP portundan içeri sızar. Bugün uç noktanın kalbine iniyoruz; saldırganın gözüyle işletim sisteminin röntgenini çekip her bir tehdidi MITRE ATT&CK matrisine bağlayacağız."*

---

## 1. Giriş ve Büyük Resim: Aşama 6 (Uç Nokta Güvenliği) Vizyonu

Aşama 6 boyunca (Hafta 19 ve sonrası), siber güvenlik operasyonlarının en sıcak savaş alanına adım atıyoruz: **Uç Nokta Güvenliği ve Sertleştirme (Endpoint Security & Hardening)**.

Bir uç nokta (Workstation, Sunucu, Domain Controller); donanım, bellenim (UEFI/BIOS), işletim sistemi çekirdeği (Kernel), sistem servisleri, kullanıcı oturumları ve çalışan uygulamalardan oluşan çok katmanlı karmaşık bir yapıdır. Saldırgan bu katmanlardan herhangi birinde bulduğu en ufak bir yapılandırma hatasını basamak (Pivot) olarak kullanarak tüm kurumsal ağı ele geçirebilir.

```
+-----------------------------------------------------------------------------------+
|               UÇ NOKTA SALDIRI ZİNCİRİ (ENDPOINT KILL CHAIN)                      |
+-----------------------------------------------------------------------------------+
| 1. İlk Erişim (Initial Access)   --> Phishing, Drive-by, RDP Açıklığı            |
| 2. Çalıştırma (Execution)        --> LOLBins (PowerShell, Certutil, MSHTA)       |
| 3. Kalıcılık (Persistence)       --> Registry Run Keys, Scheduled Tasks, Systemd |
| 4. Yetki Yükseltme (PrivEsc)     --> Unquoted Path (CWE-428), SUID (CWE-250)     |
| 5. Savunma Atlatma (Evasion)     --> EDR Kapatma, Tamper, Log Temizleme (CWE-693)|
| 6. Kimlik Hırsızlığı (CredDump)  --> LSASS Dump (CWE-311 / T1003.001)            |
| 7. Yanal Hareket (Lateral Mvt)   --> Pass-the-Hash, SMB/WMI, SSH Pivoting        |
+-----------------------------------------------------------------------------------+
```

---

## 2. Uç Nokta Saldırı Yüzeyleri ve Tehdit Vektörleri

### 2.1. Kimlik Bilgisi Güvenliği ve LSASS Koruması (CWE-311 / MITRE T1003.001)
Windows işletim sistemlerinde `lsass.exe` (Local Security Authority Subsystem Service), kullanıcıların oturum açma biletlerini (Kerberos TGT), NTLM özetlerini ve düz metin parolalarını bellekte tutar.
- **Tehdit:** Yerel yönetici haklarına sahip bir saldırgan veya zararlı yazılım `ProcessDump` (veya Mimikatz) kullanarak LSASS belleğini diske kopyalar ve kimlik bilgilerini çalar.
- **Savunma:**
  1. **RunAsPPL (Protected Process Light):** LSASS sürecini korumalı moda geçirir (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL=1`).
  2. **Credential Guard:** Donanım sanallaştırması (VBS - Virtualization Based Security) kullanarak kimlik sırlarını sanal bir izole ortamda (VSM) saklar. Yönetici dahi olsa bellekten sır okunamaz.

### 2.2. Servis Yolları ve Yetki Yükseltme (CWE-428 / MITRE T1574.009)
Windows'ta bir servis başlatılırken servis ikili dosya yolu tırnak işareti içine alınmamışsa ve yol boşluk içeriyorsa:
- Örnek: `C:\Program Files\My Application\service.exe`
- Windows yolu şu sırayla dener:
  1. `C:\Program.exe`
  2. `C:\Program Files\My.exe`
  3. `C:\Program Files\My Application\service.exe`
- **Tehdit:** `C:\` kök dizinine yazma izni olan bir standart kullanıcı `Program.exe` adında bir zararlı koyarsa, sistem yeniden başladığında bu zararlı `NT AUTHORITY\SYSTEM` yetkisiyle çalışır.
- **Savunma:** Tüm servis yollarının çift tırnak (`"C:\Program Files\..."`) ile sarılması zorunludur.

### 2.3. Linux SUID / SGID Zafiyetleri (CWE-250 / MITRE T1548.001)
Linux'ta bir dosyada `SUID` biti (`chmod u+s`) varsa, o dosya kim çalıştırırsa çalıştırsın dosya sahibinin (genellikle `root`) yetkileriyle çalışır.
- **Tehdit:** Eğer `vim`, `find`, `bash`, `nmap` veya `python` gibi kabuk açabilen ikililere yanlışlıkla SUID biti verilmişse, düşük yetkili saldırgan GTFOBins yöntemleriyle tek bir komutla root kabuğu elde eder.
- **Savunma:** Sistemdeki tüm SUID dosyaları düzenli taranmalı (`find / -perm -4000 2>/dev/null`), standart dışı olanlardan SUID biti kaldırılmalıdır.

### 2.4. Uç Nokta Telemetrisi ve Kurcalama Koruması (CWE-693 / MITRE T1562.001)
Bir EDR (Endpoint Detection & Response) ajanının kurulu olması tek başına yeterli değildir:
1. **Tamper Protection (Kurcalama Koruması):** Açık değilse, saldırgan yerel admin olduğunda `sc stop EDRService` komutuyla veya kayıt defterinden servisi devre dışı bırakır.
2. **Derin Telemetri (Sysmon / Auditd):** Windows Olay Günlükleri (Event Viewer) varsayılan olarak süreç komut satırı argümanlarını veya ağ bağlantılarını loglamaz. Sysmon (Event ID 1, 3, 7, 10, 11) veya Linux `auditd` kural seti ile her bir süreç oluşturma adımı kayıt altına alınmalıdır.

---

## 3. Uç Nokta Tehdit Modelleme Metodolojisi

Bir uç noktanın tehdit modelini çıkarırken 4 temel adımı işletiriz:
1. **Varlık ve Rol Tanımlama:** Cihaz bir son kullanıcı laptopu mu, veritabanı mı, yoksa Active Directory Domain Controller mı? (Rol çarpanı: DC için 1.5x, DB için 1.3x).
2. **Saldırı Yüzeyi Taraması:** Kimlik belleği, servisler, kayıt defteri autorunları, açık portlar, betik kısıtlamaları (PowerShell CLM) ve EDR durumu denetlenir.
3. **CWE ve MITRE Eşleştirmesi:** Tespit edilen her zafiyet standart taksonomiye bağlanır.
4. **Tehdit Endeksi ve Sıkılaştırma Planı:** 0-100 ölçeğinde risk skoru hesaplanır; CIS Benchmark kurallarıyla önceliklendirilmiş düzeltme yol haritası sunulur.

---

## 4. Çırağa Usta Öğüdü

Evlat! Uç nokta güvenliğinde "varsayılan ayar" senin en büyük düşmanındır:
1. Microsoft Windows veya Linux kutudan çıktığı haliyle güvenli değildir; o genel kullanım için yapılandırılmıştır, yüksek güvenlik için değil.
2. Servis yollarındaki tırnak işaretini küçümseme; 20 yıllık tırnaksız servis zafiyetiyle bugün hala dünyanın en büyük kurumları hackleniyor.
3. LSA Korumasını aç, BitLocker'ı zorunlu kıl, PowerShell'i CLM moduna al ve telemetriyi açık tut. Uç noktayı saldırgan için cehenneme çevir ki, içeri girmeye çalışan kapıda takılsın!
