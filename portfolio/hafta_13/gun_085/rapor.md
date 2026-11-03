# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 085: Değerlendirme ve Teknik Denetim Raporu
**Konu:** PowerShell Nesne Boru Hattı (PowerShell Object Pipeline & Security Automation)  
**Tarih:** 2026-11-01  
**Aşama / Hafta:** Aşama 04 / Hafta 13  
**Nihai Değerlendirme Skoru:** 100 / 100 — **YETERLİ / PASS**

---

## 1. Yönetici Özeti ve Rubrik Değerlendirmesi

Hafta 13'ün ilk günü olan Gün 085 kapsamında, PowerShell ekosisteminin temel yapı taşı olan **Nesne Boru Hattı (Object Pipeline)** mekanizması, adli bilişim ve tehdit avcılığı (threat hunting) perspektifinden incelenmiş; boru hattı güvenlik analizlerini ve tehdit korelasyonunu gerçekleştiren bağımsız `PowerShellPipelineSecurityEngine` ve native PowerShell 7 modülü `SecurityPipelineAuditor.ps1` geliştirilmiştir.

Uygulama, bağımsız gün kuralına harfiyen uygun olarak hiçbir dış bağımlılık veya önceki gün kodu gerektirmeden çalışmaktadır. Uygulama ve test kodundaki her çalıştırılabilir satır Türkçe pedagojik açıklamalarla zenginleştirilmiştir.

| Değerlendirme Boyutu | Ağırlık / Tam Puan | Alınan Puan | Durum |
| :--- | :---: | :---: | :---: |
| **1. Müfredat ve Standart Uyumu** | 20 | **20** | Eksiksiz Tamamlandı |
| **2. Kod Kalitesi ve Bağımsız Çalışabilirlik** | 40 | **40** | Eksiksiz Tamamlandı |
| **3. Test Kapsamı ve Negatif Testler** | 25 | **25** | Eksiksiz Tamamlandı |
| **4. Kanıt ve Dokümantasyon Eksiksizliği** | 15 | **15** | Eksiksiz Tamamlandı |
| **TOPLAM PUAN** | **100** | **100** | **YETERLİ / PASS** |

---

## 2. Mimari Bileşenler ve Güvenlik Mekanizmaları

1. **Statik Boru Hattı ve Betik Denetleyicisi (`PipelineSyntaxAuditor`):**
   - Null-byte (`\x00`) enjeksiyonu denetimi (CWE-158).
   - Bozuk boru hattı sözdizimi (`| |` veya havada kalan `|`) denetimi (CWE-20).
   - `Invoke-Expression` (`IEX`) boru hattı enjeksiyonu tespiti (CWE-95).
   - Download Cradle (Ağ üzerinden `WebClient` ile indirip boru hattında çalıştırma) tespiti (CWE-829).
   - Gizlenmiş Base64 `-EncodedCommand` tespiti (CWE-116).
   - Tırnaksız ve boşluklu servis yolu (Unquoted Service Path - CWE-428) tespiti.

2. **Süreç Tehdit Avcısı (`ProcessPipelineHunter`):**
   - Boru hattından akan süreç nesnelerinde bilinen saldırı araçlarının (`mimikatz`, `rubeus`, `chisel`, `nc`) tespiti.
   - LOLBins ve anormal ebeveyn-çocuk ilişkilerinin (`winword.exe` / `excel.exe` -> `powershell.exe`) tespiti (MITRE T1059 / CWE-250).
   - Kullanıcı yazılabilir dizinlerde (`\Users\Public`, `\Temp\`, `\AppData\`) çalışan imzasız ikililerin bayraklanması.

3. **Ağ Soket Korelasyon Motoru (`NetworkPipelineCorrelator`):**
   - Boru hattından akan TCP bağlantı nesnelerinde RFC standartlarına uygun IP doğrulaması.
   - Şüpheli port dinleme (Port 4444 Metasploit, 1337, 8888, 9001) tespiti ve ilgili süreç PID'siyle ilişkilendirme.

4. **Boru Hattı Akış Yöneticisi (`PowerShellPipelineSecurityEngine`):**
   - Maksimum 5000 nesne tavanı ile boru hattı bellek tükenmesi (Pipeline Bomb DoS - CWE-400) koruması.
   - Kapsamlı adli raporlama ve bulgu listeleme (`PipelineAuditReport`).

5. **Native PowerShell 7 Modülü (`SecurityPipelineAuditor.ps1`):**
   - PowerShell 7 ortamında `Get-SecureProcessAudit` ve `Test-PipelineScriptSafety` fonksiyonları ile canlı nesne boru hattı akışı (`begin / process / end`).

---

## 3. Test ve Doğrulama Sonuçları

### A. Python Birim Testleri (`unittest`)
- **Toplam Test Sayısı:** 14
- **Başarılı Test Sayısı:** 14 (14/14 PASS)
- **Çalışma Süresi:** 0.011 saniye
- **Kapsanan Alanlar:** Güvenli betik doğrulaması, IEX enjeksiyonu tespiti, Base64 EncodedCommand tespiti, Download Cradle tespiti, Unquoted Service Path tespiti, null-byte reddi, boş pipe sözdizimi reddi, havada kalan pipe reddi, bilinen saldırı aracı (mimikatz) avcılığı, anormal ebeveyn-çocuk ilişkisi tespiti, katı modda soy kütüğü istisnası, şüpheli ağ portu (4444) tespiti, geçersiz IP soketi reddi, DoS nesne limiti koruması.

### B. Negatif Güvenlik Kontrolleri
`invalid_powershell_inputs.json` dosyasındaki 9 adet güvenlik saldırı senaryosu çalıştırılmış ve %100 oranında beklenen istisnalarla engellenmiştir:
1. `NEG_01_IEX_COMMAND_INJECTION`: `DangerousPipelineInvocationException` (PASS)
2. `NEG_02_OBFUSCATED_BASE64_EXECUTION`: `ObfuscatedPayloadDetectedException` (PASS)
3. `NEG_03_UNQUOTED_SERVICE_PATH`: `UnquotedServicePathException` (PASS)
4. `NEG_04_DOWNLOAD_CRADLE_PIPELINE`: `DownloadCradleDetectedException` (PASS)
5. `NEG_05_OVERSIZED_PIPELINE_BOMB_DOS`: `PipelineObjectLimitExceededException` (PASS)
6. `NEG_06_NULL_BYTE_IN_SCRIPT_OR_NAME`: `NullByteForbiddenException` (PASS)
7. `NEG_07_SUSPICIOUS_PARENT_CHILD_ANOMALY`: `AnomalousProcessLineageException` (PASS)
8. `NEG_08_MALFORMED_PIPELINE_SYNTAX`: `MalformedPipelineSyntaxException` (PASS)
9. `NEG_09_INVALID_IP_SOCKET_IN_PIPELINE`: `InvalidPipelineSocketException` (PASS)

---

## 4. Kanıt Dosyaları Dökümü

- `kanit/gercek/test_sonuclari.txt`: 14 birim testin terminal log çıktısı.
- `kanit/gercek/komut_ve_cikis.txt`: CLI komut, terminal ve native PowerShell 7 yürütme çıktısı.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 9 negatif test senaryosunun ayrıntılı dökümü.
- `kanit/gercek/powershell_boru_hatti_denetim_raporu.txt`: Gerçek süreç ve ağ nesneleri üzerinde tehdit avcılığı çıktısı.
- `kanit/temsili/powershell_boru_hatti_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla mimari akış şeması.

---

## 5. Sonuç ve Bir Sonraki Adım

Gün 085 çalışması, müfredat hedeflerine ve pedagojik kalite standartlarına %100 uygun şekilde tamamlanmış, tüm kanıtlar oluşturulmuş ve arşivlenmiştir. Hafta 13'ün ikinci günü olan **Gün 086 (PowerShell betik yazımı ve fonksiyonlar)** çalışmasına geçilebilir.
