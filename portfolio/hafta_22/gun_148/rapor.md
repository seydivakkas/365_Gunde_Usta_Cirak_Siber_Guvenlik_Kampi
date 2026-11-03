# Gün 148: EDR, AV ve Telemetri — Değerlendirme Raporu

**Tarih:** 2026-11-03  
**Modül:** Hafta 22 — Gün 148 (Excel Satır 152)  
**Konu:** EDR, Antivirüs (AV), Uç Nokta Telemetrisi, Süreç Soy Ağacı ve MITRE ATT&CK Korelasyonu  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında modern uç nokta savunmasının temel direkleri olan **Geleneksel Antivirüs (AV)** imza taraması ile **Uç Nokta Tespit ve Müdahale (EDR)** davranışsal telemetri analizi, çekirdek (Kernel) olayları, süreç soy ağacı (Process Lineage) ve MITRE ATT&CK korelasyonu uçtan uca simüle edilmiş ve kurumsal standartlarda doğrulanmıştır.

Geliştirilen güvenlik ve telemetri motoru ile:
1. **Geleneksel AV Statik Taraması:** Kriptografik dosya hash eşleşmeleri (SHA-256) ve YARA benzeri içerik desen taraması (EICAR standart test imzası, Mimikatz komut kalıpları) başarıyla icra edilmiş; zararlı dosyalar otomatik karantina protokolüne sevk edilmiştir.
2. **Süreç Soy Ağacı ve LOLBAS Anomalileri:** Word uygulamasının (`WINWORD.EXE`) arka planda gizlice PowerShell veya CMD başlatması (Makro Oltalama Saldırısı - T1059.001) çekirdek telemetrisi üzerinden tespit edilmiş ve süreç sonlandırma (`KILL_PROCESS`) aksiyonu tetiklenmiştir.
3. **Bellek Enjeksiyonu ve Parola Dökümü (Credential Dumping):** `lsass.exe` sürecine yönelik yetkisiz tanıtıcı (Handle) açma ve bellek dökümü alma girişimleri (T1003.001) ile çapraz süreç iş parçacığı enjeksiyonları (`CreateRemoteThread` / `VirtualAllocEx` - T1055) anında yakalanarak uç nokta ağ izolasyonuna (`ISOLATE_HOST`) alınmıştır.
4. **Kalıcılık ve Savunma Bozma (Tampering):** Kayıt defteri otomatik başlatma anahtarlarına (`CurrentVersion\Run` - T1547.001) yazma girişimleri ve güvenlik servislerini (`WinDefend`) durdurma çabaları (T1562.001) tespit edilmiştir.
5. **Otonom Müdahale ve PowerShell Üretimi:** Zararlı süreçlerin PID listesi tekilleştirilerek `Stop-Process` komutları ve uç noktayı yerel ağdan izole eden `New-NetFirewallRule` kuralları otomatik olarak üretilmiştir.

Tüm denetim motoru harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş; 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla doğrulanmıştır.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama, didaktik yorumlar) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (MITRE ATT&CK v14, Sysmon, NIST SP 800-61, CIS Controls v8) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 148: TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.002 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/edr_telemetry_report.json
  - kanit/gercek/edr_response_remediation.ps1
  - kanit/gercek/edr_mitre_matrix.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/edr_av_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Uygulanan Çözüm / Savunma | Durum |
|---------------|-------------------|---------------------------|-------|
| **Office Makro Saldırısı** | `WINWORD.EXE` sürecinin `powershell.exe` başlatması | `EDR-RULE-001` (T1059.001) tespiti ve sürecin sonlandırılması (`KILL_PROCESS`) | Doğrulandı |
| **Kod Gizleme (Obfuscation)** | Base64 kodlu `-enc` ve `DownloadString` içeren PowerShell | `EDR-RULE-002` (T1027) tespiti ve yürütmenin durdurulması | Doğrulandı |
| **LSASS Parola Dökümü** | `procdump.exe` ile `lsass.exe` belleğine `0x1010` erişimi | `EDR-RULE-003` (T1003.001) tespiti ve uç noktanın ağdan izole edilmesi | Doğrulandı |
| **Bellek Enjeksiyonu** | Çapraz süreçte `CreateRemoteThread` kullanımı | `EDR-RULE-004` (T1055) tespiti ve enjektör sürecin öldürülmesi | Doğrulandı |
| **Kayıt Defteri Kalıcılığı** | `HKLM\...\CurrentVersion\Run` anahtarına arka kapı eklenmesi | `EDR-RULE-005` (T1547.001) tespiti ve SOC alarmı üretilmesi | Doğrulandı |
| **Komuta Kontrol (C2)** | Şüpheli harici porta (4444) yetkisiz TCP bağlantısı | `EDR-RULE-006` (T1071) tespiti ve `ISOLATE_HOST` kararı | Doğrulandı |
| **Savunma Bozma (Tampering)** | `net stop WinDefend` ile AV servisinin durdurulması | `EDR-RULE-007` (T1562.001) tespiti ve izinsiz kapatmanın engellenmesi | Doğrulandı |
| **Statik AV (EICAR)** | Test imzası içeren dosya tespiti | `AV-SIG-001` tespiti ve dosyanın karantinaya alınması | Doğrulandı |
| **Statik AV (Mimikatz)** | Bilinen parola çalma ikili deseni | `AV-SIG-002` tespiti ve dosyanın silinmesi/karantinası | Doğrulandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
