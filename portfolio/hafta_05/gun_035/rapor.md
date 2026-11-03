# GÜN 35: MİNİ PROJE 4: SİSTEM DURUM KONTROLÜ — TEKNİK RAPOR VE DEĞERLENDİRME

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu rapor ve değerlendirme içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## 1. GÖREV VE PEDAGOJİK HEDEF ÖZETİ
- **Gün:** 35 (G035) | **Hafta:** 05 | **Aşama:** 02 (Sistem ve Ağ Güvenliği Temelleri)
- **Konu:** Mini proje 4: sistem durum kontrolü (MP-04 - System Posture Auditor)
- **Standart Kaynak:** `standart_gun.md §3–12`
- **Resmî Kaynak:** [Microsoft Learn: Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- **Öğrenme Çıktısı:**
  1. Hafta 05 boyunca işlenen süreç ağaçları, servis yapılandırmaları, dosya bütünlüğü (FIM) ve sihirli bayt (magic bytes) denetimlerini tek bir konsolide analiz çatısında birleştirme.
  2. G035-SC1 ilkesi gereğince sistem durum taramasının yalnızca gözlemlerden anlamlı özet üretmesini ve yönetimsel ayrıcalık gerektirmemesini sağlama (Salt-Okunur Gözlemci Modeli).
  3. Süreç zinciri anormalliklerini (`winword.exe` -> `powershell.exe`), servis tahrifatını (`MpsSvc` durdurulması), unquoted service path zafiyetini, FIM hash uyuşmazlığını ve uzantı aldatmacasını (Extension Spoofing) tespit edebilme.
  4. 100 üzerinden ağırlıklı Sağlık Puanı (Health Score) ve Yönetici Durum Panosu (Executive Dashboard) üretebilme.

---

## 2. DÖRT BİLEŞENLİ DEĞERLENDİRME RUBRİĞİ (100 / 100)

| Rubrik Kriteri | Taban Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 0 – 20 | **20** | `soru_cevap.md` içinde G035-SC1..3 ve haftalık W05-SC1..3 soruları tam teknik derinlikle, 4 zorunlu alt başlık eksiksiz uygulanarak hazırlanmıştır. |
| **Gerçek Uygulama / Simülasyon** | 0 – 40 | **40** | `system_posture_auditor.py` aracı bağımsız ve sıfırdan geliştirilmiştir. Çalıştırılabilir her bir kod satırı didaktik açıklamalarla zenginleştirilmiş; 4 alt denetim modülü, sağlık puanlama motoru ve yönetici panosu eksiksiz kodlanmıştır. |
| **Doğrulanabilir Kanıt** | 0 – 25 | **25** | `kanit/gercek/` altında 14/14 birim test çıktısı (`test_sonuclari.txt`), CLI yürütme dökümü (`komut_ve_cikis.txt`), ASCII yönetici panosu (`sistem_durum_panosu_raporu.txt`) ve bozuk veri reddini belgeleyen `negatif_kontrol_sonuclari.txt` doğrulanmıştır. `kanit/temsili/` altında etiketli mimari şema yer almaktadır. |
| **Teknik Raporlama** | 0 – 15 | **15** | Rapor; çok boyutlu denetim bulgularını, MITRE ATT&CK eşleşmelerini ve kurumsal savunma önlemlerini net bir şekilde ortaya koymaktadır. |
| **TOPLAM PUAN** | **100** | **100** | **SONUÇ: YETERLİ / PASS (TAM BAŞARI)** |

---

## 3. LABORATUVAR VE KONSOLİDE DURUM BULGULARI ÖZETİ

`system_telemetry_snapshot.json` anlık görüntüsü incelenmiş ve aşağıdaki çok katmanlı tehditler tespit edilmiştir:

1. **Süreç Hiyerarşisi Alanı (Process Domain) — CRITICAL:**
   - **Hedef:** PID 8820 (`powershell.exe`) | Ebeveyn: PID 8810 (`winword.exe`)
   - **Zafiyet:** `MALICIOUS_OFFICE_SPAWN` (T1059.001 / T1204.002) — Word makrosu gizli ve bypass parametreli PowerShell yürütmektedir.
   - **Hedef:** PID 9900 (`svch0st.exe`) | Konum: `C:\Windows\Temp\`
   - **Zafiyet:** `PROCESS_MASQUERADING` (T1036) — Meşru svchost adını taklit eden zararlı arka kapı.
2. **Servis Güvenliği Alanı (Service Domain) — CRITICAL & HIGH:**
   - **Hedef:** `MpsSvc` (Windows Defender Firewall) -> Durum: `Stopped` / `Disabled` (`SECURITY_SERVICE_TAMPERED` - CRITICAL - T1562.001).
   - **Hedef:** `CloudBackupSvc` -> Yol: `C:\Program Files\Enterprise Cloud Backup\agent.exe` (`UNQUOTED_SERVICE_PATH` - HIGH - T1574.009).
3. **Dosya Bütünlüğü Alanı (FIM Domain) — CRITICAL & HIGH:**
   - **Hedef:** `C:\ProgramData\App\security_policy.cfg` -> Durum: `MISMATCH` (`INTEGRITY_VIOLATION` - CRITICAL - T1565.001).
   - **Hedef:** `missing_baseline_file.bin` -> Durum: `MISSING` (`BASELINE_DISRUPTION` - HIGH - T1485).
4. **Dosya İmzası ve Sihirli Bayt Alanı (Signature Domain) — CRITICAL & HIGH:**
   - **Hedef:** `invoice_receipt.pdf` -> İddia: `.pdf` | Gerçek Başlık: `4D 5A` (MZ PE Executable) (`EXTENSION_SPOOFING` - CRITICAL - T1036.008).
   - **Hedef:** `statement.pdf.exe` -> Çift uzantılı Truva Atı (`DOUBLE_EXTENSION_TROJAN` - HIGH - T1036.007).

**Sistem Sağlık Puanı:** `0 / 100` (COMPROMISED_ENVIRONMENT)
Ağır ve çoklu ihlaller nedeniyle sistem duruşu acil izolasyon seviyesindedir.

---

## 4. NEGATİF KONTROL VE HATA DAYANIKLILIĞI

`corrupted_telemetry_test_cases.json` dosyasındaki 5 bozuk test senaryosu (eksik bölümler, geçersiz veri tipleri, liste olmayan alanlar ve null girdiler) `validate_telemetry_schema` fonksiyonu tarafından başarıyla yakalanmış, sistem çökmemiş ve tüm hatalar `corrupted_records` listesine kaydedilmiştir. 14 birim testin tamamı 0.039 saniyede hatasız geçmiştir.

---

## 5. HAFTA 05 GENEL DEĞERLENDİRMESİ VE BİR SONRAKİ ADIM
Hafta 05 (Aşama 02: Sistem ve Ağ Güvenliği Temelleri); Gün 29'dan Gün 35'e kadar olan 7 günlük maratonla, Usta-Çırak pedagojisine tam uyumla, her satırı açıklamalı kodlar ve eksiksiz kanıtlarla %100 PASS olarak başarıyla tamamlanmıştır.

- **Tamamlanan Hafta:** Hafta 05 (Mini Proje 4 ile başarıyla kapandı)
- **Sonraki Gün:** Gün 36 (Hafta 06 Başlangıcı - Aşama 02 Devamı)
- **Hazırlık:** Gün 35'in yedeklenmesi, manifest dosyasının üretilmesi ve Excel çizelgesinin güncellenmesi.
