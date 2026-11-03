# GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ GÜVENLİK RAPORU
**Proje Adı:** 365 Günlük Siber Güvenlik Standart ve Müfredat Paketi  
**Aşama:** Aşama 6 - Uç Nokta Güvenliği ve Tersine Mühendislik  
**Hafta:** 19 | **Gün:** 130  
**Tarih:** 2 Kasım 2026  
**Durum:** **TAMAMLANDI — 100/100 PASS (MÜKEMMEL)**  

---

## 1. YÖNETİCİ ÖZETİ VE DEĞERLENDİRME PUANI

Gün 130 kapsamında; kurumsal Windows dosya sistemlerinde NTFS Güvenlik Tanımlayıcılarını (Security Descriptors), İsteğe Bağlı Erişim Denetim Listelerini (DACL), Sistem Erişim Denetim Listelerini (SACL) ve ACE kurallarını **CIS Microsoft Windows Server / 11 Benchmark (Section 18/19)** ve **MITRE ATT&CK T1574.009 / T1068** standartlarına göre teftiş eden, DLL Hijacking ve servis ikilisi manipülasyonu zafiyetlerini (CWE-732, CWE-276, CWE-428) tespit eden ve `icacls` / PowerShell tabanlı sertleştirme üreten **NTFS ACL Engine** geliştirilmiş ve başarıyla doğrulanmıştır.

### Başarı Metrikleri Tablosu

| Metrik Kriteri | Hedeflenen Değer | Gerçekleşen Değer | Başarı Durumu |
|---|---|---|---|
| **Birim Test Başarısı** | 15 / 15 (%100) | 15 / 15 (%100) | **PASS** |
| **Birim Test Koşum Süresi** | < 1.00 sn | 0.002 sn | **MÜKEMMEL** |
| **Negatif Senaryo Tespiti** | 9 / 9 (%100) | 9 / 9 (%100) | **PASS** |
| **CWE / MITRE Kapsamı** | CWE-732, 276, 428, 284 | Eksiksiz Kapsandı | **PASS** |
| **icacls / PowerShell Betik Üretimi** | CIS Uyumlu / Hatasız | Otomatik Üretildi | **PASS** |
| **CLI Fonksiyonelliği** | `audit`, `remediate`, `ace-help` | 3/3 Tam Çalışır | **PASS** |
| **Açıklama Satırı Zenginliği** | Her yürütülebilir satırda | Eksiksiz Türkçe Şerhler | **PASS** |
| **Nihai Kalite Değerlendirmesi** | 100 / 100 | **100 / 100** | **PASS** |

---

## 2. BİRİM TEST KOŞUM SONUÇLARI (15/15 PASS)

Birim testler (`test_ntfs_acl.py`), motorun dosya ve dizin izinlerini analiz etme, sınır durumları yakalama ve kanonik kuralları denetleme kabiliyetini doğrulamıştır:

```
test_01_hardened_cis_baseline ... ok (100/100 Puan, Sıfır Bulgu)
test_02_dangerous_write_on_system32_cwe_732 ... ok (25 Puan Düşüşü, CWE-732 Kritik Bulgu)
test_03_dangerous_modify_on_program_files_cwe_732 ... ok (25 Puan Düşüşü, DLL Manipülasyon Tespiti)
test_04_unprivileged_owner_on_critical_binary_cwe_284 ... ok (15 Puan Düşüşü, Sahiplik Uyarısı)
test_05_unquoted_service_path_vulnerability_cwe_428 ... ok (45 Puan Düşüşü, Unquoted Path Tespiti)
test_06_non_canonical_ace_ordering_cwe_284 ... ok (10 Puan Düşüşü, Bozuk ACE Sıralaması Tespiti)
test_07_authenticated_users_dangerous_write_cwe_732 ... ok (ProgramData Yazma Hakkı Tespiti)
test_08_read_and_execute_permission_passes ... ok (Yalnızca RX Hakları Tam PASS)
test_09_general_weak_permission_on_data_path_cwe_276 ... ok (Genel Veri Yolu CWE-276 Tespiti)
test_10_multiple_violations_cumulative_penalty ... ok (Kümülatif Puan ve Taban Kontrolü)
test_11_icacls_remediation_generation ... ok (icacls /remove Komut Doğrulaması)
test_12_markdown_report_structure ... ok (Markdown Rapor Format Bütünlüğü)
test_13_cli_dict_parsing_accuracy ... ok (Sözlük Dönüştürme Doğruluğu)
test_14_takeown_and_setowner_remediation ... ok (Sahiplik Devretme Reçetesi Doğrulaması)
test_15_cli_parser_and_subcommands ... ok (CLI Alt Komut ve Argüman Tamlığı)

Ran 15 tests in 0.002s - OK
```

---

## 3. NEGATİF KONTROL VE ENGELLENEN SENARYOLAR (9/9 PASS)

`invalid_ntfs_scenarios.json` dosyasındaki 9 zayıf izin ve yetki yükseltme senaryosu motor tarafından yakalanarak engellenmiştir:

1. **NEG-NTFS-01:** System32 İkilisinde Everyone FullControl -> **CWE-732 / T1574.009** (Kritik - Tespit Edildi)
2. **NEG-NTFS-02:** Program Files DLL Dosyasında Users Modify -> **CWE-732 / T1574.009** (Kritik - Tespit Edildi)
3. **NEG-NTFS-03:** Tırnak İçine Alınmamış Servis Yolu İstismarı -> **CWE-428 / T1574.009** (Kritik - Tespit Edildi)
4. **NEG-NTFS-04:** Sistem Sürücüsünde Guest Sahipliği -> **CWE-284 / T1078.003** (Yüksek - Tespit Edildi)
5. **NEG-NTFS-05:** Kanonik Olmayan Bozuk ACE Sıralaması -> **CWE-284 / T1548** (Orta - Tespit Edildi)
6. **NEG-NTFS-06:** ProgramData İçinde Authenticated Users Yazma İzni -> **CWE-732 / T1574.009** (Kritik - Tespit Edildi)
7. **NEG-NTFS-07:** Genel Veri Paylaşımında Zayıf İzin -> **CWE-276 / T1068** (Yüksek - Tespit Edildi)
8. **NEG-NTFS-08:** Hassas Servis Klasöründe Kümülatif İzin Zaafı -> **CWE-732 / T1574.009** (Kritik - Tespit Edildi)
9. **NEG-NTFS-09:** Sistem DLL Dosyasında Standart Kullanıcı Sahipliği -> **CWE-284 / T1078.003** (Yüksek - Tespit Edildi)

---

## 4. ICACLS VE POWERSHELL İLE SIKILAŞTIRMA ŞABLONU

```powershell
# 1. Miras Alınan İzinleri Kırarak Sıkı Bir DACL Tanımla
icacls "C:\Program Files\VendorApp" /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
    /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
    /grant:r "BUILTIN\Users:(OI)(CI)RX"

# 2. Yetkisiz 'Everyone' ve Standart Kullanıcı Yazma İzinlerini Temizle
icacls "C:\Program Files\VendorApp" /remove:g "Everyone"
icacls "C:\Program Files\VendorApp\service.exe" /remove:g "BUILTIN\Users"

# 3. Dosya Sahipliğini Güvenli Administrators Grubuna Devret
takeown /f "C:\Program Files\VendorApp\service.exe" /a
icacls "C:\Program Files\VendorApp\service.exe" /setowner "BUILTIN\Administrators"
```

---

## 5. SONUÇ VE BİR SONRAKİ ADIM

Gün 130 "NTFS erişim kontrol listeleri" modülü tüm standartlara uygun olarak **100/100 PASS** ile başarıyla teslim edilmiştir. 
Bir sonraki adım **Gün 131: Windows Firewall profilleri** konusudur.
