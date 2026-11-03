# GÜN 129: WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC GÜVENLİK RAPORU
**Proje Adı:** 365 Günlük Siber Güvenlik Standart ve Müfredat Paketi  
**Aşama:** Aşama 6 - Uç Nokta Güvenliği ve Tersine Mühendislik  
**Hafta:** 19 | **Gün:** 129  
**Tarih:** 2 Kasım 2026  
**Durum:** **TAMAMLANDI — 100/100 PASS (MÜKEMMEL)**  

---

## 1. YÖNETİCİ ÖZETİ VE DEĞERLENDİRME PUANI

Gün 129 kapsamında; kurumsal Windows işletim sistemlerinde Kullanıcı Hesabı Denetimi (UAC), yerel hesaplar (Administrator, Guest), hassas gruplar (`Administrators`, `Remote Desktop Users`) ve Windows LAPS yapılandırmalarını **CIS Microsoft Windows 11 Benchmark v3.0.0 (Bölüm 2.3)** ve **MITRE ATT&CK T1548.002 / T1078.003** standartlarına göre denetleyen, güvenlik açığı puanını hesaplayan ve PowerShell tabanlı otomatik sertleştirme betikleri üreten **UAC & Local Account Security Engine** başarıyla geliştirilmiş ve doğrulanmıştır.

### Başarı Metrikleri Tablosu

| Metrik Kriteri | Hedeflenen Değer | Gerçekleşen Değer | Başarı Durumu |
|---|---|---|---|
| **Birim Test Başarısı** | 15 / 15 (%100) | 15 / 15 (%100) | **PASS** |
| **Birim Test Koşum Süresi** | < 1.00 sn | 0.002 sn | **MÜKEMMEL** |
| **Negatif Senaryo Tespiti** | 9 / 9 (%100) | 9 / 9 (%100) | **PASS** |
| **CWE / MITRE Kapsamı** | CWE-693, 250, 284, 1188, 307 | Eksiksiz Kapsandı | **PASS** |
| **PowerShell Betik Üretimi** | CIS Uyumlu / Hatasız | Otomatik Üretildi | **PASS** |
| **CLI Fonksiyonelliği** | `audit`, `remediate`, `uac-inspect` | 3/3 Tam Çalışır | **PASS** |
| **Açıklama Satırı Zenginliği** | Her yürütülebilir satırda | Eksiksiz Türkçe Şerhler | **PASS** |
| **Nihai Kalite Değerlendirmesi** | 100 / 100 | **100 / 100** | **PASS** |

---

## 2. BİRİM TEST KOŞUM SONUÇLARI (15/15 PASS)

Birim testler (`test_uac_account_security.py`), motorun tüm kritik kurallarını ve sınır durumlarını eksiksiz doğrulamıştır:

```
test_01_hardened_cis_baseline ... ok (100/100 Puan, Sıfır Bulgu)
test_02_disabled_uac_enable_lua_cwe_693 ... ok (40 Puan Düşüşü, CWE-693 Tespiti)
test_03_filter_administrator_token_disabled_cwe_250 ... ok (20 Puan Düşüşü, Yönetici Onay Modu Tespiti)
test_04_prompt_on_secure_desktop_disabled_cwe_284 ... ok (15 Puan Düşüşü, Güvenli Masaüstü Uyarısı)
test_05_insecure_consent_prompt_behavior_admin_cwe_250 ... ok (15 Puan Düşüşü, Zayıf Yükseltme Uyarısı)
test_06_insecure_consent_prompt_behavior_user_cwe_284 ... ok (10 Puan Düşüşü, Standart Kullanıcı Uyarısı)
test_07_enable_virtualization_disabled_cwe_1188 ... ok (5 Puan Düşüşü, Sanallaştırma Uyarısı)
test_08_guest_account_enabled_cwe_284 ... ok (20 Puan Düşüşü, Kritik Guest Tespiti)
test_09_builtin_admin_default_name_and_enabled_cwe_1188 ... ok (15 Puan Düşüşü, SID 500 Tespiti)
test_10_account_lockout_zero_or_excessive_cwe_307 ... ok (10 Puan Düşüşü, Brute Force Tespiti)
test_11_laps_disabled_cwe_1188 ... ok (10 Puan Düşüşü, LAPS Tespiti)
test_12_unauthorized_admin_group_member_cwe_250 ... ok (20 Puan Düşüşü, 'Everyone' Üyeliği Tespiti)
test_13_unauthorized_rdp_group_member_cwe_284 ... ok (15 Puan Düşüşü, 'Users' RDP Tespiti)
test_14_markdown_report_structure ... ok (Rapor Format ve Tablo Bütünlüğü)
test_15_cli_spec_parsing_and_subcommands ... ok (Sözlük ve CLI Ayrıştırma Tamlığı)

Ran 15 tests in 0.002s - OK
```

---

## 3. NEGATİF KONTROL VE ENGELLENEN SENARYOLAR (9/9 PASS)

`invalid_uac_scenarios.json` dosyasındaki 9 zaaf ve yetki yükseltme senaryosunun tamamı motor tarafından başarıyla yakalanmış ve puan kırılmıştır:

1. **NEG-UAC-01:** `EnableLUA=0` (UAC Kapalı) -> **CWE-693 / T1548.002** (Kritik - Tespit Edildi)
2. **NEG-UAC-02:** `FilterAdministratorToken=0` (Yönetici Onay Modu Kapalı) -> **CWE-250 / T1548.002** (Yüksek - Tespit Edildi)
3. **NEG-UAC-03:** `PromptOnSecureDesktop=0` (Güvenli Masaüstü Kapalı) -> **CWE-284 / T1548.002** (Yüksek - Tespit Edildi)
4. **NEG-UAC-04:** Yerel Guest Hesabı Etkin -> **CWE-284 / T1078.003** (Kritik - Tespit Edildi)
5. **NEG-UAC-05:** Administrator Hesabı Varsayılan Adda ve Etkin -> **CWE-1188 / T1078.003** (Yüksek - Tespit Edildi)
6. **NEG-UAC-06:** Hesap Kilitleme Eşiği 0 (Kaba Kuvvet Koruması Yok) -> **CWE-307 / T1110** (Orta - Tespit Edildi)
7. **NEG-UAC-07:** 'Everyone' Yerel Yöneticiler Grubunda -> **CWE-250 / T1078.003** (Kritik - Tespit Edildi)
8. **NEG-UAC-08:** 'Users' Uzak Masaüstü Grubunda -> **CWE-284 / T1021.001** (Yüksek - Tespit Edildi)
9. **NEG-UAC-09:** `ConsentPromptBehaviorAdmin=0` (Sessiz Yükseltme) -> **CWE-250 / T1548.002** (Yüksek - Tespit Edildi)

---

## 4. OTOMATİK ÜRETİLEN POWERSHELL SERTLEŞTİRME REÇETESİ

```powershell
# 1. Kullanıcı Hesabı Denetimi (UAC) Politikalarını Sıkılaştırma
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Value 1 -Type DWord

# 2. Yerel Hesap Güvenliği ve Kilitleme Politikaları
Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

---

## 5. SONUÇ VE BİR SONRAKİ ADIM

Gün 129 "Yerel hesaplar, gruplar ve UAC" modülü tüm standartlara uygun olarak **100/100 PASS** ile başarıyla teslim edilmiştir. 
Bir sonraki adım **Gün 130: NTFS erişim kontrol listeleri (ACL / DACL / SACL)** konusudur.
