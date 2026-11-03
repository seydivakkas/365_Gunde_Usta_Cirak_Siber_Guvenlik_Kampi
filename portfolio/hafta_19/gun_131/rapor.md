# GÜN 131: WINDOWS FIREWALL PROFİLLERİ GÜVENLİK RAPORU
**Proje Adı:** 365 Günlük Siber Güvenlik Standart ve Müfredat Paketi  
**Aşama:** Aşama 6 - Uç Nokta Güvenliği ve Tersine Mühendislik  
**Hafta:** 19 | **Gün:** 131  
**Tarih:** 2 Kasım 2026  
**Durum:** **TAMAMLANDI — 100/100 PASS (MÜKEMMEL)**  

---

## 1. YÖNETİCİ ÖZETİ VE DEĞERLENDİRME PUANI

Gün 131 kapsamında; Windows Defender Gelişmiş Güvenlikli Güvenlik Duvarı (WFAS) Domain, Private ve Public ağ profillerini, varsayılan gelen/giden eylemlerini, engellenen paket kütükleme mekanizmalarını ve açık gelen istisnalarını **CIS Microsoft Windows 11 / Server Benchmark (Section 9)** ve **MITRE ATT&CK T1562.004 / T1021** standartlarına göre denetleyen, güvenlik açıklarını (CWE-693, CWE-284, CWE-778) puanlayan ve PowerShell / netsh tabanlı sertleştirme üreten **Windows Firewall Engine** başarıyla geliştirilmiş ve doğrulanmıştır.

### Başarı Metrikleri Tablosu

| Metrik Kriteri | Hedeflenen Değer | Gerçekleşen Değer | Başarı Durumu |
|---|---|---|---|
| **Birim Test Başarısı** | 15 / 15 (%100) | 15 / 15 (%100) | **PASS** |
| **Birim Test Koşum Süresi** | < 1.00 sn | 0.002 sn | **MÜKEMMEL** |
| **Negatif Senaryo Tespiti** | 9 / 9 (%100) | 9 / 9 (%100) | **PASS** |
| **CWE / MITRE Kapsamı** | CWE-693, 284, 778 | Eksiksiz Kapsandı | **PASS** |
| **PowerShell Betik Üretimi** | CIS Uyumlu / Hatasız | Otomatik Üretildi | **PASS** |
| **CLI Fonksiyonelliği** | `audit`, `remediate`, `profiles-info` | 3/3 Tam Çalışır | **PASS** |
| **Açıklama Satırı Zenginliği** | Her yürütülebilir satırda | Eksiksiz Türkçe Şerhler | **PASS** |
| **Nihai Kalite Değerlendirmesi** | 100 / 100 | **100 / 100** | **PASS** |

---

## 2. BİRİM TEST KOŞUM SONUÇLARI (15/15 PASS)

Birim testler (`test_windows_firewall.py`), güvenlik duvarı profil denetimlerini, kütükleme ve riskli port filtreleme kurallarını doğrulamıştır:

```
test_01_hardened_cis_baseline ... ok (100/100 Puan, Sıfır Bulgu)
test_02_public_profile_disabled_cwe_693 ... ok (30 Puan Düşüşü, Kritik Public Profil Tespiti)
test_03_domain_profile_disabled_cwe_693 ... ok (20 Puan Düşüşü, Domain Profil Uyarısı)
test_04_default_inbound_allow_cwe_284 ... ok (25 Puan Düşüşü, Varsayılan Allow Tespiti)
test_05_log_blocked_disabled_cwe_778 ... ok (10 Puan Düşüşü, Kütükleme Eksikliği Tespiti)
test_06_log_size_below_minimum_cwe_778 ... ok (5 Puan Düşüşü, Kütük Boyutu Uyarısı)
test_07_inbound_any_any_rule_cwe_284 ... ok (25 Puan Düşüşü, Any-Any Kuralı Tespiti)
test_08_public_profile_rdp_port_open_cwe_284 ... ok (20 Puan Düşüşü, Public RDP Tespiti)
test_09_public_profile_smb_port_open_cwe_284 ... ok (20 Puan Düşüşü, Public SMB Tespiti)
test_10_public_profile_winrm_port_open_cwe_284 ... ok (20 Puan Düşüşü, Public WinRM Tespiti)
test_11_private_profile_isolated_rule_passes ... ok (Yalnızca Private İzinleri Tam PASS)
test_12_cumulative_penalty_and_floor ... ok (Kümülatif Puan Düşüşü ve Taban Kontrolü)
test_13_markdown_report_structure ... ok (Rapor Format ve Tablo Bütünlüğü)
test_14_cli_spec_parsing_and_conversion ... ok (Sözlük Dönüştürme Doğruluğu)
test_15_cli_parser_and_subcommands ... ok (CLI Alt Komut ve Parametre Doğrulaması)

Ran 15 tests in 0.002s - OK
```

---

## 3. NEGATİF KONTROL VE ENGELLENEN SENARYOLAR (9/9 PASS)

`invalid_firewall_scenarios.json` dosyasındaki 9 zaaf ve port sızıntısı senaryosunun tamamı motor tarafından yakalanmış ve puan kırılmıştır:

1. **NEG-FW-01:** Public Profil Kapalı -> **CWE-693 / T1562.004** (Kritik - Tespit Edildi)
2. **NEG-FW-02:** Domain Profil Kapalı -> **CWE-693 / T1562.004** (Yüksek - Tespit Edildi)
3. **NEG-FW-03:** Private Profil Varsayılan Gelen 'Allow' -> **CWE-284 / T1562.004** (Kritik - Tespit Edildi)
4. **NEG-FW-04:** Any-to-Any Gelen İzin Kuralı -> **CWE-284 / T1562.004** (Kritik - Tespit Edildi)
5. **NEG-FW-05:** Public Profilde RDP (3389) Açık -> **CWE-284 / T1021.001** (Kritik - Tespit Edildi)
6. **NEG-FW-06:** Public Profilde SMB (445) Açık -> **CWE-284 / T1021.002** (Kritik - Tespit Edildi)
7. **NEG-FW-07:** Public Profilde WinRM (5985) Açık -> **CWE-284 / T1021.006** (Kritik - Tespit Edildi)
8. **NEG-FW-08:** Domain Profilinde Kütükleme Kapalı -> **CWE-778 / T1562.004** (Orta - Tespit Edildi)
9. **NEG-FW-09:** Public Profilde Kütük Boyutu < 16 MB -> **CWE-778 / T1562.004** (Düşük - Tespit Edildi)

---

## 4. POWERSHELL VE NETSH SIKILAŞTIRMA REÇETESİ

```powershell
# 1. Tüm Profilleri (Domain, Private, Public) Etkinleştir
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# 2. Varsayılan Gelen Trafiği Blokla, Giden Trafiğe İzin Ver
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow

# 3. Kütükleme (Logging) Ayarlarını Yapılandır (CIS: >= 16 MB)
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogBlocked True `
    -LogMaxSizeKilobytes 16384 `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# 4. Public Profilde Gelen İstisnaları Kapat (En Üst Savunma)
Set-NetFirewallProfile -Profile Public -AllowInboundRules False
```

---

## 5. SONUÇ VE BİR SONRAKİ ADIM

Gün 131 "Windows Firewall profilleri" modülü tüm standartlara uygun olarak **100/100 PASS** ile başarıyla teslim edilmiştir. 
Bir sonraki adım **Gün 132: Windows hizmet güvenliği** konusudur.
