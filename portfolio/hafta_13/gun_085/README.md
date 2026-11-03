# Gün 085: PowerShell Nesne Boru Hattı (Object Pipeline) ve Güvenlik Otomasyonu

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)
![Negative Controls: 9 Passed](https://img.shields.io/badge/negative%20tests-9%20passed-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
```

---

## 📌 Genel Bakış ve Kapsam

Bu modül, PowerShell ekosisteminin merkezinde yer alan **Nesne Boru Hattı (Object Pipeline)** mekanizmasını, adli bilişim analizi, süreç ve ağ tehdit avcılığı (threat hunting) ve boru hattı güvenlik zafiyetleri (IEX, Download Cradle, Base64 gizleme, Unquoted Service Path) açılarından inceleyen hibrit bir denetim paketidir.

### Temel Güvenlik ve Analiz Yetenekleri
- **Boru Hattı Statik Güvenlik Denetimi:** `Invoke-Expression` (`IEX`), Download Cradle (`WebClient.DownloadString | iex`), gizlenmiş Base64 (`-EncodedCommand`) ve tırnaksız servis yollarının tespiti.
- **Süreç Tehdit Avcılığı (Process Pipeline Hunting):** Bilinen saldırı araçlarının (`mimikatz`), anormal ebeveyn-çocuk ilişkilerinin (`winword.exe` -> `powershell.exe`) ve kullanıcı dizinlerindeki imzasız ikililerin yakalanması.
- **Ağ Soketi Korelasyonu:** Şüpheli dinleme portlarının (Port 4444 Metasploit vb.) tespiti ve ilgili süreç kimlikleriyle (PID) bağlanması.
- **Boru Hattı DoS Koruması (CWE-400):** Sınırsız nesne akışlarına karşı 5000 nesnelik fail-closed güvenlik tavanı.
- **Native PowerShell 7 Desteği:** `SecurityPipelineAuditor.ps1` ile gerçek PowerShell oturumlarında nesne akışı (`begin / process / end`) denetimi.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_13/gun_085/
├── README.md                                       # Proje tanıtım ve kullanım kılavuzu
├── ders.md                                         # Usta-çırak pedagojisiyle derin teknik ders
├── soru_cevap.md                                   # 3 senaryo ve 4 zorunlu alt başlıklı Soru-Cevap
├── rapor.md                                        # 100/100 tam puanlı teknik denetim raporu
├── sonuc.json                                      # Makine tarafından okunabilir yürütme özeti
├── manifest.json                                   # SHA-256 doğrulama özeti
├── ornek_veri/
│   ├── sample_powershell_artifacts.json            # Süreç, ağ ve olay günlüğü nesneleri
│   ├── sample_pipeline_script.ps1                  # Güvenli örnek PowerShell boru hattı betiği
│   └── invalid_powershell_inputs.json              # 9 adet negatif güvenlik kontrol senaryosu
├── uygulama/
│   ├── __init__.py                                 # Paket tanımlayıcı
│   ├── powershell_pipeline_security_engine.py      # Güvenlik motoru (her satır Türkçe açıklamalı)
│   └── SecurityPipelineAuditor.ps1                 # Native PowerShell 7 boru hattı denetleyicisi
├── tests/
│   ├── __init__.py                                 # Test paketi tanımlayıcı
│   └── test_powershell_pipeline_security_engine.py # 14 birim test (her satır Türkçe açıklamalı)
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                      # unittest yürütme logları (14/14 PASS)
    │   ├── komut_ve_cikis.txt                      # CLI ve pwsh komut/çıktı dökümü
    │   ├── negatif_kontrol_sonuclari.txt           # 9 negatif kontrolün yürütme kanıtı
    │   └── powershell_boru_hatti_denetim_raporu.txt # Gerçek tehdit avcılığı çıktısı
    └── temsili/
        └── powershell_boru_hatti_mimarisi.txt      # TEMSİLÎ etiketli ASCII mimari diyagramı
```

---

## 🚀 Çalıştırma ve Doğrulama

### Python Birim Testlerini Çalıştırma
```bash
python -m unittest portfolio.hafta_13.gun_085.tests.test_powershell_pipeline_security_engine -v
```

### Native PowerShell 7 Modülünü Test Etme
```powershell
pwsh -NoProfile -Command ". ./portfolio/hafta_13/gun_085/uygulama/SecurityPipelineAuditor.ps1; Test-PipelineScriptSafety -ScriptContent 'Get-Process | Where-Object { `$_.CPU -gt 5 }'"
```
