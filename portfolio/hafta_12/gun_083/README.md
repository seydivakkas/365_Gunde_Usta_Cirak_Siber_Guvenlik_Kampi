# Gün 083: Git Commit ve Değişiklik İncelemesi (Git Commit & Diff Auditing)

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

Bu modül, yazılım geliştirme ve güvenlik operasyonları yaşam döngüsünde (DevSecOps / CI/CD) Git commit nesnelerini ve Unified Diff akışlarını statik olarak denetleyen bağımsız bir güvenlik motorudur (`GitCommitDiffAuditor`).

### Temel Güvenlik Yetenekleri
- **Unified Diff Ayrıştırma:** Commit hash, yazar, e-posta, tarih, mesaj, dosya deltaları ve hunk yapılarını ayrıştırır.
- **Sır ve Kimlik Bilgisi Taraması (CWE-798 / CWE-312):** AWS Access Key, GitHub PAT, RSA Özel Anahtarları, Slack Token ve JWT kalıplarını tespit eder ve maskeler.
- **Shannon Bilgi Entropisi Hesabı ($H = -\sum p_i \log_2 p_i$):** Bilinen kalıplara uymayan rastgele parola ve tuzları tespit eder.
- **Trojan Source Tespiti (CVE-2021-42574):** Kod inceleyenleri aldatmaya yönelik Unicode Bidi (çift yönlü) kontrol karakterlerini engeller.
- **Güvensiz Kod Kalıpları Tespiti (CWE-95 / CWE-78):** `eval()`, `exec()`, `os.system()`, `subprocess(shell=True)` eklemelerini yakalar.
- **DoS ve Diff Bombası Koruması (CWE-400):** Bayt boyutu ve satır sayısı limitleri ile fail-closed denetim uygular. Null byte (`\x00`) saldırılarını reddeder.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_12/gun_083/
├── README.md                               # Proje tanıtım ve kılavuz belgesi
├── ders.md                                 # Usta-çırak pedagojisiyle derin teknik ders
├── soru_cevap.md                           # 3 senaryo ve 4 zorunlu alt başlıklı Soru-Cevap
├── rapor.md                                # 100/100 tam puanlı teknik denetim raporu
├── sonuc.json                              # Makine tarafından okunabilir yürütme özeti
├── manifest.json                           # SHA-256 doğrulama özeti
├── ornek_veri/
│   ├── sample_commit.diff                  # Güvenli örnek commit ve unified diff
│   └── invalid_git_inputs.json             # 9 adet negatif güvenlik kontrol vektörü
├── uygulama/
│   ├── __init__.py                         # Paket tanımlayıcı
│   └── git_commit_diff_auditor.py          # Denetim motoru çekirdeği (her satır Türkçe açıklamalı)
├── tests/
│   ├── __init__.py                         # Test paketi tanımlayıcı
│   └── test_git_commit_diff_auditor.py     # 14 birim test (her satır Türkçe açıklamalı)
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt              # unittest yürütme logları (14/14 PASS)
    │   ├── komut_ve_cikis.txt              # CLI komut ve çıktı dökümü
    │   ├── negatif_kontrol_sonuclari.txt   # 9 negatif kontrolün yürütme kanıtı
    │   └── git_denetim_raporu.txt          # Gerçek motor denetim raporu çıktısı
    └── temsili/
        └── git_diff_ve_guvenlik_mimarisi.txt # TEMSİLÎ etiketli ASCII mimari diyagramı
```

---

## 🚀 Çalıştırma ve Doğrulama

### Birim Testlerini Çalıştırma
```bash
python -m unittest portfolio.hafta_12.gun_083.tests.test_git_commit_diff_auditor -v
```

### Negatif Güvenlik Testlerini Çalıştırma
```bash
python -c "
import json
from portfolio.hafta_12.gun_083.uygulama.git_commit_diff_auditor import GitCommitDiffAuditor
with open('portfolio/hafta_12/gun_083/ornek_veri/invalid_git_inputs.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
auditor = GitCommitDiffAuditor()
for item in data['negatif_testler']:
    payload = item['diff_icerik']
    if item['test_id'] == 'NEG_08_OVERSIZED_DIFF_DOS':
        payload = 'diff --git a/h.py b/h.py\n' + ('+l\n' * 11000)
    try:
        auditor.audit(payload, fail_fast=True)
    except Exception as e:
        print(f'[PASS] {item[\"test_id\"]} -> {type(e).__name__}')
"
```
