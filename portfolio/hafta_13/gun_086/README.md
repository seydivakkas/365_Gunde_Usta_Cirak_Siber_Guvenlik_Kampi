# G086: PowerShell Betik Parametreleri ve Güvenlik Denetim Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square)
![Testler](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Negatif Kontroller](https://img.shields.io/badge/Negatif%20Kontroller-9%2F9%20PASS-brightgreen?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Müfredatı**'nın 86. Günü (Hafta 13 - Aşama 04) kapsamında geliştirilmiştir. PowerShell betiklerindeki `param(...)` bloklarını statik olarak analiz eden, açık metin parolaları (CWE-312), eksik doğrulamaları (CWE-20, CWE-22) ve alt süreçlere yönelik argüman enjeksiyonlarını (CWE-88) tespit eden ve çalışma zamanında savunma derinliği sağlayan bir denetim motoru içerir.

---

## 🛡️ Lisans Kuralı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır.

YASAKLAR:
  1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
  2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
  3. Alt lisanslanamaz, satılamaz veya devredilemez.
  4. Tersine mühendislik yapılamaz.

İZİN VERİLEN KULLANIM:
  - GitHub üzerinde görüntüleme ve okuma.
  - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
İzin talepleri için: GitHub @seydivakkas
```

---

## 🏗️ Mimari Bileşenler

1. **`ScriptParamBlockParser`:** Dengeli parantez sayma algoritmasıyla `param(...)` bloğunu ve parametre özniteliklerini (`[Parameter()]`, `[Validate*]`, `[type]`) ayrıştırır.
2. **`ArgumentInjectionDetector`:** Dış süreç çağrılarında komut ayırıcı (`;`, `&&`, `|`, `` ` ``) ve şüpheli ikilileri tespit eder (CWE-88).
3. **`RuntimeParameterValidator`:** Çalışma zamanında dosya yollarını (CWE-22), sayısal aralıkları, izin verilen setleri ve regex kalıplarını doğrular; null-byte (0x00) ve 4096 karakter DoS tavanı uygular.
4. **`PowerShellParameterSecurityAuditor`:** Façade tasarım deseniyle statik betik analizi ve bulgu raporlaması sunar.
5. **`SecureParameterModule.ps1`:** Yerel PowerShell 7 gelişmiş fonksiyonu ile güvenli parametre splatting ve nesne boru hattı sağlar.

---

## 🚀 Çalıştırma ve Test

### Python Birim Testleri:
```bash
python -m unittest portfolio.hafta_13.gun_086.tests.test_powershell_parameter_security_auditor -v
```

### Kanıt ve Rapor Üretimi:
```bash
python -m portfolio.hafta_13.gun_086.kanit_uretici
```

### Yerel PowerShell 7 Modülü:
```powershell
pwsh -NoProfile -Command ". ./portfolio/hafta_13/gun_086/uygulama/SecureParameterModule.ps1; Invoke-SecureParameterAudit -TargetFile 'audit.log' -Port 8443 -Mode 'Enforce' -HostName 'corp.local'"
```
