# G087: Bash Betik İskeleti ve Quoting Güvenlik Denetim Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Bash](https://img.shields.io/badge/Bash-5.0+-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square)
![Testler](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Negatif Kontroller](https://img.shields.io/badge/Negatif%20Kontroller-9%2F9%20PASS-brightgreen?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Müfredatı**'nın 87. Günü (Hafta 13 - Aşama 04) kapsamında geliştirilmiştir. Bash betiklerindeki iskelet yapılarını (`#!/usr/bin/env bash`, `set -euo pipefail`, `IFS=$'\n\t'`, `trap`), tırnaksız değişken genişletmelerini (CWE-732), dinamik `eval` komut enjeksiyonlarını (CWE-78), kelime bölünmesini (Word Splitting) ve yol adı genişletmesiyle oluşan bayrak enjeksiyonlarını (CWE-88) statik olarak denetleyen kurumsal bir güvenlik motoru ve güvenli betik şablonu içerir.

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

1. **`BashSkeletonParser`:** Shebang (`#!/usr/bin/env bash`), katı yürütme modu (`set -euo pipefail`), dahili alan ayırıcı (`IFS`) ve hata yakalama tuzaklarını (`trap`) ayrıştırır ve doğrular.
2. **`QuotingSecurityScanner`:** Tırnaksız değişken genişletmelerini (`rm -rf $DIR`), tehlikeli `eval` kullanımlarını, `for f in $(ls)` kalıplarını ve tırnaksız dizi aktarımlarını (`$*`, `$@`) tespit eder.
3. **`RuntimeWordSplittingSimulator`:** Kelime bölünmesi (Word Splitting) ve bayrak enjeksiyonu (`-rf`) dinamiklerini simüle ederek zafiyet riskini puanlar.
4. **`BashSkeletonQuotingAuditor`:** Façade tasarım deseniyle statik analiz raporlamasını ve katı mod (`strict=True`) istisna yönetimini sağlar.
5. **`secure_skeleton.sh`:** Kurumsal ortamlarda doğrudan kullanılabilecek, savunma derinliği ilkeleriyle donatılmış güvenli Bash betik iskeleti şablonudur.

---

## 🚀 Çalıştırma ve Test

### Python Birim Testleri:
```bash
python -m unittest portfolio.hafta_13.gun_087.tests.test_bash_skeleton_quoting_auditor -v
```

### Kanıt ve Rapor Üretimi:
```bash
python -m portfolio.hafta_13.gun_087.kanit_uretici
```

### Yerel Bash Betiği Doğrulaması:
```bash
bash ./portfolio/hafta_13/gun_087/uygulama/secure_skeleton.sh --file "test.log" --action "audit"
```
