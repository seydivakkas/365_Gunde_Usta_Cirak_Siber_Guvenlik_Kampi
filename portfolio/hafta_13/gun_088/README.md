# G088: Komut Çıkış Kodu ve stderr Güvenlik Denetim Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Bash](https://img.shields.io/badge/Bash-5.0+-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square)
![Testler](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Negatif Kontroller](https://img.shields.io/badge/Negatif%20Kontroller-9%2F9%20PASS-brightgreen?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Müfredatı**'nın 88. Günü (Hafta 13 - Aşama 04) kapsamında geliştirilmiştir. İşletim sistemi süreçlerinin POSIX ve Windows çıkış kodlarını (0-255) adli ve güvenlik perspektifinden inceleyen; standart hata (stderr) akışındaki kimlik bilgisi sızıntılarını (CWE-209 / CWE-532), `2> /dev/null` ile sessiz hata yutma (CWE-390) zafiyetlerini, boru hattı ara hatalarını (`PIPESTATUS`) ve süreç asılı kalma (DoS) risklerini tespit eden ve güvenli hata yönetimi sağlayan bir denetim motorudur.

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

1. **`ProcessExecutionInspector`:** Alt süreçleri güvenle yürütür, zaman aşımı (timeout) uygular, çıkış kodunu POSIX standartlarına (0, 1, 2, 126, 127, 128+N) göre anlamlandırır.
2. **`StderrSecurityScanner`:** Standart hata akışında açık metin parola, API anahtarı, veritabanı URI'si veya özel anahtar sızıntılarını tespit eder (CWE-209 / CWE-532).
3. **`ScriptErrorHandlingAuditor`:** Betik dosyalarında `2> /dev/null` ile sessiz hata yutma (CWE-390) ve `set -e` olmaksızın sahte `exit 0` dönme kalıplarını statik analizle yakalar.
4. **`CommandExitStderrSecurityAuditor`:** Façade deseni ile tüm analiz ve süreç denetim fonksiyonlarını birleştirir.
5. **`secure_exit_handling.sh`:** Kurumsal standartlarda güvenli hata yakalama, stderr maskeleme ve PIPESTATUS denetimi sağlayan yerel Bash modülüdür.

---

## 🚀 Çalıştırma ve Test

### Python Birim Testleri:
```bash
python -m unittest portfolio.hafta_13.gun_088.tests.test_command_exit_stderr_security_auditor -v
```

### Kanıt ve Rapor Üretimi:
```bash
python -m portfolio.hafta_13.gun_088.kanit_uretici
```

### Yerel Bash Betiği Doğrulaması:
```bash
bash ./portfolio/hafta_13/gun_088/uygulama/secure_exit_handling.sh "test.log"
```
