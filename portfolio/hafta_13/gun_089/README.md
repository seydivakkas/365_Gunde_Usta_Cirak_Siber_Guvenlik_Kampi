# Gün 089: Argparse ve CLI Tasarımı

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik araçları için kurumsal, POSIX uyumlu, girdi doğrulama kalkanlarına ve alt komut (subparser) mimarisine sahip CLI motoru.

---

## 🛡️ Yetenekler ve Özellikler

- **POSIX/GNU Standardı Komut Ayrıştırma:** Kısa (`-v`) ve uzun (`--verbose`) bayraklar, alt komutlar (`scan`, `audit`, `hash`).
- **Miras Ayrıştırıcı (Common Parent Parser):** `add_help=False` ile ortak bayrakların (`--json-output`, `-v`) tüm alt komutlarda tutarlı çalışması.
- **Karşılıklı Dışlayan Seçenekler:** `add_mutually_exclusive_group` ile `--fast` ve `--deep` gibi birbiriyle çelişen bayrakların ayrıştırma seviyesinde engellenmesi.
- **Siber Güvenlik Girdi Doğrulama:**
  - **Port Sınır Denetimi (CWE-20):** $1 \le port \le 65535$.
  - **Dizin Atlama Engeli (CWE-22):** `..` dizin atlama karakterlerinin filtrelenmesi.
  - **Argüman Enjeksiyonu Koruması (CWE-88):** RFC-1123 uyumlu alan adı ve IP regex denetimi.
  - **DoS Önleme:** Girdi dizgi boyutu ($\le 8192$ bayt) ve argüman adedi ($\le 64$) sınırlandırması.
- **Standart POSIX Çıkış Kodları:** `0` (Başarı), `1` (Genel Hata), `2` (CLI Sözdizimi Hatası).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_13/gun_089/
├── uygulama/
│   ├── __init__.py
│   ├── security_cli_engine.py    # Çekirdek CLI ayrıştırma ve doğrulama motoru
│   └── cli_runner.py             # Terminal giriş noktası
├── tests/
│   ├── __init__.py
│   └── test_security_cli_engine.py # 14/14 tam kapsamlı birim test seti
├── ornek_veri/
│   ├── sample_cli_commands.json  # Örnek geçerli komut senaryoları
│   └── invalid_cli_inputs.json   # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                   # Doğrulanmış test ve denetim çıktıları
│   └── temsili/                  # Mimari ASCII görselleştirmesi
├── ders.md                       # Kapsamlı usta-çırak ders notu
├── soru_cevap.md                 # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                      # 100/100 rubrik değerlendirme raporu
├── sonuc.json                    # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py              # Testleri çalıştırıp kanıtları toplayan otomasyon betiği
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve negatif kontrol testlerini çalıştırmak için:

```bash
# Birim testleri çalıştırma
python -m unittest tests/test_security_cli_engine.py

# Kanıt üretici ve test paketini yürütme
python kanit_uretici.py

# Doğrudan CLI aracını deneme
python uygulama/cli_runner.py scan 192.168.1.1 --port 443 --json-output
python uygulama/cli_runner.py audit /var/log/syslog --deep
python uygulama/cli_runner.py hash "Gizli Mesaj" --algorithm sha256
```

---

## 📜 Lisans

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
