# Gün 092: Veri Doğrulama ve Tip Güvenliği

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik varlıkları, telemetri verileri ve ağ yapılandırmaları için çalışma zamanı (runtime) tip güvenliği, Allowlist tabanlı girdi doğrulaması ve enjeksiyon savunma kalkanı.

---

## 🛡️ Yetenekler ve Özellikler

- **Çalışma Zamanı Tip Güvenliği (`@enforce_types`):** Fonksiyon parametrelerinin tip ipuçlarıyla uyuşmasını çalışma anında zorunlu kılar.
- **Tip Karışıklığı (Type Confusion - CWE-843) Savunması:** Python'da `bool` tipinin `int` yerine sızmasını engeller.
- **Sıkı Ağ ve Güvenlik Doğrulamaları:**
  - **IPv4:** 4 oktet, 0-255 sınırları ve Octal IP (baştaki sıfır) engeli (CWE-704).
  - **Port Sınırları:** 1-65535 kapalı aralığı (CWE-1284).
  - **MAC Adresi:** EUI-48 standardı regex ve hex doğrulaması.
  - **Hostname:** RFC-1123 uyumu ve kabuk ayracı / komut enjeksiyonu koruması (CWE-88).
  - **SHA-256:** 64 karakterlik kriptografik hex özet doğrulaması.
  - **Protokol:** Allowlist kümesi (TCP, UDP, ICMP, SCTP).
  - **Risk Skoru:** [0.0, 10.0] sayısal aralık denetimi.
- **Gelişmiş Saldırı Kalkanları:**
  - **Null-Byte (`\x00`) Zehirlemesi Koruması (CWE-158):** C kütüphanelerine sızabilecek null karakterlerin anında engellenmesi.
  - **DoS ve Bellek Tavanı (CWE-400):** Alan başına maksimum 4096 bayt sınırı.
- **Değiştirilemez (Immutable) Güvenlik Nesnesi:** `@dataclass(frozen=True)` ile durum güvenliği.
- **POSIX Uyumlu CLI (`validator_cli.py`):** Standart çıkış kodları (0, 1, 2) ve `--strict` modu.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_092/
├── uygulama/
│   ├── __init__.py
│   ├── security_data_validator.py        # Çekirdek veri doğrulama ve tip güvenliği motoru
│   └── validator_cli.py                  # Terminal CLI arayüzü
├── tests/
│   ├── __init__.py
│   └── test_security_data_validator.py   # 14/14 birim test seti
├── ornek_veri/
│   ├── valid_security_assets.json        # Geçerli güvenlik varlıkları
│   └── invalid_security_assets.json      # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                           # Doğrulanmış test ve denetim çıktıları
│   └── temsili/                          # Mimari ASCII görselleştirmesi
├── ders.md                               # Kapsamlı usta-çırak ders notu
├── soru_cevap.md                         # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                              # 100/100 rubrik değerlendirme raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                      # Testleri çalıştırıp kanıtları toplayan otomasyon betiği
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Birim testleri çalıştırma
python -m unittest tests/test_security_data_validator.py

# Kanıt üretici ve test paketini yürütme
python kanit_uretici.py

# CLI aracını deneme
python uygulama/validator_cli.py --input-file ornek_veri/valid_security_assets.json
python uygulama/validator_cli.py --input-file ornek_veri/valid_security_assets.json --json-output
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
