# Gün 090: Tarih-Saat, UTC ve Saat Dilimi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Adli bilişim (DFIR) ve olay müdahalesi (IR) süreçleri için çok kaynaklı heterojen log zaman damgalarını (ISO-8601, Unix Epoch, Windows FileTime) sıfır belirsizlikle UTC standardına normalize eden, saat sapması (Clock Skew) ve Replay Attack risklerini denetleyen güvenlik motoru.

---

## 🛡️ Yetenekler ve Özellikler

- **Çoklu Format Adli Dönüşümü:**
  - **ISO-8601 / RFC-3339:** Zulu (`Z`) ve saat dilimi ofseti (`+03:00`, `-04:00`, `+09:00`) içeren zaman damgalarının UTC'ye indirgenmesi.
  - **Unix Epoch:** 10 haneli saniye ve 13 haneli milisaniye değerlerinin UTC datetime nesnesine dönüştürülmesi.
  - **Windows FileTime:** 1 Ocak 1601 başlangıçlı 64-bitlik Active Directory ve NTFS zaman damgalarının Unix Epoch dönüşümü.
- **Naive Datetime Güvenlik Kalkanı (CWE-613):** Saat dilimi bilgisi içermeyen belirsiz zaman damgalarının anında engellenmesi.
- **Saat Sapması (Clock Skew) ve Replay Attack Savunması (CWE-1385):** Kerberos ve OAuth standartlarına uygun $\Delta t \le 300$ saniye kuralı denetimi.
- **Kronolojik Adli Zaman Çizgisi (Forensic Timeline):** Heterojen kaynaklardan gelen olayların Unix Epoch sıralamasıyla kusursuz bir zaman çizgisine oturtulması.
- **Sıkı Girdi Doğrulama:** Takvimsel imkansızlıklar (Şubat 30), saat/dakika taşmaları ve DoS uzunluk sınırları ($\le 128$ karakter) denetimi.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_13/gun_090/
├── uygulama/
│   ├── __init__.py
│   ├── utc_timezone_forensic_normalizer.py # Çekirdek adli bilişim ve normalizasyon motoru
│   └── forensic_timeline_runner.py        # Terminal CLI arayüzü
├── tests/
│   ├── __init__.py
│   └── test_utc_timezone_forensic_normalizer.py # 14/14 birim test seti
├── ornek_veri/
│   ├── sample_multisource_logs.json       # Farklı saat dilimi ve formatlardaki loglar
│   └── invalid_timestamp_inputs.json      # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                            # Doğrulanmış test ve denetim çıktıları
│   └── temsili/                           # Mimari ASCII görselleştirmesi
├── ders.md                                # Kapsamlı usta-çırak ders notu
├── soru_cevap.md                          # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                               # 100/100 rubrik değerlendirme raporu
├── sonuc.json                             # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                       # Testleri çalıştırıp kanıtları toplayan otomasyon betiği
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Birim testleri çalıştırma
python -m unittest tests/test_utc_timezone_forensic_normalizer.py

# Kanıt üretici ve test paketini yürütme
python kanit_uretici.py

# Doğrudan CLI aracını deneme
python uygulama/forensic_timeline_runner.py --input-logs ornek_veri/sample_multisource_logs.json
python uygulama/forensic_timeline_runner.py --audit-skew
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
