# Gün 093: Hashlib ile Dosya Doğrulama ve Bütünlük İzleme (FIM)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik operasyonlarında adli delil güvenliği, dağıtım paketlerinin doğrulanması ve dosya bütünlük izleme (File Integrity Monitoring - FIM) süreçleri için tasarlanmış kurumsal seviyede kriptografik hash motoru.

---

## 🛡️ Yetenekler ve Güvenlik Mimarisi

- **$O(1)$ Sabit Bellek Akışı (Chunk-Based Streaming):** Dosya boyutu ne kadar büyük olursa olsun (gigabaytlarca log, ISO veya disk imajı), veriyi 64 KB'lık sabit bloklar halinde okur; belleği tüketmez (CWE-400 DoS koruması).
- **Zayıf Kriptografik Algoritma Kalkanı (CWE-328):** Sıkı modda (`strict_mode=True`) çarpışma zafiyeti bulunan MD5 ve SHA-1 kullanımını anında reddeder; modern SHA-256 ve SHA-512 algoritmalarını zorunlu kılar.
- **Zamanlama Analizi Koruması (CWE-208 Timing Attack Defense):** Kriptografik özet doğrulamalarında standart `==` operatörü yerine `hmac.compare_digest()` sabit zamanlı karşılaştırma fonksiyonunu kullanarak yan kanal zamanlama analizlerini engeller.
- **Dosya Bütünlük İzleme (FIM) Taban Çizgisi:** Belirtilen hedef dizinleri yinelemeli (recursive) tarayarak kriptografik hash taban çizgisi (baseline) oluşturur ve daha sonra bu taban çizgisi üzerinden yetkisiz değişiklikleri (`MODIFIED`), yeni eklenen dosyaları (`ADDED`) ve silinen dosyaları (`REMOVED`) tespit eder.
- **Dizin Aşımı (Path Traversal - CWE-22) ve Null-Byte (CWE-158) Kalkanı:** Dosya yolu çözümlemelerinde `..` kaçışlarını ve null karakter enjeksiyonlarını anında tespit ederek engeller.
- **POSIX Uyumlu CLI (`fim_runner.py`):** Standart Linux/Unix ve PowerShell boru hatlarına uygun çıkış kodları (0: Başarılı, 1: Bütünlük Uyuşmazlığı, 2: Sistem/Doğrulama Hatası).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_093/
├── uygulama/
│   ├── __init__.py
│   ├── file_integrity_verifier.py        # Kriptografik hash ve FIM çekirdek motoru
│   └── fim_runner.py                     # Terminal CLI yürütücüsü
├── tests/
│   ├── __init__.py
│   └── test_file_integrity_verifier.py   # 14/14 birim test seti
├── ornek_veri/
│   ├── test_corpus/                      # Bütünlük denetimi yapılan örnek test dosyaları
│   │   ├── app_payload.bin
│   │   ├── policy_doc.txt
│   │   └── secure_config.conf
│   ├── known_checksums.json              # Gerçek doğrulanmış SHA-256 ve SHA-512 özetleri
│   └── invalid_hash_inputs.json          # 9 adet negatif kontrol saldırı senaryosu
├── kanit/
│   ├── gercek/                           # Doğrulanmış test ve denetim çıktıları
│   │   ├── butunluk_denetim_raporu.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── test_sonuclari.txt
│   └── temsili/                          # Kriptografik FIM mimarisi ASCII şeması
│       └── hashlib_fim_mimarisi.txt
├── ders.md                               # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                         # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                              # 100/100 rubrik değerlendirme raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                      # Otomatik test ve kanıt üretim orkestratörü
├── manifest.json                         # Dosya doğrulama ve bütünlük manifestosu
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Kanıt üreticiyi çalıştır
python kanit_uretici.py

# Birim testleri doğrudan unittest ile koştur
python -m unittest tests/test_file_integrity_verifier.py -v

# FIM CLI ile dosya doğrulama testi
python uygulama/fim_runner.py verify --file ornek_veri/test_corpus/secure_config.conf --expected-hash b23512a868f00eb3ad3c5b5f2a15c32bb491a90c23d0cbe11311545672a91e5c --algo sha256
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
