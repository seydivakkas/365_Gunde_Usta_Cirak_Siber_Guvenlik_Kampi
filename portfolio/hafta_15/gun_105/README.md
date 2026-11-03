# Gün 105: Mini Proje 14 — Kriptografik Hash Bütünlük Manifesti ve Doğrulama Motoru (FIM)

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![Test Status](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](tests/)
[![Security Standards](https://img.shields.io/badge/standards-NIST%20SP%20800--147%20%7C%20PCI%20DSS%2010.5.5-orange?style=flat-square)](rapor.md)

---

## 📌 Genel Bakış ve Amaç

Bu mini proje (Hafta 15 Bitirme Projesi); Tripwire, AIDE, Git ve Linux `dm-verity` mimarilerinden ilham alarak geliştirilmiş, dosya ağaçlarının bütünlüğünü kriptografik kesinlikle takip eden saf Python (Pure Python) tabanlı bir **Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM)** sistemidir.

Proje, yazılım tedarik zinciri (software supply chain) güvenliği, adli bilişim ve yetkisiz sistem manipülasyonlarını (tampering) tespit etmek üzere tasarlanmıştır.

---

## 🛡️ Temel Güvenlik Özellikleri ve Savunulan Zafiyetler

1. **Akışlı (Streaming) Hashing (CWE-400 Savunması):** Bellek taşmalarını (OOM DoS) önlemek için dosyalar 64 KB'lık sabit tampon bloklarla taranır.
2. **Kripto-Çevik Çoklu Hash (Multi-Hash):** SHA-256, BLAKE2b ve SHA-512 algoritmalarıyla eşzamanlı özet çıkarımı. Zayıf algoritmalar (MD5/SHA-1 - CWE-328) anında engellenir.
3. **HMAC-SHA256 Kriptografik Mühür (CWE-353 Savunması):** Manifest dosyasının kendisinin tahrif edilmesini önlemek amacıyla gizli mühür anahtarı ile imzalanması.
4. **Dizin Aşımı ve Sembolik Bağ Savunması (CWE-22 & CWE-59):** Bağıl yolların kök dizin hapishanesinde tutulması (`safe_resolve_path`), sembolik bağ kaçışlarının engellenmesi.
5. **Zamanlama Analizi Direnci (CWE-208):** Mühür ve hash karşılaştırmalarında `hmac.compare_digest` kullanımı.

---

## 📁 Proje Dizin Yapısı

```
portfolio/hafta_15/gun_105/
├── uygulama/
│   ├── __init__.py
│   ├── hash_manifest_engine.py       # Çekirdek FIM ve kriptografik mühürleme motoru
│   └── manifest_cli.py               # Komut satırı denetim ve alarm arayüzü
├── tests/
│   ├── __init__.py
│   └── test_hash_manifest.py         # 15 Birim testi (%100 Başarı)
├── ornek_veri/
│   ├── sample_project_tree/          # Örnek kaynak ağacı (app.py, config.json vb.)
│   ├── manifest_samples.json         # Referans manifest şeması
│   └── invalid_manifest_inputs.json  # 9 Negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/                       # Gerçek test ve analiz çıktıları
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── manifest_denetim_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/                      # Mimari ASCII diyagramı (Zorunlu bantlı)
│       └── hash_manifest_mimarisi.txt
├── kanit_uretici.py                  # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                           # Usta-Çırak FIM ders notları
├── soru_cevap.md                     # 3 Kritik teknik mülakat sorusu ve derin analiz
├── rapor.md                          # 100/100 Puanlık değerlendirme ve CWE matrisi
├── sonuc.json                        # Makine tarafından okunabilir sonuç özeti
├── manifest.json                     # Günlük paket içerik dökümü ve hash listesi
└── README.md                         # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Kurulum ve Kullanım

Herhangi bir harici kütüphane gerektirmez (Pure Python Standard Library).

```bash
# 1. Proje dizini için HMAC mühürlü manifest oluşturma
python uygulama/manifest_cli.py --create ornek_veri/sample_project_tree \
    --output test_manifest.json \
    --seal-key "GucluMuhurAnahtari2026!#"

# 2. Manifestoyu ve dosya bütünlüğünü doğrulama
python uygulama/manifest_cli.py --verify ornek_veri/sample_project_tree \
    --manifest test_manifest.json \
    --seal-key "GucluMuhurAnahtari2026!#"

# 3. Kötü niyetli değişiklik simülasyonu (Manipülasyon Tespiti)
python uygulama/manifest_cli.py --tamper-sim ornek_veri/sample_project_tree/config.json

# 4. Tüm birim testlerini koşturma
python -m unittest tests/test_hash_manifest.py -v
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
