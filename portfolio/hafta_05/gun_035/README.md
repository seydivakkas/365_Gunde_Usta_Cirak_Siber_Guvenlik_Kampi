# Gün 35: Mini Proje 4: Sistem Durum Kontrolü (MP-04)

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
![Status: Pass](https://img.shields.io/badge/status-PASS-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-blue?style=flat-square)
![Stage: 02](https://img.shields.io/badge/stage-02--System--and--Network-orange?style=flat-square)
![Week: 05](https://img.shields.io/badge/week-05--Mini--Project--04-purple?style=flat-square)

---

### Lisans Bildirimi
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

## 1. Genel Bakış ve Amaç
Bu modül; Hafta 05'in kapanış projesi olan **Mini Proje 4 (MP-04)** kapsamında geliştirilen konsolide bir **Sistem Durum Kontrolü ve Sağlık Denetleyicisi (`SystemPostureAuditor`)** sunar.

G035-SC1 ilkesi uyarınca sistem durum taraması salt-okunur (read-only) ve sıfır yan etkili gözlemlerden anlamlı özet üretir; yönetimsel ayrıcalık gerektirmez. Süreç zincirleri (Word -> PowerShell), servis tahrifatları, tırnaksız servis yolları, FIM hash uyuşmazlıkları ve sihirli bayt uzantı aldatmacaları tek bir yönetici durum panosunda konsolide edilir.

---

## 2. Klasör ve Dosya Hiyerarşisi
```
portfolio/hafta_05/gun_035/
├── README.md                                    # Bu dokümantasyon
├── ders.md                                      # Kapsamlı Usta-Çırak teorik ve haftalık proje ders notu
├── soru_cevap.md                                # G035-SC1..3 ve W05-SC1..3 detaylı soru-cevap bankası
├── rapor.md                                     # 20/40/25/15 puanlamalı 100/100 teknik rapor
├── sonuc.json                                   # Standart 14 alanlı makine tarafından okunabilir özet
├── manifest.json                                # SHA-256 bütünlük karmaları
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı ve lisans
│   └── system_posture_auditor.py                # Satır satır açıklamalı konsolide denetleyici uygulaması
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı ve lisans
│   └── test_system_posture_auditor.py           # 14 birim testi içeren test paketi
├── ornek_veri/
│   ├── system_telemetry_snapshot.json           # Çok boyutlu gerçekçi sistem telemetri anlık görüntüsü
│   └── corrupted_telemetry_test_cases.json      # Negatif kontrol bozuk telemetri veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # Unittest 14/14 PASS terminal çıktısı
    │   ├── komut_ve_cikis.txt                   # CLI yürütme dökümü
    │   ├── sistem_durum_panosu_raporu.txt       # Ayrıntılı ASCII yönetici panosu çıktısı
    │   └── negatif_kontrol_sonuclari.txt        # Bozuk telemetri reddetme raporu
    └── temsili/
        └── sistem_durum_kontrolu_mimarisi.txt   # 'TEMSİLÎ — AI İLLÜSTRASYONU' mimari şeması
```

---

## 3. Hızlı Başlangıç ve Kullanım

### A. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_05/gun_035/tests/test_system_posture_auditor.py -v
```

### B. Denetleyici Uygulamasını Çalıştırma
```bash
python portfolio/hafta_05/gun_035/uygulama/system_posture_auditor.py
```

---

## 4. Temel Yetenekler
- **Salt-Okunur Gözlemci Modeli:** Hedef sistemde hiçbir değişiklik yapmadan, en az ayrıcalıkla (Least Privilege) durum tespiti yapar.
- **Dört Boyutlu Güvenlik Taraması:** Süreç Hiyerarşisi, Servis Yapılandırması, Dosya Bütünlüğü (FIM) ve Sihirli Bayt (Magic Bytes) denetimlerini tek geçişte koşturur.
- **Sağlık Puanlama Motoru:** 100 üzerinden ağırlıklı sağlık puanı hesaplar ve duruş derecelendirmesi atar.
- **Öncelikli Eylem Kılavuzu (Remediation Playbook):** Tespit edilen her tehdit için net adli ve defansif aksiyon adımı üretir.
