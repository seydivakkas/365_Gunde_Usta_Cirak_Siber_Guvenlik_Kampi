# Gün 025: Kullanıcı, Grup ve Oturum Güvenliği Mimarisi

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue)
![Security Standard](https://img.shields.io/badge/standard-NIST%20800--53%20%7C%20CIS%20Benchmark-orange)
![Tests](https://img.shields.io/badge/tests-14%2F14%20PASS-brightgreen)

## Lisans ve Telif Hakkı

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

## Genel Bakış

Bu çalışma, 365 Günlük Siber Güvenlik Müfredatı kapsamında **Aşama 02 / Hafta 04 / Gün 025** ("Kullanıcı, grup ve oturum") modülü için geliştirilmiştir.

Modülün temel amacı; işletim sistemlerindeki statik Kimlik (Authentication) ile dinamik Etkin Oturum (Active Session) arasındaki farkı, UID/GID/SID kimlik belirteçlerini, servis hesaplarının sıkılaştırılmasını (`/usr/sbin/nologin`), ortak hesapların (shared accounts) inkâr edilemezlik (non-repudiation) ilkesini nasıl ortadan kaldırdığını, atıl (dormant) hesap risklerini ve oturum zaman aşımı kontrollerini teorik ve uygulamalı olarak öğretmektir.

---

## Proje Yapısı

```
portfolio/hafta_04/gun_025/
│
├── uygulama/
│   ├── __init__.py
│   └── user_group_session_auditor.py     # Canlı oturum ve envanter denetleyicisi
│
├── tests/
│   ├── __init__.py
│   └── test_user_group_session_auditor.py # 14 birim test
│
├── ornek_veri/
│   ├── system_users_groups_baseline.json # CIS/NIST tabanlı kurallar
│   └── sample_active_sessions_and_users.json # Taranan kullanıcı/oturum envanteri
│
├── kanit/
│   ├── gercek/
│   │   ├── yerel_oturum_belgeleme.txt    # G025-SC2 canlı oturum belgelemesi
│   │   ├── test_sonuclari.txt            # 14/14 test pass çıktısı
│   │   └── komut_ve_cikis.txt            # CLI çalışma ve denetim çıktıları
│   └── temsili/
│       └── kimlik_ve_oturum_mimarisi.txt # Temsili mimari şema
│
├── ders.md                               # Kapsamlı didaktik usta-çırak dersi
├── soru_cevap.md                         # 3 senaryo ve 4 zorunlu alt başlık
├── rapor.md                              # 100/100 başarım ve değerlendirme
├── sonuc.json                            # 14 standart alan
└── manifest.json                         # Dosya bütünlük SHA-256 özeti
```

---

## Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_04/gun_025/tests -p "test_*.py" -v
```

### 2. Geçerli Oturumu Canlı Olarak Belgeleme (G025-SC2)
```bash
python portfolio/hafta_04/gun_025/uygulama/user_group_session_auditor.py --live-session
python portfolio/hafta_04/gun_025/uygulama/user_group_session_auditor.py --live-session --json
```

### 3. Kullanıcı ve Oturum Güvenlik Denetimi
```bash
python portfolio/hafta_04/gun_025/uygulama/user_group_session_auditor.py --audit
```
