# Hafta 17 / Gün 119: Mini Proje 16 — Kurumsal Rol Tabanlı Erişim Simülatörü ve Politika Doğrulama Motoru

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: NIST ANSI/INCITS 359-2004](https://img.shields.io/badge/standard-NIST_ANSI_359_RBAC-green.svg?style=flat-square)](https://csrc.nist.gov/)
[![Test Durumu: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15_PASS-brightgreen.svg?style=flat-square)](tests/)
[![Puan: 100/100](https://img.shields.io/badge/score-100%2F100_YETERLİ-success.svg?style=flat-square)](rapor.md)

---

## 🔒 Lisans Bildirimi

```text
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

## 📌 Proje Genel Bakışı

Bu proje, Hafta 17'nin zirvesi olan **Mini Proje 16** kapsamında geliştirilmiş, kurumsal organizasyonların ve IAM ekiplerinin canlı sistemlere dokunmadan önce yetkilendirme modellerini test ettiği, doğruladığı ve simüle ettiği **Rol Tabanlı Erişim Simülatörü (RBAC Simulator & Policy Engine)** çözümüdür.

Sistem şu temel yetenekleri ve savunma kalkanlarını içerir:
1. **NIST Core & Hierarchical RBAC:** Rol hiyerarşisi (DAG) üzerinden miras alınan izinlerin özyineli hesaplanması.
2. **Döngüsel Bağımlılık (Cycle Detection - CWE-674) Koruması:** DFS tabanlı döngü tespit algoritması ile sonsuz döngü ve yığın taşması saldırılarının engellenmesi.
3. **Statik Görevler Ayrılığı (SSD - CWE-863):** Çıkar çatışması oluşturan rollerin (`accountant` vs `cashier`) aynı kullanıcıya atanmasının engellenmesi.
4. **Dinamik Görevler Ayrılığı (DSD - CWE-863):** Kullanıcı birden fazla role sahip olsa dahi aynı aktif oturumda çatışan rolleri (`sec_officer` vs `developer`) çalıştırmasının önlenmesi.
5. **Yetki Birikimi (Privilege Creep - CWE-250) Analizörü:** Kullanıcı başına azami rol sınırı ile gereksiz yetki birikiminin tespiti ve engellenmesi.
6. **Dinamik Oturum Kapsamı (Session-Scoped Least Privilege):** Kullanıcının oturum açarken rollerinin sadece bir kısmını aktive edebilmesi.
7. **Toplu Politika Kuru Koşturma (Batch Dry-Run):** Çoklu istek paketlerinin canlı öncesi test edilerek iş sürekliliğinin güvenceye alınması.
8. **Yapılandırılmış Denetim İzi (JSON Audit Trail):** Tüm rol tanımlama, atama, geri alma, oturum açma ve erişim simülasyonu olaylarının kayıt altına alınması.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-862** | Missing Authorization (Rol Yetki Eksikliği) | Fail-Closed varsayılan ret mantığı ve kesin izin eşleşmesi |
| **CWE-863** | Incorrect Authorization (Statik SoD Çatışması) | Çatışan rollerin (`accountant` vs `cashier`) aynı kullanıcıya atanması engeli |
| **CWE-863** | Incorrect Authorization (Dinamik SoD Çatışması) | Çatışan rollerin (`sec_officer` vs `developer`) tek oturumda açılması engeli |
| **CWE-285** | Improper Authorization (Atanmamış Rol Aktivasyonu) | Kullanıcının atanmamış rolleri oturumda açmasının engellenmesi |
| **CWE-674** | Uncontrolled Recursion (Hiyerarşik Döngü Enjeksiyonu) | DFS tabanlı döngü tespit algoritması (Cycle Detection) ile koruma |
| **CWE-250** | Execution with Unnecessary Privileges (Privilege Creep) | Kullanıcı başına azami rol sınırı ile aşırı yetki birikiminin önlenmesi |
| **CWE-613** | Insufficient Session Expiration (Geçersiz/Sahte Oturum) | Kayıtsız veya süresi dolmuş oturum jetonlarının reddedilmesi |
| **CWE-862** | Missing Authorization (Geri Alınan Rol Yetkisi) | Kullanıcıdan rol geri alındığında izinlerin anında düşürülmesi |
| **CWE-287** | Improper Authentication (Kayıtsız Kullanıcı Talebi) | Sistemde tanımlı olmayan kullanıcı taleplerinin güvenli reddi |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_119/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── rbac_simulator_engine.py   # RBAC simülatörü, DAG miras, SSD, DSD, Creep motoru
│   └── rbac_sim_cli.py            # Simülasyon, SoD analizi ve yetki denetim CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_rbac_simulator.py     # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── enterprise_rbac_model.json # Kurumsal rol modeli, miras ağacı ve SoD kuralları
│   └── invalid_simulator_requests.json # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── rbac_sim_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── rbac_simulator_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Kanıt Üretici ve Doğrulama Koşturma
```powershell
python kanit_uretici.py
```

### 3. CLI ile Erişim Simülasyonu ve SoD Analizi
```powershell
# Başarılı Erişim Simülasyonu (CFO Bütçe Onayı)
python uygulama/rbac_sim_cli.py sim-access --user-id "cfo_selim" --target "budget" --action "approve"

# Yetkisiz Erişim Denemesi (Geliştirici Bütçe Onaylayamaz - CWE-862)
python uygulama/rbac_sim_cli.py sim-access --user-id "dev_ayse" --target "budget" --action "approve"

# Görevler Ayrılığı (SoD) Çatışma Analizi
python uygulama/rbac_sim_cli.py check-sod --roles "accountant,cashier"
```
