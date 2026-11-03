# Gün 027: Paket ve Güncelleme Yöneticileri Güvenlik Denetim ve Yönetim Aracı

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02 - Sistem ve Ag Guvenligi](https://img.shields.io/badge/stage-02--Sistem%20ve%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Week: 04](https://img.shields.io/badge/week-04-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-brightgreen?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)

Bu çalışma, **Siber Güvenlik 365 Gün Standart ve Müfredat Paketi** kapsamında, Aşama 02 (Sistem ve Ağ Güvenliği Temelleri) Hafta 04 bünyesinde geliştirilmiş kurumsal paket yöneticisi denetim, sürüm sabitleme (pinning), güvenli güncelleme ve geri alma (rollback) motorunu içermektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_04/gun_027/
├── ders.md                 # 7 bölümlük usta-çırak pedagojik ders anlatımı
├── soru_cevap.md           # G027-SC1, SC2, SC3 senaryoları ve 4 başlıklı analizleri
├── rapor.md                # 20/40/25/15 kriter puanlama tablosu ve 100/100 sonuç raporu
├── README.md               # Proje genel bakışı, kullanım kılavuzu ve lisans
├── sonuc.json              # 14 standart alanlı makine tarafından okunabilir sonuç dosyası
├── manifest.json           # Dizin içeriği ve SHA256 bütünlük hash listesi
├── uygulama/
│   ├── __init__.py
│   └── package_update_manager_auditor.py  # Paket ve güncelleme denetim motoru
├── tests/
│   ├── __init__.py
│   └── test_package_update_manager_auditor.py # 14 kapsamlı birim test
├── ornek_veri/
│   ├── package_manager_policy_baseline.json   # Kurumsal politika ve referans kurallar
│   └── sample_package_inventory.json          # Örnek sunucu paket ve depo envanteri
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # Unittest yürütme çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI --audit çalıştırma çıktısı
    │   └── guncelleme_ve_geri_alma_kaydi.txt  # Pinning, negatif kontrol, update, rollback izi
    └── temsili/
        └── paket_yonetimi_ve_guvenlik_mimarisi.txt # GPG doğrulama ve güncelleme şeması
```

---

## 🚀 Kullanım Kılavuzu

### 1. Sistem ve Depo Güvenlik Denetimi (`--audit`)
Kurulu depoları HTTPS/GPG standartlarına göre inceler; kritik paketlerdeki sabitleme eksikliklerini ve bekleyen CVE'leri listeler:
```bash
python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --inventory portfolio/hafta_04/gun_027/ornek_veri/sample_package_inventory.json --audit
```

### 2. Kritik Paketi Dondurma / Sabitleme (`--pin`)
Üretim ortamındaki kritik paketi sabitleyerek plansız güncellemelere karşı korumaya alır:
```bash
python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --inventory ornek_veri/sample_package_inventory.json --pin nginx
```

### 3. Güvenli Güncelleme ve İşlem Günlüğü (`--update`)
Serbest bir paketi hedef sürüme yükseltir ve eski sürümü işlem günlüğüne kaydeder:
```bash
python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --inventory ornek_veri/sample_package_inventory.json --journal ornek_veri/journal.json --update openssl 3.0.13
```

### 4. Geri Alma / Rollback (`--rollback`)
Güncelleme sonrasında olası bir arıza durumunda paketi önceki kararlı sürümüne döndürür:
```bash
python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --inventory ornek_veri/sample_package_inventory.json --journal ornek_veri/journal.json --rollback openssl
```

### 5. Kurumsal Politika Notu Üretimi (`--policy-note`)
Kurumsal paket ve yama yönetimi ilkelerini metin formatında yazdırır:
```bash
python portfolio/hafta_04/gun_027/uygulama/package_update_manager_auditor.py --policy-note
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm testler harici kütüphane bağımlılığı olmaksızın Python standart kütüphanesi (`unittest`) ile koşulur:
```bash
python -m unittest discover -s portfolio/hafta_04/gun_027/tests -p "test_*.py" -v
```

---

## 📄 Lisans

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
