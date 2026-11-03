# GÜN 012: Sanal Makine Anlık Görüntü (Snapshot), Yedekleme ve Geri Dönüş Mimarisi

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 01](https://img.shields.io/badge/A%C5%9Fama-01-blue?style=flat-square)
![Hafta: 02](https://img.shields.io/badge/Hafta-02-indigo?style=flat-square)
![Durum: PASS](https://img.shields.io/badge/Durum-PASS-brightgreen?style=flat-square)
![Test Kapsamı: 100%](https://img.shields.io/badge/Test%20Kapsam%C4%B1-100%25-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📌 Genel Bakış ve Hedefler

Bu çalışma; siber güvenlik laboratuvarlarında zararlı yazılım analizi ve sızma testi öncesi "Altın Durum" (Golden State) anlık görüntülerinin (snapshot) alınmasını, test sonrası saniyeler içinde geri dönüşü (rollback) ve snapshot mekanizmasının asla bir "yedek" sanılmaması gerektiğini donanım ve hypervisor disk blokları seviyesinde ele alır.

### Temel Kazanımlar:
1. **Snapshot vs Backup Ayrımı:** Copy-on-Write / Redirect-on-Write differencing disk mekanizması ve ana diske mutlak bağımlılık.
2. **Snapshot Yaş Sınırı ve Disk Şişmesi (Bloat):** 72 saat kuralı ve hypervisor veri deposu kilitlenmesi riskleri.
3. **3-2-1-1-0 Kurumsal Yedekleme Standardı:** Farklı ortamlar, harici kopyalar ve WORM (Write Once Read Many) / Değişmezlik kilidi.
4. **Fidye Yazılımlarının VSS İmha Taktikleri:** `vssadmin delete shadows` saldırı yüzeyi ve tespit yöntemleri.
5. **Kriptografik Bütünlük:** SHA-256 akışkan özetleme ve bozulmuş/manipüle edilmiş yedeklerin geri yüklenmesini reddetme.

---

## 📂 Dizin Yapısı

```text
portfolio/hafta_02/gun_012/
├── README.md                                   # Bu bilgilendirme ve kullanım kılavuzu
├── ders.md                                     # 7 bölümlü Usta-Çırak masterclass ders metni
├── soru_cevap.md                               # Soru bankasındaki 3 soruya derin kurumsal yanıtlar
├── rapor.md                                    # 20/40/25/15 puanlama ve doğrulama raporu
├── sonuc.json                                  # 14 zorunlu standart alanı içeren makine-okunabilir özet
├── manifest.json                               # Kriptografik SHA-256 dosya bütünlük indeks tablosu
├── uygulama/
│   └── vm_snapshot_backup_manager.py           # Snapshot, yedekleme ve denetim CLI aracı
├── tests/
│   └── test_vm_snapshot_backup_manager.py      # 14 birim testten oluşan kapsamlı doğrulama paketi
├── ornek_veri/
│   ├── vm_lab_envanteri.json                   # Sentetik sanal makineler ve snapshot zinciri envanteri
│   └── restore_drill_policy.json               # Geri dönüş tatbikatı ve WORM politikası
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                  # Gerçek CLI yürütme çıktıları ve ortam bilgisi
    │   └── test_sonuclari.txt                  # 14/14 unittest başarı çıktısı
    └── temsili/
        └── snapshot_ve_yedek_mimarisi.txt      # Etiketli temsilî ASCII mimari şeması
```

---

## 🚀 Çalıştırma ve Test Rehberi

### 1. Ortam Gereksinimleri
- Python 3.10+ (Standart Kütüphane: `hashlib`, `json`, `os`, `sys`, `argparse`, `datetime`, `unittest`)
- Harici üçüncü taraf bağımlılığı yoktur.

### 2. Güvenlik Denetimini Çalıştırma
```bash
# Tüm laboratuvar sanal makinelerini denetle
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json

# VM-SEC-WIN-01 için derinlemesine risk analizi yap
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --denetle
```

### 3. Snapshot Alma ve Rollback İcrası
```bash
# Yeni bir analiz kontrol noktası snapshot'ı al
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --snapshot-al "Pre_Infection_Point"

# Test tamamlandıktan sonra altın duruma geri dön
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --rollback SNAP-WIN-01
```

### 4. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_012/tests/test_vm_snapshot_backup_manager.py -v
```

---

## 🛡️ Güvenlik ve Etik Sınırlar

- Bu depodaki tüm veriler sentetiktir; hiçbir gerçek kullanıcı veya kurumsal veri içermez.
- Fidye yazılımı (ransomware) ve VSS gölge kopya silme anlatımları yalnızca savunma mekanizmalarının ve olay günlüğü tespit kurallarının anlaşılması amacıyla sunulmuştur.
- Üretim ortamlarında test edilmeden doğrudan komut çalıştırılmamalıdır.
