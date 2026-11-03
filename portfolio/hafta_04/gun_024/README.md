# Gün 024: Linux Dosya İzinleri (RWX) ve Geri Alma Mimarisi

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20POSIX-blue)
![Security Standard](https://img.shields.io/badge/standard-CIS%20Benchmark%20%7C%20NIST%20800--53-orange)
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

Bu çalışma, 365 Günlük Siber Güvenlik Müfredatı kapsamında **Aşama 02 / Hafta 04 / Gün 024** ("Linux dosya izinleri rwx") modülü için geliştirilmiştir.

Modülün temel amacı; Linux İsteğe Bağlı Erişim Denetimi (DAC) kapsamında Kullanıcı (`u`), Grup (`g`) ve Diğerleri (`o`) katmanlarının okuma (`r=4`), yazma (`w=2`), çalıştırma (`x=1`) bitlerini, SUID (`4000`), SGID (`2000`) ve Sticky (`1000`) bitlerini, matematiksel umask projeksiyonunu, CWE-732 world-writable güvenlik açıklarını ve yapılan izin değişikliklerinin bir denetim günlüğü (journal) aracılığıyla atomik biçimde geri alınmasını (rollback) pratik ve teorik olarak öğretmektir.

---

## Proje Yapısı

```
portfolio/hafta_04/gun_024/
│
├── uygulama/
│   ├── __init__.py
│   └── linux_permission_rwx_auditor.py   # Denetim, umask ve geri alma motoru
│
├── tests/
│   ├── __init__.py
│   └── test_linux_permission_rwx_auditor.py  # 14 birim test
│
├── ornek_veri/
│   ├── permission_baseline_rules.json    # CIS/NIST tabanlı izin politikaları
│   ├── sample_files_permissions.json     # Taranan sistem envanteri
│   ├── lab_test_dosyasi.txt              # G024-SC2 kontrollü deney dosyası
│   └── chmod_journal.json                # Geri alma (rollback) işlem günlüğü
│
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # 14/14 test pass çıktısı
│   │   ├── chmod_degisiklik_ve_geri_alma_kaydi.txt # SC2 deney kaydı
│   │   └── komut_ve_cikis.txt            # CLI çalışma çıktıları
│   └── temsili/
│       └── linux_izin_rwx_mimarisi.txt   # Temsili mimari şema
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
python -m unittest discover -s portfolio/hafta_04/gun_024/tests -p "test_*.py" -v
```

### 2. İzin Dönüştürme (Oktal <-> Sembolik)
```bash
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --convert 0755
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --convert rwxr-xr-x
```

### 3. Umask Hesaplama ve Güvenlik Değerlendirmesi
```bash
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --umask 027
```

### 4. Sistem Envanteri Güvenlik Denetimi
```bash
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --audit
```

### 5. Kontrollü İzin Değiştirme ve Geri Alma (Rollback - G024-SC2)
```bash
# Değişiklik yap ve günlüğe kaydet
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --modify hedef_dosya.txt 0600

# Yapılan değişikliği orijinal iznine geri al
python portfolio/hafta_04/gun_024/uygulama/linux_permission_rwx_auditor.py --rollback --target-file hedef_dosya.txt
```
