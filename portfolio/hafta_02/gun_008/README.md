# GÜN 008: Sanallaştırmanın Güvenlikteki Rolü (Hypervisor İzolasyonu, VM Escape ve Sertleştirme)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, Siber Güvenlik 365 Gün Müfredatının **2. Hafta açılış günüdür (GÜN 008)**. Sanallaştırma katmanının (Intel VT-x/AMD-V, Ring -1 VMM, Tip-1 vs Tip-2 hypervisor) siber güvenlikteki koruyucu rolünü, zararlı yazılım analizinde BSL-4 eldivenli cam kabin analojisiyle ele alır.

Sanal makineden konak sisteme sıçrama (**VM Escape**), yerel ağa yayılma (**Lateral Movement**) ve zararlı yazılımların sanal ortamı fark ederek uyku moduna geçmesi (**Anti-VM Evasion**) mekanizmaları derinlemesine incelenmiş; CIS ve BSI standartlarında sanal makine yapılandırma profillerini denetleyen **VM Security Auditor** aracı geliştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_02/gun_008/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar (G008-SC1, SC2, SC3)
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── vm_security_auditor.py       # Zengin açıklamalı Sanal Makine Güvenlik Denetleyicisi CLI motoru
├── tests/
│   └── test_vm_security_auditor.py  # 12 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   └── vm_guvenlik_profili.json     # 3 farklı senaryoya ait VM güvenlik profilleri
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 12/12 unittest başarı kaydı
    └── temsili/
        └── sanallastirma_guvenlik_mimarisi.txt # ASCII formatında hypervisor ve VM Escape şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. Sanal Makine Güvenlik Profillerini Denetleme (CLI)
```bash
python portfolio/hafta_02/gun_008/uygulama/vm_security_auditor.py --profile portfolio/hafta_02/gun_008/ornek_veri/vm_guvenlik_profili.json
```

Yalnızca belirli bir VM profilini filtrelemek için:
```bash
python portfolio/hafta_02/gun_008/uygulama/vm_security_auditor.py --profile portfolio/hafta_02/gun_008/ornek_veri/vm_guvenlik_profili.json --vm-id VM-SEC-01
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_02/gun_008/uygulama/vm_security_auditor.py --profile portfolio/hafta_02/gun_008/ornek_veri/vm_guvenlik_profili.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_008/tests/test_vm_security_auditor.py -v
```

---

## 🛡️ Lisans ve Kullanım Şartları

Bu proje ve ilgili tüm dosyalar **Seydi Eryılmaz (@seydivakkas)** adına tescilli olup tüm hakları saklıdır. Hiçbir açık kaynak lisansına (MIT, Apache, GPL vb.) tabi değildir. Ticari veya gayriticari olarak kopyalanamaz, paylaşılamaz, türetilemez.
