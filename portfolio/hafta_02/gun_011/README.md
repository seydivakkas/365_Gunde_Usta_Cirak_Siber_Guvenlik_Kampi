# GÜN 011: Laboratuvar Ağ Sınırları (Mikro-Segmentasyon, VLAN İzolasyonu, Statefull Conntrack ve DNS Sinkhole)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, Siber Güvenlik 365 Gün Müfredatının **2. Haftasının 4. günüdür (GÜN 011)**. Laboratuvar ortamlarında kurban makineler (malware analiz ortamı), saldırgan düğümler (Kırmızı Takım / Kali) ve izleme sunucuları (Mavi Takım / SIEM) arasındaki ağ sınırlarını ve sızıntı önleme kalkanlarını inceler.

Denizaltı su geçirmez bölmeleri (Bulkheads) analojisiyle; **Mikro-Segmentasyon (4 Ayrık VLAN)**, durum takipli (**Statefull Conntrack**) asimetrik yönlendirme (tersine kabuk engeli), **DNS Sinkholing** (INetSim / FakeNet yönlendirmesi) ve sıkı çıkış filtrelemesi (**Strict Egress Filtering**) NIST SP 800-115 standartlarında somutlaştırılmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_02/gun_011/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar (G011-SC1, SC2, SC3)
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── lab_network_boundary_auditor.py # Zengin açıklamalı Ağ Sınırları ve İzolasyon Denetim Motoru
├── tests/
│   └── test_lab_network_boundary_auditor.py # 14 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   ├── laboratuvar_ag_topolojisi.json # Mikro-segmente ve güvensiz düz ağ topolojileri
│   └── iptables_rules.sh            # Otomatik üretilen kurumsal iptables kural betiği
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 14/14 unittest başarı kaydı
    └── temsili/
        └── laboratuvar_ag_topolojisi.txt # ASCII formatında mikro-segmentasyon ve DNS sinkhole şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. Laboratuvar Ağ Sınırlarını Denetleme (CLI)
```bash
python portfolio/hafta_02/gun_011/uygulama/lab_network_boundary_auditor.py --topology portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json
```

Yalnızca sertleştirilmiş topolojiyi denetlemek ve kurumsal `iptables_rules.sh` betiği üretmek için:
```bash
python portfolio/hafta_02/gun_011/uygulama/lab_network_boundary_auditor.py --topology portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json --topology-id TOPOLOGY-SEC-01 --generate-iptables portfolio/hafta_02/gun_011/ornek_veri/iptables_rules.sh
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_02/gun_011/uygulama/lab_network_boundary_auditor.py --topology portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_011/tests/test_lab_network_boundary_auditor.py -v
```

---

## 🛡️ Lisans ve Kullanım Şartları

Bu proje ve ilgili tüm dosyalar **Seydi Eryılmaz (@seydivakkas)** adına tescilli olup tüm hakları saklıdır. Hiçbir açık kaynak lisansına (MIT, Apache, GPL vb.) tabi değildir. Ticari veya gayriticari olarak kopyalanamaz, paylaşılamaz, türetilemez.
