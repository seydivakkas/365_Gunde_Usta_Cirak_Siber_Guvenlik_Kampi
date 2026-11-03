# Gün 049: Mini Proje 6 — Ağ Adresleme Çalışma Kitabı ve Güvenlik Denetimi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 07, Gün 049 (Haftalık Mini Proje 6) çalışmasıdır.

---

## 📋 Proje Özeti

Katman-2 (MAC/VLAN/ARP) ve Katman-3 (IPv4/IPv6/CIDR/ICMP) protokollerini bütünsel bir ağ denetim motorunda birleştiren; çoklu alt ağ (VLSM/CIDR) matematiğini, IP-MAC-Gateway-DNS parametre tutarlılığını ve ağ mimarisi güvenlik açıklarını (çakışan alt ağlar, geçersiz ağ geçitleri, kullanılamaz IP atamaları, EUI-64 MAC gizlilik sızıntıları) otomatik olarak analiz eden kapsamlı bir ağ çalışma kitabı ve denetim aracıdır.

### Temel Özellikler
- **Matematiksel Alt Ağ Hesaplayıcıları:**
  - `IPv4SubnetCalculator`: Bit düzeyinde ağ maskesi, joker maske, ağ adresi, yayın adresi, kullanılabilir host aralığı ve toplam/kullanılabilir adres hesabı.
  - RFC 3021 /31 nokta-nokta ağ kuralı ve /32 tekil host istisnası desteği.
  - `IPv6SubnetCalculator`: IPv6 CIDR adresleme ve EUI-64 MAC adresi sızıntısı analizi.
- **Topoloji ve Çalışma Kitabı Yönetimi:** Çoklu VLAN (Yönetim, DMZ, İstemciler /23, Misafir) ve uç nokta cihaz envanterini JSON üzerinden yükleme ve yönetme.
- **Güvenlik ve Çakışma Denetim Motoru:**
  - `CAKISAN_ALT_AG`: Çakışan alt ağ aralıklarını tespit ederek asimetrik yönlendirme risklerini önleme.
  - `GECERSIZ_AG_GECIDI`: Kendi alt ağ sınırları dışındaki geçersiz ağ geçitlerini yakalama.
  - `KULLANILAMAZ_IP_ATAMASI`: Uç noktalara atanmış Network ID (.0) veya Broadcast (.255) adreslerini engelleme.
  - `IP_CAKISMASI` & `MAC_CAKISMASI`: Duplicate çakışmaları ve ARP flap risklerini tespit etme.
  - `IPV6_EUI64_GIZLILIK_SIZINTISI`: Donanım MAC adresinin IPv6 içinde ifşa edilmesini denetleme.
- **Otomatik Raporlama:** Tüm analiz bulgularını ve topoloji tablolarını profesyonel Markdown raporu olarak dışa aktarma.
- **Satır Satır Açıklamalı Kod:** Uygulama ve test kodlarının tamamı didaktik açıklamalarla zenginleştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_07/gun_049/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış mini proje dersi
├── soru_cevap.md                                # Soru bankası (G049-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── network_addressing_workbook.py           # Ağ çalışma kitabı ve güvenlik denetim motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_network_addressing_workbook.py      # 14 birim testi ve güvenlik doğrulamaları
├── ornek_veri/
│   ├── sample_topology_workbook.json            # 4 alt ağ, 8 cihaz ve 5 enjekte edilen test senaryosu
│   └── invalid_topology_inputs.json             # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── ag_adresleme_calisma_kitabi_raporu.txt # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── ag_adresleme_ve_segmentasyon_topolojisi.txt # Çoklu VLAN ve denetim mimari şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Ağ Çalışma Kitabı ve Denetim Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_049/uygulama/network_addressing_workbook.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_07/gun_049/tests/test_network_addressing_workbook.py -v
```

---

## 🔒 Lisans Kuralı

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
