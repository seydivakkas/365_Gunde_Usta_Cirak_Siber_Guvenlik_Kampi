# GÜN 013: Güvenli Araştırma ve Kaynak Doğrulama

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

Bu çalışma; siber güvenlik zafiyet analizlerinde, tehdit istihbaratı toplamada ve sistem sertleştirme süreçlerinde kullanılan bilgi kaynaklarının bilimsel CRAAP çerçevesiyle filtrelenmesini, zehirli Truva Atı (Trojanized PoC) tuzaklarının tespit edilmesini ve aynı konunun en az iki bağımsız kaynaktan çapraz teyit (triangulation) edilmesini ele alır.

### Temel Kazanımlar:
1. **İstihbarat ve Kaynak Güvenilirlik Piramidi:** Birincil resmî kaynaklar (NVD, MSRC), hakemli lablar, saygın konferanslar ve doğrulanmamış forumlar arasındaki hiyerarşi.
2. **CRAAP Modeli Uygulaması:** Currency (Güncellik), Relevance (İlgililik), Authority (Otorite), Accuracy (Doğruluk), Purpose (Amaç) kriterleriyle puanlama.
3. **Zehirli İstismar Kodu (Trojanized PoC) Tespiti:** Gizlenmiş (Base64) `curl | sh` yüklerinin tespiti ve Lazarus APT vakası analizi.
4. **Yıkıcı Tavsiye Engelleme:** Eski forumlardaki `chmod 777` veya `verify=False` gibi sistemi savunmasız kılan önerilerin elenmesi.
5. **Kriptografik Bütünlük:** GPG imza ve SHA-256 sağlama doğrulamaları.

---

## 📂 Dizin Yapısı

```text
portfolio/hafta_02/gun_013/
├── README.md                                   # Bu bilgilendirme ve kullanım kılavuzu
├── ders.md                                     # 7 bölümlü Usta-Çırak masterclass ders metni
├── soru_cevap.md                               # Soru bankasındaki 3 soruya derin kurumsal yanıtlar
├── rapor.md                                    # 20/40/25/15 puanlama ve doğrulama raporu
├── sonuc.json                                  # 14 zorunlu standart alanı içeren makine-okunabilir özet
├── manifest.json                               # Kriptografik SHA-256 dosya bütünlük indeks tablosu
├── uygulama/
│   └── security_source_validator.py            # Kaynak doğrulama ve CRAAP puanlama CLI motoru
├── tests/
│   └── test_security_source_validator.py       # 14 birim testten oluşan kapsamlı doğrulama paketi
├── ornek_veri/
│   ├── guvenlik_arastirma_kaynaklari.json      # Resmî ve zehirli kaynakları içeren sentetik araştırma veritabanı
│   └── craap_dogrulama_kriterleri.json         # CRAAP puanlama ve ret eşikleri standartları
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                  # Gerçek CLI yürütme çıktıları ve ortam bilgisi
    │   └── test_sonuclari.txt                  # 14/14 unittest başarı çıktısı
    └── temsili/
        └── guvenli_arastirma_ve_kaynak_hiyerarsisi.txt # Etiketli temsilî ASCII mimari şeması
```

---

## 🚀 Çalıştırma ve Test Rehberi

### 1. Ortam Gereksinimleri
- Python 3.10+ (Standart Kütüphane: `os`, `sys`, `json`, `argparse`, `datetime`, `unittest`)
- Harici üçüncü taraf bağımlılığı yoktur.

### 2. Çapraz Kaynak Teyidini Çalıştırma
```bash
# Tüm araştırma vakalarını analiz et
python portfolio/hafta_02/gun_013/uygulama/security_source_validator.py --veri-tabani portfolio/hafta_02/gun_013/ornek_veri/guvenlik_arastirma_kaynaklari.json --tumunu-denetle

# RCE zaafiyeti için NVD vs Sahte GitHub PoC çapraz karşılaştırması
python portfolio/hafta_02/gun_013/uygulama/security_source_validator.py --veri-tabani portfolio/hafta_02/gun_013/ornek_veri/guvenlik_arastirma_kaynaklari.json --vaka-id VAKA-CVE-RCE-01 --karsilastir
```

### 3. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_013/tests/test_security_source_validator.py -v
```

---

## 🛡️ Güvenlik ve Etik Sınırlar

- Bu depodaki tüm veriler sentetiktir; hiçbir gerçek saldırı kodu veya kurumsal kimlik bilgisi barındırmaz.
- Trojanized PoC ve sahte istismar analizi tamamen savunma bilincini artırmak ve araştırmacıların kendi kendilerini hacklemesini önlemek amacıyla yerel sandbox seviyesinde modellenmiştir.
- Üretim sistemlerinde doğrulanmamış hiçbir üçüncü taraf betik çalıştırılmamalıdır.
