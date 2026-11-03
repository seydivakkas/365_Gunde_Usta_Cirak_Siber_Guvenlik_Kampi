# GÜN 123: Güvenli Varsayılanlar (Secure by Default) ve Fail-Safe Mimarisi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Day: 123/365](https://img.shields.io/badge/G%C3%BCn-123%2F365-blue?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/Status-100%2F100%20PASS-brightgreen?style=flat-square)

---

## ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

**YASAKLAR:**
1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
3. Alt lisanslanamaz, satılamaz veya devredilemez.
4. Tersine mühendislik yapılamaz.

**İZİN VERİLEN KULLANIM:**
- GitHub üzerinde görüntüleme ve okuma.
- Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.  
İzin talepleri için: GitHub @seydivakkas

---

## Proje Genel Bakışı

Bu proje, Saltzer ve Schroeder'in 1975 tarihli klasik güvenlik tasarım ilkeleri ile CISA "Secure by Design & Secure by Default" standartlarına tam uyumlu olarak geliştirilmiş saf Python standardında bir **Güvenli Varsayılanlar (Default-Deny) ve Fail-Safe / Fail-Secure Karar Motoru**dur.

Sistem; kaynak konfigürasyonlarını CWE-1188 (Insecure Default Initialization) zaafiyetine karşı (debug modu, varsayılan parolalar, permissive CORS, şifresiz iletişim ve depolama) otomatik denetler; erişim taleplerinde açık kural eşleşmediğinde Saltzer-Schroeder Default-Deny kuralını işletir; veritabanı kesintisi, zaman aşımı ve beklenmeyen istisnalar gibi arıza anlarında erişimi anında kesen **Fail-Secure (Fail-Closed)** mekanizmasını uygulayarak CWE-636 zafiyetini engeller.

---

## Dizin Yapısı

```
portfolio/hafta_18/gun_123/
├── uygulama/
│   ├── __init__.py
│   ├── secure_defaults_failsafe_engine.py # Çekirdek Fail-Safe ve varsayılanlar motoru
│   └── failsafe_cli.py                    # Komut satırı denetim ve erişim test aracı
├── tests/
│   ├── __init__.py
│   └── test_secure_defaults_failsafe.py   # 15/15 birim test (%100 PASS)
├── ornek_veri/
│   ├── system_failsafe_config.json        # Kurumsal güvenli mimari yapılandırması
│   └── invalid_failsafe_scenarios.json    # 9 negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── failsafe_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── failsafe_mimarisi.txt          # ASCII mimari illüstrasyonu
├── kanit_uretici.py                       # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                                # Usta-Çırak interaktif ders anlatımı
├── soru_cevap.md                          # 3 derin teknik soru ve çözüm analizi
├── rapor.md                               # 100/100 tam puan değerlendirme karnesi
├── sonuc.json                             # Puan ve yeterlilik doğrulama dosyası
├── manifest.json                          # Dosya bütünlüğü ve SHA256 özetleri
└── README.md                              # Dokümantasyon ve lisans bildirimi
```

---

## Çalıştırma ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_secure_defaults_failsafe.py
```

### 2. CLI ile Güvenli Varsayılanları Denetleme
```bash
# Yapılandırmayı denetle ve konsol özetini gör
python uygulama/failsafe_cli.py audit ornek_veri/system_failsafe_config.json

# Markdown formatında yönetici raporu üret
python uygulama/failsafe_cli.py audit ornek_veri/system_failsafe_config.json --format markdown
```

### 3. Erişim Talebi Değerlendirme ve Arıza Testi
```bash
# Normal yetkili talep (İzin Verilir)
python uygulama/failsafe_cli.py evaluate ornek_veri/system_failsafe_config.json --role admin --resource-id RES-AUTH-API --action manage

# Veritabanı çökmesi simülasyonu (Fail-Secure Devreye Girer -> RED)
python uygulama/failsafe_cli.py evaluate ornek_veri/system_failsafe_config.json --role admin --resource-id RES-AUTH-API --action manage --simulate-failure DATABASE_DOWN
```

### 4. Tüm Kanıtları Yeniden Üretme
```bash
python kanit_uretici.py
```
