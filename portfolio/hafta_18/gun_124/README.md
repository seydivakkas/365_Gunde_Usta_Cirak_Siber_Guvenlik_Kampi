# GÜN 124: Secrets Yönetimi ve Çevre Değişkenleri

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Day: 124/365](https://img.shields.io/badge/G%C3%BCn-124%2F365-blue?style=flat-square)
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

Bu proje, NIST SP 800-57 anahtar yönetimi direktifleri ve CISA standartlarına tam uyumlu olarak geliştirilmiş saf Python standardında bir **Kurumsal Secrets Kasası (Secret Vault), CWE-798 Hardcoded Secret Tarayıcısı ve CWE-532 Log Maskeleme Motoru**dur.

Sistem; gizli anahtarları (API tokenları, veritabanı şifreleri, JWT sırları) zarflı şifreleme (Envelope Encryption - PBKDF2 ve HMAC-SHA256) ile korur; rol bazlı en az yetki erişimi (PoLP - CWE-285) sağlar; süre aşımı (TTL - CWE-613) ve dinamik anahtar rotasyonu işletir; kaynak kodlardaki sızıntıları hem imza regex kalıpları hem de Shannon Entropi hesaplaması ile tespit eder (CWE-798); log kayıtlarına sızabilecek hassas verileri otomatik maskeler (CWE-532).

---

## Dizin Yapısı

```
portfolio/hafta_18/gun_124/
├── uygulama/
│   ├── __init__.py
│   ├── secrets_management_engine.py  # Çekirdek Vault, zarflı şifreleme ve tarayıcı motoru
│   └── secrets_cli.py                # Komut satırı kasa, tarama ve maskeleme aracı
├── tests/
│   ├── __init__.py
│   └── test_secrets_management.py    # 15/15 birim test (%100 PASS)
├── ornek_veri/
│   ├── vault_sample_config.json      # Örnek kurumsal kasa yapılandırması
│   └── invalid_secrets_scenarios.json # 9 negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── secrets_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── secrets_mimarisi.txt      # ASCII mimari illüstrasyonu
├── kanit_uretici.py                  # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                           # Usta-Çırak interaktif ders anlatımı
├── soru_cevap.md                     # 3 derin teknik soru ve çözüm analizi
├── rapor.md                          # 100/100 tam puan değerlendirme karnesi
├── sonuc.json                        # Puan ve yeterlilik doğrulama dosyası
├── manifest.json                     # Dosya bütünlüğü ve SHA256 özetleri
└── README.md                         # Dokümantasyon ve lisans bildirimi
```

---

## Çalıştırma ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_secrets_management.py
```

### 2. Kasa Raporu ve Secret Okuma
```bash
# Kasa envanteri ve durum raporu üret
python uygulama/secrets_cli.py vault ornek_veri/vault_sample_config.json --action report

# Yetkili rol ile gizli anahtarı oku
python uygulama/secrets_cli.py vault ornek_veri/vault_sample_config.json --action get --secret-id SEC-PROD-DB-01 --role backend_prod_service
```

### 3. Kaynak Kodda Hardcoded Secret Taraması (CWE-798)
```bash
# Dosya veya metin taraması yap
python uygulama/secrets_cli.py scan "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"

# Entropi eşiği belirterek tara
python uygulama/secrets_cli.py scan "SECRET = 'k9#vL2$mP8@zX4!qN7%yR1^wT5*'" --entropy 4.0
```

### 4. Log Maskeleme Testi (CWE-532)
```bash
python uygulama/secrets_cli.py mask ornek_veri/vault_sample_config.json "Bağlantı hatası: sk_test_51NyAbcDefGhiJklMnoPqrStuv kullanıldı."
```

### 5. Tüm Kanıtları Yeniden Üretme
```bash
python kanit_uretici.py
```
