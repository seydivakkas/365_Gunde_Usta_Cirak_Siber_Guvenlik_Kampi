# Gün 158: Kurumsal Oturum Yönetimi ve Süresi Güvenlik Sistemi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-7%20Web%20Güvenliği-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-23-orange?style=flat-square)
![Durum](https://img.shields.io/badge/Testler-15%2F15%20PASS-brightgreen?style=flat-square)

Bu modül; web uygulamalarında HTTP oturumlarının tüm yaşam döngüsünü (oluşturma, kriptografik CSPRNG entropisi, boşta kalma ve mutlak zaman aşımları, oturum sabitleme/fixation koruması, yetki yükseltme rotasyonu, eşzamanlı oturum sınırlandırması ve sunucu taraflı iptal mekanizmalarını) **OWASP ASVS** ve **NIST SP 800-63B** standartlarına göre yöneten ve denetleyen üretim kalitesinde bir güvenlik motorudur.

---

## 1. Dizin Yapısı

```
portfolio/hafta_23/gun_158/
├── ders.md                         # Usta-Çırak derin teknik ders notları
├── soru_cevap.md                   # 4 başlıklı 3 adet derinlemesine teknik soru & cevap
├── rapor.md                        # 100/100 PASS başarı karnesi
├── README.md                       # Proje dokümantasyonu ve özel lisans
├── sonuc.json                      # Yapılandırılmış yürütme özeti
├── manifest.json                   # 20 dosyanın SHA-256 doğrulama özeti
├── kanit_uretici.py                # Kanıt üretim ve yürütme orkestrasyon betiği
├── uygulama/
│   ├── __init__.py                 # Python modül tanımlayıcısı
│   ├── session_manager_engine.py   # Oturum yaşam döngüsü ve süre motoru
│   └── session_manager_cli.py      # CLI yönetim arayüzü
├── tests/
│   ├── __init__.py                 # Test paketi tanımlayıcısı
│   └── test_session_manager.py     # 15 kapsamlı birim test
├── ornek_veri/
│   ├── enterprise_session_policy.json # Kurumsal oturum güvenlik politikası şartnamesi
│   └── invalid_session_scenarios.json # 9 adet negatif kontrol ve ihlal senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt      # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif senaryo doğrulama çıktısı
    │   ├── session_lifecycle_report.json # Yaşam döngüsü istatistik raporu
    │   ├── active_sessions_dump.json # Aktif oturumlar bellek dökümü
    │   └── komut_ve_cikis.txt      # CLI yürütme logları
    └── temsili/
        └── oturum_yasam_dongusu.txt # ASCII mimari yaşam döngüsü diyagramı
```

---

## 2. Temel Yetenekler ve Özellikler

1. **Yüksek Entropili Oturum Kimliği:**
   - `secrets.token_hex(32)` ile en az 128 bit (teorik 256 bit) Shannon entropisine sahip, tahmin edilemez belirteçler.
2. **Çift Kademeli Zaman Aşımı (Dual Timeout Architecture):**
   - **Boşta Kalma Zaman Aşımı (Idle Timeout):** 15 dakika boyunca istek gelmezse oturumu sonlandırır.
   - **Mutlak Oturum Ömrü (Absolute Timeout):** Kullanıcı sürekli aktif olsa dahi 8 saat sonunda zorla login ekranına yönlendirir.
3. **Oturum Sabitleme (Session Fixation) ve Rotasyon Kalkanı:**
   - Kullanıcı yetki yükselttiğinde (Privilege Escalation - User -> Admin) veya periyodik aralıklarla (30 dk) oturum kimliğini derhal yeniler; eski kimliği sunucu tarafında iptal eder.
4. **Eşzamanlı Oturum Limiti (Concurrent Session Control):**
   - Kullanıcı başına maksimum 3 oturum sınırı uygular; aşım durumunda FIFO kuralıyla en eski oturumu otomatik kapatır.
5. **Bağlam ve Cihaz Doğrulama (Context Binding):**
   - User-Agent ve IP parmak izi uyuşmazlığında oturumu askıya alarak oturum kaçırma (Session Hijacking) girişimlerini engeller.
6. **Sunucu Taraflı İptal (Server-Side Revocation):**
   - Logout işleminde ve parola sıfırlamada oturumu sunucu önbelleğinden kalıcı olarak temizler.

---

## 3. Kurulum ve Çalıştırma

### Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_23/gun_158/tests/test_session_manager.py -v
```

### Yeni Oturum Açma (CLI):
```bash
python portfolio/hafta_23/gun_158/uygulama/session_manager_cli.py create --user-id usr_01 --username seydi --role Admin
```

### Oturum Doğrulama ve Süre Kontrolü:
```bash
python portfolio/hafta_23/gun_158/uygulama/session_manager_cli.py validate --elapsed-seconds 120
```

### Ayrıcalık Yükseltme ve Rotasyon Simülasyonu:
```bash
python portfolio/hafta_23/gun_158/uygulama/session_manager_cli.py elevate --new-role SuperAdmin
```

### Oturum Politikası ve Yaşam Döngüsü Denetimi:
```bash
python portfolio/hafta_23/gun_158/uygulama/session_manager_cli.py audit --policy-file portfolio/hafta_23/gun_158/ornek_veri/enterprise_session_policy.json
```

### Tüm Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_23/gun_158/kanit_uretici.py
```

---

## 4. Lisans

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
