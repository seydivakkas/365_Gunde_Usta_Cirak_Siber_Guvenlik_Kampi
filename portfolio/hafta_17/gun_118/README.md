# Hafta 17 / Gün 118: En Az Ayrıcalık (PoLP) ve Sıfır Güven (Zero Trust) Referans Güvenlik Motoru

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: NIST SP 800-207](https://img.shields.io/badge/standard-NIST_SP_800--207_Zero_Trust-green.svg?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![Test Durumu: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15_PASS-brightgreen.svg?style=flat-square)](tests/)
[![Puan: 100/100](https://img.shields.io/badge/score-100%2F100_YETERLİ-success.svg?style=flat-square)](rapor.md)

---

## 🔒 Lisans Bildirimi

```text
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

## 📌 Proje Genel Bakışı

Bu proje, modern siber güvenlik altyapılarında **En Az Ayrıcalık İlkesi (Principle of Least Privilege — PoLP)** ve **NIST SP 800-207 Sıfır Güven Mimarisi (Zero Trust Architecture — ZTA)** prensiplerini saf Python standart kütüphanesi ile hayata geçiren referans güvenlik motorudur.

Sistem şu temel güvenlik bileşenlerini ve mekanizmalarını içerir:
1. **Sıfır Kalıcı Ayrıcalık (Zero Standing Privileges - ZSP):** Kalıcı `root` veya `admin` rollerinin kaldırılması (CWE-250 engeli).
2. **Just-In-Time (JIT) Geçici Yetkilendirme:** Görev odaklı, kısıtlı süreli (TTL 15-60 dk) ve onay mekanizmalı dinamik yetki tahsisi (CWE-272 & CWE-613).
3. **Uç Nokta Cihaz Sağlığı (Device Posture Assessment):** MDM yönetimi, EDR/antivirüs durumu, BitLocker disk şifreleme ve yama gecikmesi kontrolleri (CWE-284).
4. **Sürekli Dinamik Güven Skoru (Continuous Dynamic Trust Scoring):** Uç nokta sağlığı (%50) ve kimlik gücü (%50) ile anlık hesaplanan, şüpheli anomalilerde puan kıran dinamik değerlendirici.
5. **Ağ Mikro-Segmentasyonu:** Ağ sınırlarının servis bazında izole edilmesi ve Yanal Hareketin (Lateral Movement — CWE-284) engellenmesi.
6. **Kritik İşlemlerde Step-Up MFA:** Yüksek riskli kaynaklara erişimde anlık ikinci faktör doğrulama zorunluluğu (CWE-308).
7. **Yapılandırılmış Denetim İzi (Structured JSON Audit Trail):** Tüm erişim talepleri için tekil UUID takipli ve gerekçelendirilmiş güvenlik kayıtları.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-250** | Execution with Unnecessary Privileges (Standing Privileges) | Kalıcı root/admin ve sınırsız yetki taleplerinin kesin yasağı (ZSP) |
| **CWE-272** | Least Privilege Violation (Aşırı Kapsam Talebi) | Onaylı JIT kataloğu dışındaki yetki taleplerinin PEP'te reddedilmesi |
| **CWE-613** | Insufficient Session Expiration (Süresi Dolan JIT) | Kısıtlı TTL (15-60 dk) süresi aşılmış geçici yetki iptali |
| **CWE-284** | Improper Access Control (Uç Nokta Posture Zafiyeti) | BYOD, yamasız veya antivirüsü kapalı cihazların PEP kapısında engellenmesi |
| **CWE-284** | Improper Access Control (Yanal Hareket / Lateral Movement) | Mikro-segmentasyon kuralları ile izole ağ geçişlerinin durdurulması |
| **CWE-284** | Improper Access Control (Dinamik Güven Skoru Düşüşü) | Şüpheli anomalilerde güven puanının kırılarak erişimin kesilmesi |
| **CWE-308** | Use of Single-factor Authentication (Eksik Step-Up MFA) | Yüksek riskli kaynaklarda anlık Step-Up MFA zorunluluğu |
| **CWE-613** | Insufficient Session Expiration (Manuel İptal Edilen JIT) | Manuel iptal edilen JIT yetkisinin anında hükümsüz kılınması |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_118/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── least_privilege_zero_trust_engine.py # PoLP, ZSP, JIT, Posture ve Sıfır Güven motoru
│   └── zero_trust_cli.py          # Uç nokta sağlığı, JIT ve erişim değerlendirme CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_least_privilege_zero_trust.py   # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── zero_trust_policies.json   # Kurumsal JIT kataloğu, cihaz sağlık ağırlıkları ve politikalar
│   └── invalid_zero_trust_requests.json     # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── zero_trust_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── zero_trust_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Kanıt Üretici ve Doğrulama Koşturma
```powershell
python kanit_uretici.py
```

### 3. CLI ile Sıfır Güven Değerlendirmesi
```powershell
# Başarılı Sıfır Güven Erişimi (Sağlıklı Cihaz, Jumpbox Segmenti, MFA, JIT)
python uygulama/zero_trust_cli.py eval --user-id "lead_admin" --segment "management_jumpbox" --mfa --jit-scope "db:maintenance_backup" --resource-id "res_core_db" --target-segment "core_banking" --step-up --min-trust 75.0

# Kalıcı Yetki Yasağı Testi (CWE-250)
python uygulama/zero_trust_cli.py eval --user-id "intruder" --jit-scope "*:*" --resource-id "res_core_db"

# Yanal Hareket Engelleme Testi (CWE-284)
python uygulama/zero_trust_cli.py eval --user-id "wifi_guest" --segment "guest_wifi" --resource-id "res_core_db" --target-segment "core_banking"
```
