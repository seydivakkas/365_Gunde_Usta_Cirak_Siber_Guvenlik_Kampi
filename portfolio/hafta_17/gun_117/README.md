# Hafta 17 / Gün 117: RBAC ve ABAC Hibrit Kurumsal Erişim Kontrol Motoru

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: NIST ANSI 359 & SP 800-162](https://img.shields.io/badge/standard-NIST_RBAC_%26_ABAC-green.svg?style=flat-square)](https://csrc.nist.gov/)
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

Bu proje, kurumsal bilgi sistemlerinde, bulut mimarilerinde ve mikroservis API Gateway'lerinde kullanılan **Rol Tabanlı Erişim Kontrolü (RBAC — NIST ANSI/INCITS 359-2004)** ile **Öznitelik Tabanlı Erişim Kontrolünü (ABAC — NIST SP 800-162)** hibrit bir orkestrasyonda buluşturan referans güvenlik motorudur.

Sistem şu ana güvenlik bileşenlerini ve mekanizmalarını içerir:
1. **NIST Seviye 2 Hiyerarşik RBAC:** Rol hiyerarşisi üzerinden miras alınan izinlerin (`Admin > Manager > Staff > User`) özyineli çözümlenmesi.
2. **Statik Görevler Ayrılığı (SSD / SoD - CWE-863):** Satın alma emri açan ile faturayı onaylayan personelin aynı kişi olmasını engelleyen kural motoru.
3. **NIST SP 800-162 Uyumlu ABAC Motoru:** Özne (Subject), Kaynak (Resource), Eylem (Action) ve Çevre (Environment) özniteliklerini 'Deny-Overrides' mantığıyla değerlendiren politika denetleyicisi.
4. **Çok Kiracılı (Multi-Tenant) İzolasyon (CWE-284):** Çapraz kiracı erişim girişimlerinin katı sınır denetimiyle engellenmesi.
5. **Departman İzolasyonu ve IDOR Savunması (CWE-639):** Farklı departmanların gizli verilerine yetkisiz erişimlerin önlenmesi (denetçi istisnası hariç).
6. **Bağlamsal Güvenlik (Contextual Constraints):** Mesai saatleri dışı kritik finansal yazma kısıtlaması, güvenli IP CIDR denetimi ve dinamik risk puanı değerlendirmesi.
7. **Yapılandırılmış Denetim İzi (JSON Audit Trail):** Her erişim isteği için tekil UUID takipli, gerekçelendirilmiş güvenlik kayıtları.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-862** | Missing Authorization (Rol Yetki Eksikliği) | RBAC hiyerarşik izin denetimi ve Fail-Closed varsayılan ret mantığı |
| **CWE-863** | Incorrect Authorization (SoD & Toksik Kombinasyon) | Statik Görevler Ayrılığı (SSD) kural denetimi (`purchaser` vs `approver`) |
| **CWE-284** | Improper Access Control (Multi-Tenant İzolasyon) | Özne ve kaynak `tenant_id` katı eşitlik teyidi |
| **CWE-285** | Improper Authorization (Insufficient Clearance) | Çok seviyeli gizlilik (`Clearance >= Classification`) doğrulaması |
| **CWE-639** | Insecure Direct Object Reference (IDOR) | Departman sahipliği ve yetkisiz yatay veri erişim engeli |
| **CWE-863** | Incorrect Authorization (Kilitli Kaynak Değişikliği) | Arşivlenmiş/kilitli kayıtlarda yazma/silme engeli |
| **CWE-308** | Use of Single-factor Authentication (Eksik MFA) | Kritik silme (`delete`) işlemlerinde aktif MFA oturumu şartı |
| **CWE-284** | Improper Access Control (Mesai Dışı Finansal Erişim) | Kritik defter kayıtlarında mesai saati dışı yazma kısıtlaması |
| **CWE-284** | Improper Access Control (Ağ ve Risk Puanı Kısıtı) | Güvensiz IP ve yüksek risk skoruna sahip isteklerin reddedilmesi |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_117/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── rbac_abac_engine.py        # RBAC, ABAC ve Hibrit Erişim Motoru
│   └── access_cli.py              # Erişim değerlendirme ve SoD denetim CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_rbac_abac.py          # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── policy_rules.json          # Örnek rol hiyerarşisi, SoD ve ABAC yapılandırması
│   └── invalid_access_requests.json # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── access_control_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── access_control_mimarisi.txt
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

### 3. CLI ile Erişim Değerlendirme ve SoD Denetimi
```powershell
# Başarılı Erişim Talebi (Staff Rolü, IT Departmanı, Clearance 2)
python uygulama/access_cli.py evaluate --user-id "dev_01" --roles "staff" --department "it" --clearance 2 --tenant "tenant_corp" --ip "10.0.1.100" --resource-id "code_repo" --resource-type "project_doc" --owner-dept "it" --classification 2 --action "read"

# Görevler Ayrılığı (SoD) Çatışma Testi
python uygulama/access_cli.py sod-check --roles "purchaser,approver"

# Yetersiz Yetki ve İhlal Senaryosu
python uygulama/access_cli.py evaluate --user-id "guest_user" --roles "user" --department "guest" --resource-id "secret_db" --resource-type "financial_report" --action "write"
```
