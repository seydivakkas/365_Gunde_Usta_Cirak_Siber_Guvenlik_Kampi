# Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

İnternet bağlantısı olmayan izole SCADA/ICS altyapılarında, banka HSM odalarında ve kritik askeri ağlarda sıfır dış bağımlılıkla (Pure Standard Library) çalışan modüler siber güvenlik araç seti.

---

## 🛡️ Yetenekler ve Güvenlik Mimarisi

- **Sıfır Dış Bağımlılık (Pure Python Standard Library):** `pip`, `apt` veya harici derlenmiş C kütüphanelerine ihtiyaç duymaz; yalnızca CPython standart kütüphanesini kullanır.
- **Air-Gap Doctor (`sec_toolkit doctor`):** Ortamda yetkisiz harici paketlerin bulunmadığını, Python sürüm uyumluluğunu ve çevresel izolasyonu doğrular.
- **Ağ Varlığı ve Tip Güvenliği (`sec_toolkit validate`):** IPv4 (Octal IP CWE-704 korumalı), Port ([1, 65535] CWE-1284/843), MAC (EUI-48) ve Hostname doğrulaması.
- **Kriptografik Bütünlük ve FIM (`sec_toolkit hash / fim`):**
  - 64 KB parçalı akışla bellek tasarruflu SHA-256 / SHA-512 özetleme.
  - Zamanlama saldırılarına dirençli `hmac.compare_digest` doğrulaması (CWE-208).
  - Dizin kriptografik taban çizgisi oluşturma ve yetkisiz değişiklik (`MODIFIED`), ekleme (`ADDED`), silme (`REMOVED`) tespiti.
- **DLP Kişisel Veri Maskeleme (`sec_toolkit mask`):** TCKN (10/11 kuralı), Kredi Kartı (Luhn Mod-10), E-Posta ve token maskelemesi. ReDoS (CWE-1333) ve Null-Byte (CWE-158) koruması.
- **Performans ve SLA Denetimi (`sec_toolkit bench`):** `time.perf_counter` ve `tracemalloc` ile süre ve bellek profillemesi, SLA bütçe aşım kalkanı (CWE-400).
- **POSIX Standart Çıkış Kodları:** `0` (Başarılı / Temiz), `1` (Güvenlik / Bütünlük / SLA İhlali), `2` (Girdi / Parametre Hatası).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_097/
├── uygulama/
│   ├── __init__.py
│   ├── offline_security_toolkit.py      # Çekirdek modüler güvenlik motoru
│   └── sec_toolkit_cli.py               # Alt komutlu terminal CLI yürütücüsü
├── tests/
│   ├── __init__.py
│   └── test_offline_security_toolkit.py # 14/14 birim test seti
├── ornek_veri/
│   ├── airgap_test_env/                 # İzole test ortamı
│   │   ├── assets.json                  # Ağ varlıkları şeması
│   │   ├── sensitive_traffic.log        # Hassas telemetri kütüğü
│   │   └── system_conf.ini              # FIM ile izlenen sistem ayarları
│   └── invalid_toolkit_inputs.json      # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                          # Doğrulanmış test ve denetim çıktıları
│   │   ├── cevrimdisi_arac_seti_raporu.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── test_sonuclari.txt
│   └── temsili/                         # Kapsamlı mimari ASCII görselleştirmesi
│       └── cevrimdisi_arac_seti_mimarisi.txt
├── ders.md                              # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                        # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                             # 100/100 rubrik değerlendirme raporu
├── sonuc.json                           # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                     # Otomatik test ve kanıt üretim orkestratörü
├── manifest.json                        # Dosya bütünlük manifestosu
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Kanıt üreticiyi çalıştır
python kanit_uretici.py

# Birim testleri doğrudan koştur
python -m unittest tests/test_offline_security_toolkit.py -v

# Hava boşluklu ortam hazır bulunuşluk taraması
python uygulama/sec_toolkit_cli.py doctor

# Dosya bütünlük hash'i üret
python uygulama/sec_toolkit_cli.py hash --file ornek_veri/airgap_test_env/system_conf.ini --algo sha256

# Hassas log maskeleme
python uygulama/sec_toolkit_cli.py mask --file ornek_veri/airgap_test_env/sensitive_traffic.log --style MASK
```

---

## 📜 Lisans

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
