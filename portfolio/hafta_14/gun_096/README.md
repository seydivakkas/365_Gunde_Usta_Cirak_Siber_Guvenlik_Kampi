# Gün 096: Güvenli Betik Kullanım Belgeleri ve Dokümantasyon Linter Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik operasyonlarında, DFIR araçlarında ve SOC otomasyon betiklerinde belgelenmemiş gizli parametreleri (CWE-1188 Arka Kapı Engeli), yetki aşımını (CWE-250) ve çıkış kodu uyumsuzluklarını önleyen kurumsal "Documentation as Code" ve statik linter motoru.

---

## 🛡️ Yetenekler ve Güvenlik Mimarisi

- **Tek Doğruluk Kaynaklı Güvenlik Şeması (Security Schema as Code):** Betiğin amacı, en az yetki seviyesi (Least Privilege), tehdit modeli (CWE eşleştirmeleri), parametreleri, çıkış kodları sözlüğü ve kritik güvenlik uyarılarını yapılandırılmış JSON şemasında tanımlar.
- **Statik Dokümantasyon Linter'ı (`SecurityDocLinter`):**
  - Kaynak Python kodundaki tüm `argparse.add_argument()` bayraklarını statik olarak çıkarır.
  - Kodda tanımlı olup belgede yer verilmeyen herhangi bir gizli veya unutulmuş parametreyi tespit ettiğinde `UndocumentedArgumentError` (CWE-1188) fırlatır.
  - Kaynak dosyada kurumsal "Özel Lisans — Tüm Hakları Saklıdır" başlığının varlığını doğrular.
- **Çok Formatlı Belge Üretimi (`DocGenerator`):**
  - **Operatör Kılavuzu (Markdown):** GitHub/GitLab uyumlu, uyarı kutulu (`> [!WARNING]`), parametre ve çıkış kodu tablolarını içeren profesyonel `RUNBOOK.md`.
  - **CLI Yardım Metni (`--help`):** Terminal operatörleri için GNU standartlarına uygun hızlı kullanım rehberi.
  - **Man Sayfası (Unix ROFF):** Linux/Unix sistem entegrasyonu için standart man page formatı.
  - **JSON Telemetrisi:** SOAR ve CI/CD otomasyonları için makine tarafından okunabilir metaveri çıktısı.
- **Gelişmiş Zafiyet Kalkanları:**
  - **CWE-1188:** Belgelenmemiş ve arka kapı olabilecek parametrelerin tam engellenmesi.
  - **CWE-16:** Eksik veya yanlış yapılandırılmış parametre ve çıkış kodu kılavuzlarının tespiti.
  - **CWE-250:** En az yetki prensibi uyarısı ve root engeli denetimi.
  - **CWE-158:** Null-byte (`\x00`) enjeksiyonu koruması.
  - **CWE-400:** 1 MB şema boyut tavanı ile DoS savunması.
- **POSIX Uyumlu CLI (`docgen_cli.py`):** Standart 0 (Başarılı), 1 (Linter İhlali), 2 (Girdi Hatası) çıkış kodları.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_096/
├── uygulama/
│   ├── __init__.py
│   ├── security_doc_generator.py        # Çekirdek şema, jeneratör ve linter motoru
│   └── docgen_cli.py                    # Terminal CLI yürütücüsü
├── tests/
│   ├── __init__.py
│   └── test_security_doc_generator.py   # 14/14 birim test seti
├── ornek_veri/
│   ├── sample_security_script.py        # Denetlenen örnek güvenlik betiği
│   ├── script_security_schema.json      # Yapılandırılmış güvenlik belgeleme şeması
│   └── invalid_doc_inputs.json          # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                          # Doğrulanmış test ve denetim çıktıları
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── ornek_betik_kilavuzu.md
│   │   ├── ornek_betik_yardim_metni.txt
│   │   └── test_sonuclari.txt
│   └── temsili/                         # Kapsamlı mimari ASCII görselleştirmesi
│       └── guvenli_belgeleme_mimarisi.txt
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
python -m unittest tests/test_security_doc_generator.py -v

# CLI ile dokümantasyon linter'ını çalıştır
python uygulama/docgen_cli.py --schema ornek_veri/script_security_schema.json --source ornek_veri/sample_security_script.py --lint

# CLI ile Markdown Operatör Kılavuzu üret
python uygulama/docgen_cli.py --schema ornek_veri/script_security_schema.json --format markdown
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
