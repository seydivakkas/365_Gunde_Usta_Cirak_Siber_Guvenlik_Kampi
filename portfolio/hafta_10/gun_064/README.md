# G064: Hafta 10 Gün 64 — Wireshark Filtre Sözdizimi ve Tehdit Avcılığı Motoru

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/Asama-03-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-indigo?style=flat-square)
![Test Durumu: 14/14 PASS](https://img.shields.io/badge/Tests-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan: 100/100](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## Lisans ve Kullanım Koşulları

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

---

## Proje Genel Bakış

Bu proje, ağ trafiğinde adli bilişim ve siber tehdit avcılığı (threat hunting) yapabilmek amacıyla Wireshark görüntüleme filtresi (display filter) standartlarını sıfırdan Python ile ayrıştıran ve işleten bir filtre motoru sunar.

Motor, sözcüksel analiz (lexer) ile filtre dizgesini tokenlara ayırır, parantez dengesini doğrular ve özyinelemeli inişli ayrıştırıcı (recursive descent parser) ile bir Soyut Sözdizim Ağacı (AST) inşa eder. Ayrıştırılan ağ paketleri bu AST üzerinden süzülerek saldırı imzaları tespit edilir.

### Temel Yetenekler
- **Mantıksal Operatörler:** `&&` (`and`), `||` (`or`), `!` (`not`), parantezli öncelik gruplaması `( ... )`.
- **Karşılaştırma Operatörleri:** `==` (`eq`), `!=` (`ne`), `>`, `<`, `>=`, `<=`.
- **İçerik ve Regex Operatörleri:** `contains` (büyük/küçük harf duyarsız alt metin arama), `matches` (düzenli ifade eşleştirme).
- **Bayt Dilimleme (Byte Slicing):** `tcp.payload_hex[0:4] == "4745"` (paket başı bayt deseni arama).
- **Takma Alanlar (Alias Fields):** `ip.addr` (kaynak veya hedef IP), `tcp.port` (kaynak veya hedef port), `http` (tüm HTTP alanları).
- **Siber Tehdit Avcılığı Profilleri:** SYN Flood, Port Tarama RST yanıtları, açık metin parola sızıntısı, DNS tünelleme ve TCP sıfır pencere askıya alma saldırılarını otomatik tespit eder.

---

## Dizin Yapısı

```
portfolio/hafta_10/gun_064/
├── README.md                               # Proje genel bakış ve lisans belgesi
├── ders.md                                 # Usta-çırak teorik ders anlatımı
├── soru_cevap.md                           # 3 vaka analizi ve 4 zorunlu alt başlık
├── rapor.md                                # 100/100 değerlendirme ve doğrulama raporu
├── sonuc.json                              # 14 standart alanlı makine tarafından okunabilir çıktı
├── manifest.json                           # Dosya SHA-256 bütünlük özeti
├── uygulama/
│   ├── __init__.py
│   └── wireshark_filter_engine.py          # Wireshark filtre lexer, AST parser ve motoru
├── tests/
│   ├── __init__.py
│   └── test_wireshark_filter_engine.py     # 14 birim test paketi
├── ornek_veri/
│   ├── sample_packets.json                 # 10 adet ayrıştırılmış örnek paket havuzu
│   └── invalid_filter_inputs.json          # 9 negatif sınır ve sözdizim hatası senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt              # 14 birim testin koşu çıktısı
    │   ├── komut_ve_cikis.txt              # Terminal yürütme logları
    │   ├── wireshark_filtre_raporu.txt     # Tehdit avı profilleri ve süzme çıktıları
    │   └── negatif_kontrol_sonuclari.txt   # 9/9 negatif sınır test sonucu
    └── temsili/
        └── wireshark_filtre_ast_mimarisi.txt # BPF vs Display filter ve AST şeması
```

---

## Testleri Çalıştırma

Tüm testleri kök dizinden çalıştırmak için:

```bash
python -m unittest portfolio.hafta_10.gun_064.tests.test_wireshark_filter_engine -v
```
