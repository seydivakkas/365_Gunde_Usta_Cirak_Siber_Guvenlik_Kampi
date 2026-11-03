# GÜN 022: Değerlendirme Raporu — Komut Satırı: PowerShell Temelleri

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu rapor Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## 1. Genel Değerlendirme ve İlerleme Durumu

- **Öğrenci / Aday:** Seydi Eryılmaz (@seydivakkas)
- **Tarih:** 2026-10-27
- **Aşama:** 02 (Sistem ve Ağ Temelleri)
- **Hafta:** 04 (Ağ ve Komut Satırı Temelleri)
- **Gün:** 022 (Komut Satırı: PowerShell Temelleri)
- **Excel Satır Numarası:** 26
- **Genel Karar:** **100 / 100 — TAM BAŞARILI (YETERLİ / PASS)**

---

## 2. Puanlama Kriterleri ve Başarım Detayları

### Kriter 1: Teorik Altyapı ve Kavramsal Derinlik (20 Puan)
- **Alınan Puan:** **20 / 20**
- **Değerlendirme Notu:** 
  - Geleneksel metin boru hattı ile PowerShell .NET nesne boru hattı (Object Pipeline) mimarisi arasındaki farklar derinlemesine açıklanmıştır.
  - Soru bankası G022-SC1 gereğince salt-okunur (`Get-`) cmdlet'lerle başlama felsefesi ve adli bilişim ilkeleri detaylandırılmıştır.
  - Execution Policy mekanizmasının bir güvenlik sınırı olmadığı, gerçek koruma katmanlarının Script Block Logging (EID 4104), AMSI ve Constrained Language Mode (CLM) olduğu vurgulanmıştır.

### Kriter 2: Laboratuvar ve Kodlama Kalitesi (40 Puan)
- **Alınan Puan:** **40 / 40**
- **Değerlendirme Notu:**
  - `powershell_security_pipeline_auditor.py` aracı canlı sistemden (`--live`) güvenli cmdlet'leri çağırabilen ve bağımsız JSON nesne akışlarını filtreleyen modüler bir yapıda geliştirilmiştir.
  - Her kod satırı didaktik Türkçe açıklamalarla zenginleştirilmiş; tip güvenliği (type hints) ve UTF-8 konsol uyumluluğu sağlanmıştır.
  - Birim test suite (`test_powershell_security_pipeline_auditor.py`) 14 farklı test senaryosu içermekte olup **14/14 test 0.903 saniyede (%100 PASS)** başarıyla icra edilmiştir.
  - 4 adet negatif test (`FileNotFoundError`, bozuk JSON, şüpheli süreç kalıbı, Mimikatz saldırı tespiti) eksiksiz doğrulanmıştır.

### Kriter 3: Güvenlik, Risk Analizi ve Tehdit Modellemesi (25 Puan)
- **Alınan Puan:** **25 / 25**
- **Değerlendirme Notu:**
  - MITRE ATT&CK T1059.001 (PowerShell: Bypass, Hidden, EncodedCommand) saldırı taktikleri kod düzeyinde taranmıştır.
  - CWE-428 (Tırnaksız Servis Yolu) ve CIS Benchmark (eski protokoller: Telnet, RemoteRegistry) riskleri modellenmiştir.
  - Soru bankası G022-SC2 gereğince `Get-Process` ve `Get-Service` çıktıları filtrelenerek 6 kolonlu standart bir güvenlik CSV raporuna (`filtrelenmis_surec_ve_servisler.csv`) dönüştürülmüştür.

### Kriter 4: Kanıt Bütünlüğü, Raporlama ve Standart Uyumu (15 Puan)
- **Alınan Puan:** **15 / 15**
- **Değerlendirme Notu:**
  - Gerçek komut ve çıktı kanıtı (`kanit/gercek/komut_ve_cikis.txt`), birim test kanıtı (`kanit/gercek/test_sonuclari.txt`) ve üretilen CSV dosyası eksiksiz sunulmuştur.
  - Temsili nesne boru hattı görselleştirmesi (`kanit/temsili/powershell_pipeline_mimarisi.txt`) zorunlu uyarı başlığı (`TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL`) ile üretilmiştir.
  - Soru bankası soruları (`G022-SC1`, `G022-SC2`, `G022-SC3`) 4 zorunlu alt başlık altında yanıtlanmıştır.

---

## 3. Puan Özeti Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Kazanılan Puan | Durum |
|---|:---:|:---:|:---:|
| 1. Teorik Altyapı ve Kavramsal Derinlik | 20 | 20 | Başarılı |
| 2. Laboratuvar ve Kodlama Kalitesi | 40 | 40 | Başarılı |
| 3. Güvenlik, Risk Analizi ve Tehdit Modellemesi | 25 | 25 | Başarılı |
| 4. Kanıt Bütünlüğü, Raporlama ve Standart Uyumu | 15 | 15 | Başarılı |
| **TOPLAM** | **100** | **100** | **YETERLİ / PASS** |

---

## 4. Sonuç ve Sonraki Gün Planı

Gün 022 "Komut satırı: PowerShell temelleri" modülü 100/100 tam puanla başarıyla tamamlanmıştır. Yarın **Gün 023** (Aşama 02, Hafta 04, Gün 23) kapsamında **"Komut satırı: PowerShell ile dosya ve sistem yönetimi"** konusu işlenecektir.
