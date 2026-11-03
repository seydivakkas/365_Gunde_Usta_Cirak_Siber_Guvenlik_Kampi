# GÜN 023: Değerlendirme Raporu — Linux Terminali ve Kabuk

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu rapor Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## 1. Genel Değerlendirme ve İlerleme Durumu

- **Öğrenci / Aday:** Seydi Eryılmaz (@seydivakkas)
- **Tarih:** 2026-10-27
- **Aşama:** 02 (Sistem ve Ağ Temelleri)
- **Hafta:** 04 (Ağ ve Komut Satırı Temelleri)
- **Gün:** 023 (Linux Terminali ve Kabuk)
- **Excel Satır Numarası:** 27
- **Genel Karar:** **100 / 100 — TAM BAŞARILI (YETERLİ / PASS)**

---

## 2. Puanlama Kriterleri ve Başarım Detayları

### Kriter 1: Teorik Altyapı ve Kavramsal Derinlik (20 Puan)
- **Alınan Puan:** **20 / 20**
- **Değerlendirme Notu:** 
  - Terminal (TTY/PTY), kabuk (Bash/Sh) ve çekirdek (Kernel) katman ayrımı kavramsal olarak netleştirilmiştir.
  - Standart girdi/çıktı akışları (FD 0 stdin, FD 1 stdout, FD 2 stderr) ve yönlendirme/boru hattı mantığı detaylandırılmıştır.
  - Soru bankası G023-SC1 gereğince göreceli yol (relative path) ve mutlak yol (absolute path) farkı, çalışma dizini (`pwd`) bağlamı ve CWE-426 / CWE-22 güvenlik riskleri açıklanmıştır.

### Kriter 2: Laboratuvar ve Kodlama Kalitesi (40 Puan)
- **Alınan Puan:** **40 / 40**
- **Değerlendirme Notu:**
  - `linux_shell_security_simulator.py` aracı POSIX standartlarındaki 5 temel kabuk komutunu (`pwd`, `cd`, `ls`, `cat`, `head`) simüle eden bağımsız bir yapıda geliştirilmiştir.
  - Kodun her satırı didaktik Türkçe açıklamalarla zenginleştirilmiş; tip güvenliği (type hints) ve POSIX yol normalizasyonu sağlanmıştır.
  - Birim test suite (`test_linux_shell_security_simulator.py`) 14 farklı test senaryosu içermekte olup **14/14 test 0.095 saniyede (%100 PASS)** başarıyla tamamlanmıştır.
  - 5 adet negatif test (`FileNotFoundError`, `NotADirectoryError`, `IsADirectoryError`, dizin aşımı tespiti, güvensiz PATH tespiti) eksiksiz doğrulanmıştır.

### Kriter 3: Güvenlik, Risk Analizi ve Tehdit Modellemesi (25 Puan)
- **Alınan Puan:** **25 / 25**
- **Değerlendirme Notu:**
  - CWE-426 (Untrusted Search Path / Güvensiz PATH Değişkeni) ve CWE-22 (Path Traversal / Dizin Aşımı) zafiyetleri kod düzeyinde analiz edilmiştir.
  - `PATH` ortam değişkeninde `.` veya `/tmp` bulunması durumunda yerel yetki yükseltme (LPE) senaryoları modellenmiştir.
  - Soru bankası G023-SC2 gereğince 5 temel komut (`pwd`, `ls`, `cd`, `cat`, `head`) sıralı bir iş akışı olarak icra edilmiş ve adli analiz çıktısı üretilmiştir.

### Kriter 4: Kanıt Bütünlüğü, Raporlama ve Standart Uyumu (15 Puan)
- **Alınan Puan:** **15 / 15**
- **Değerlendirme Notu:**
  - Gerçek komut çalıştırma kanıtı (`kanit/gercek/komut_ve_cikis.txt`), birim test kanıtı (`kanit/gercek/test_sonuclari.txt`) ve üretilen yapılandırılmış analiz çıktısı (`kanit/gercek/kabuk_komut_analiz_ciktisi.txt`) eksiksiz sunulmuştur.
  - Temsili mimari akış diyagramı (`kanit/temsili/linux_kabuk_mimarisi.txt`) zorunlu uyarı başlığı (`TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL`) ile üretilmiştir.
  - Soru bankası soruları (`G023-SC1`, `G023-SC2`, `G023-SC3`) 4 zorunlu alt başlık altında yanıtlanmıştır.

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

Gün 023 "Linux terminali ve kabuk" modülü 100/100 tam puanla başarıyla tamamlanmıştır. Yarın **Gün 024** (Aşama 02, Hafta 04, Gün 24) kapsamında **"Linux dosya ve dizin izinleri: chmod, chown ve umask"** konusu işlenecektir.
