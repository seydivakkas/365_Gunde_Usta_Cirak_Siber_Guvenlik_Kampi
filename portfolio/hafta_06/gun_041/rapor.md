# G041 — Mini Proje 5: Windows ve Linux Karşılaştırmalı Güvenlik Raporu Değerlendirme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Yönetici Özeti ve Görev Kapsamı
- **Gün No ve Kimliği:** Gün 041 / `G041` (Aşama 02, Hafta 06, Gün 41).
- **Konu Başlığı:** Mini proje 5: Windows/Linux karşılaştırmalı rapor.
- **Tarih:** 2026-10-27.
- **Usta-Çırak Pedagojisi:** Didaktik anlatım, yerinde açıklamalı Python kodu, negatif ve pozitif test senaryoları, somut delil üretimi.
- **Genel Değerlendirme:** 100/100 (YETERLİ / PASS).

---

## 2. Puanlama Rubriği ve Detaylı Analiz

| Rubrik Kriteri | Ağırlık / Alınan | Durum | Gerekçe ve Doğrulama Kanıtı |
|---|---|---|---|
| **1. Kavramsal Derinlik ve Karşılaştırmalı Analiz** | 20 / 20 | PASS | Windows Server 2022 ve Ubuntu 22.04 LTS işletim sistemleri 10 standart güvenlik göstergesi üzerinden mimari düzeyde karşılaştırıldı. CIS/NIST referanslarıyla nesnellik sağlandı. |
| **2. Uygulama ve Denetim Motoru Geliştirme** | 40 / 40 | PASS | `windows_linux_security_comparator.py` motoru yazıldı. Her bir kod satırı didaktik yorumlarla donatıldı; tip güvenliği, şema doğrulaması, puan normalizasyonu ve markdown raporlayıcı eksiksiz uygulandı. |
| **3. Test Kapsamı ve Negatif Kontrol Doğrulaması** | 25 / 25 | PASS | `test_windows_linux_security_comparator.py` altında 14 adet birim ve negatif test başarıyla koşturuldu (14/14 PASS, 0.008s). Eksik gösterge, taşan puan, negatif puan, bozuk JSON ve tip sızıntıları test edildi. |
| **4. Savunma, Tespit ve Sıkılaştırma Kılavuzu** | 15 / 15 | PASS | Her iki işletim sistemi için LAPS v2, UAC, VBS/HVCI, systemd sandboxing, AppArmor ve auditd/Sysmon sıkılaştırma ve tespit yönergeleri belgelendi. |
| **TOPLAM PUAN** | **100 / 100** | **PASS** | **Müfredat ve operasyonel standartlara tam uyumlu.** |

---

## 3. Üretilen Dosyalar ve Kanıtlar

### Uygulama ve Test Dosyaları
1. `uygulama/windows_linux_security_comparator.py`: 10 göstergeli matrisi doğrulayan, puanlayan ve karşılaştırmalı rapor üreten didaktik motor.
2. `tests/test_windows_linux_security_comparator.py`: 14 adet birim ve negatif test içeren test süiti.
3. `ornek_veri/baseline_windows_linux_10_indicators.json`: Windows Server 2022 ve Ubuntu 22.04 LTS için 10 standart göstergeli referans matrisi.
4. `ornek_veri/corrupted_comparison_test_cases.json`: Negatif kontrol test senaryoları.

### Gerçek ve Temsilî Kanıtlar
1. `kanit/gercek/test_sonuclari.txt`: 14 testin başarıyla geçtiğini gösteren Python `unittest` çıktısı (14/14 PASS).
2. `kanit/gercek/komut_ve_cikis.txt`: Komut satırı üzerinden denetim motorunun çalıştırılması ve terminal yürütme kaydı.
3. `kanit/gercek/windows_linux_karsilastirma_raporu.txt`: Üretilen resmi Markdown karşılaştırma raporu (Puanlar, farklar, matris).
4. `kanit/gercek/negatif_kontrol_sonuclari.txt`: 6 adet negatif sınır durumunun başarıyla yakalandığını kanıtlayan denetim günlüğü.
5. `kanit/temsili/windows_linux_guvenlik_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` bayraklı mimari karşılaştırma diyagramı.

---

## 4. Karşılaştırmalı Güvenlik Puanlama Özeti

| Metrik | Microsoft Windows Server 2022 | Ubuntu 22.04 LTS | Karşılaştırma Notu |
|---|---|---|---|
| **Toplam Güvenlik Puanı** | **81.0 / 100.0** | **85.0 / 100.0** | Linux 4.0 puan önde |
| **Normalleştirilmiş Uyumluluk** | **%81.0** | **%85.0** | Her iki sistem de yüksek uyumlu |
| **Risk Duruşu (Posture)** | MEDIUM (Orta Risk / Sıkılaştırma) | LOW (Düşük Risk / Güçlü Savunma) | Windows servis izolasyonunda sıkılaştırma gerektirir |
| **Tam Uyumlu Göstergeler** | 7 / 10 | 9 / 10 | Temel alanlar tam uyumlu |
| **Kısmi Uyumlu Göstergeler** | 3 / 10 (Ayrıcalık, İzolasyon, Yama) | 1 / 10 (EDR Savunması) | İyileştirme alanları belirlendi |
| **Kritik Uyumsuz Göstergeler** | 0 / 10 | 0 / 10 | Doğrudan açık zaafiyet yok |

---

## 5. Usta-Çırak Değerlendirmesi
Çırak, Hafta 06'nın mini projesinde iki farklı işletim sistemini önyargılardan uzak, bilimsel ve teknik kriterlerle karşılaştırmayı başarmıştır. Geliştirilen denetim motoru temiz, dayanıklı ve tam açıklamalıdır; negatif test kapsamı mükemmeldir.

Bir sonraki adım olan **G042 ("Aşama 2 kalite özeti: işletim sistemi temelleri" - Aşama 02 ve Hafta 06 Kapanışı)** gününe geçilmesi uygundur.
