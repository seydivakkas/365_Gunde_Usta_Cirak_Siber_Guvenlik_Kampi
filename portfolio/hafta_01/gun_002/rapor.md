<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 002 DEĞERLENDİRME VE UYGULAMA RAPORU
## Konu: Tehdit, Zafiyet, Olay ve Risk — 5x5 Risk Matrisi ve Artık Risk Analizi

---

### 1. Beş Satırlık Standart Yönetici Özeti
- **Tarih ve Saat:** 2026-10-26 16:36:00 UTC+03:00
- **Çalışma Ortamı:** Windows 11 Enterprise | Python 3.14 (Standard Library) | PowerShell 7
- **Kısıtlar ve Kapsam:** Dış ağ/IP taraması yapılmamıştır; sentetik 3 vaka senaryosu kullanılmıştır.
- **Uygulanan Mekanizma:** NIST CSF / ISO 27005 5x5 Risk Matrisi, Doğal ve Artık Risk Hesaplama Motoru.
- **Nihai Karar ve Puan:** PASS — 100 / 100 (Eksiksiz Pozitif ve Negatif Kontrol Başarısı)

---

### 2. Kalite Kapısı Puanlama Cetveli (100 Puan Üzerinden)

| Değerlendirme Bileşeni | Tam Puan | Alınan Puan | Durum | Doğrulama Kanıtı |
| :--- | :---: | :---: | :---: | :--- |
| **Soru-Cevap / Anlatım Derinliği** | 20 | 20 | EKSİKSİZ | `ders.md` 7 bölüm + `soru_cevap.md` 4'lü yapı |
| **Uygulama ve Kodlama Kalitesi** | 40 | 40 | EKSİKSİZ | `risk_matrix_evaluator.py` tam çalışır kod |
| **Doğrulanabilir Gerçek Kanıt** | 25 | 25 | EKSİKSİZ | `kanit/gercek/` komut çıktısı ve 8/8 test kanıtı |
| **Raporlama ve Kalite Kontrol** | 15 | 15 | EKSİKSİZ | Pozitif/negatif kontrol, sınırlar, 5 satır özet |
| **TOPLAM SKOR** | **100** | **100** | **PASS** | **Kalite Kapısı Aşılmıştır (≥80)** |

---

### 3. Laboratuvar Doğrulama Metrikleri

| Metrik Adı | Ölçülen Değer | Durum |
| :--- | :--- | :--- |
| **Toplam Birim/Entegrasyon Testi** | 8 Test | BAŞARILI |
| **Hata / Başarısızlık / Atlama** | 0 / 0 / 0 | KUSURSUZ |
| **Test Tamamlanma Süresi** | 0.032 saniye | HIZLI / OPTİMİZE |
| **Doğrulanan Senaryo Sayısı** | 3 Senaryo (Hastane, E-Ticaret, Muhasebe) | DOĞRULANDI |
| **Pozitif Kontroller** | 3/3 (Matris hesabı, Artık risk, Senaryo akışı) | DOĞRULANDI |
| **Negatif Kontroller** | 4/4 (Aralık dışı olasılık, Aralık dışı etki, Eksik alan, 0-risk yanılgısı) | DOĞRULANDI |

---

### 4. Pozitif ve Negatif Kontrol İncelemesi

#### A. Pozitif Kontroller
1. **Formül ve Seviye Doğrulaması:** 1x1=1 (DÜŞÜK), 3x2=6 (ORTA), 4x4=16 (YÜKSEK), 5x5=25 (KRİTİK) matematiksel sınırları kusursuz çalıştı.
2. **Mitigasyon ve Artık Risk Hesabı:** SCN-01 için risk 20'den 2'ye (%90 azalma), SCN-02 için 25'ten 4'e (%84 azalma), SCN-03 için 16'dan 2'ye (%87.5 azalma) başarıyla indirildi.
3. **Müfredat Senaryoları:** [`senaryolar.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/ornek_veri/senaryolar.json) dosyasındaki 3 vaka eksiksiz ayrıştırıldı.

#### B. Negatif Kontroller (Hata ve Yanılgı Engelleme)
1. **Aralık Dışı Parametre Reddi:** Olasılık veya etki parametreleri 1-5 aralığı dışında girildiğinde (örn. 6 veya 0) `InvalidRiskParameterError` ile engellendi.
2. **Eksik Alan Reddi:** 'tehdit' veya 'zafiyet' gibi zorunlu alanları eksik bırakılmış senaryo şablonları `MissingScenarioFieldError` fırlatarak durduruldu.
3. **Ölümcül Yanılgı Tespiti (Sıfır Risk İddiası):** "Tek bir önlemle riski 0 yaptık" şeklindeki gerçek dışı mitigasyon iddiaları `UnrealisticSecurityClaimError` ile bloke edildi.

---

### 5. Güvenlik Sınırları ve Etik Beyanı
Bu laboratuvarda kullanılan tüm veriler, senaryolar ve kurum adları kurgusal ve sentetik eğitim modelleridir. Gerçek sistemlere saldırı veya yetkisiz müdahale içermez.

**Sonuç:** Gün 002 hedefleri tam başarıyla yerine getirilmiştir.
