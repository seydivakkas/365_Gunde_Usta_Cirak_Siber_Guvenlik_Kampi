# GÜN 121 DEĞERLENDİRME RAPORU: Risk Skorlama ve Kontrol Seçimi

## 1. Genel Bilgiler
- **Tarih:** 2026-11-02
- **Hafta:** 18
- **Gün:** 121
- **Konu Başlığı:** Risk skorlama ve kontrol seçimi
- **Genel Durum:** 100/100 TAM BAŞARILI (PASS)

---

## 2. Değerlendirme Kriterleri ve Puan Tablosu

| Kategori | Ağırlık / Azami Puan | Alınan Puan | Açıklama |
|---|---|---|---|
| **Kod Kalitesi ve Mimari** | 20 | 20 | Saf Python standart kütüphanesi, NIST SP 800-30/ISO 27005 uyumlu nitel ve nicel motor, SLE/ALE/ROSI hesaplayıcı, CWE-1025 korumaları |
| **Birim Test Kapsamı ve Dayanıklılık** | 40 | 40 | 15/15 unit test (%100 PASS, süre: 0.001s), uç değerler, çarpan kontrolleri, ROSI doğrulaması, yönetişim kontrolleri |
| **Negatif Kontrol ve Güvenlik Senaryoları** | 25 | 25 | 9/9 negatif kontrol senaryosu (%100 PASS, geçersiz skorlar, negatif varlıklar, onaysız kabul, kontrolsüz azaltma) |
| **Dokümantasyon ve Usta-Çırak Derinliği** | 15 | 15 | ders.md, 3 adet 4 başlıklı soru_cevap.md, rapor.md, README.md, sonuc.json, manifest.json |
| **TOPLAM** | **100** | **100** | **MÜKEMMEL (TAM PUAN)** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### A. Birim Testler (`tests/test_risk_control.py`)
- **Toplam Test Sayısı:** 15
- **Başarılı:** 15
- **Başarısız / Hata:** 0
- **Çalışma Süresi:** 0.001 saniye

Test edilen temel yetenekler:
1. `test_01_inherent_risk_score_and_level_calculation`: Doğal risk skoru ve nitel seviye eşleşmesi (LOW, MEDIUM, HIGH, CRITICAL).
2. `test_02_sle_and_inherent_ale_calculation`: SLE ($AV \times EF$) ve Inherent ALE ($SLE \times ARO$) hesaplaması.
3. `test_03_invalid_likelihood_out_of_bounds`: Olasılık puanının 1-5 sınırları dışı için `InvalidRiskScoreError`.
4. `test_04_invalid_impact_out_of_bounds`: Etki puanının 1-5 sınırları dışı için `InvalidRiskScoreError`.
5. `test_05_invalid_financial_metrics`: Negatif varlık, 1'den büyük EF veya negatif ARO için `InvalidFinancialMetricError`.
6. `test_06_control_registration_and_duplicate_rejection`: Kontrol kaydı ve aynı ID ile mükerrer kontrol engelleme (`DuplicateControlError`).
7. `test_07_invalid_control_effectiveness_bounds`: 0.01 altı veya 0.99 üstü kontrol etkinliğinin reddi (`InvalidControlSelectionError`).
8. `test_08_assign_control_to_risk_and_duplicate_assignment`: Riske kontrol atama ve çift atamanın engellenmesi.
9. `test_09_multi_control_combined_effectiveness_calculation`: Bağımsız kontrollerin birleşik etkinlik çarpım kuralı ($1 - (1-e_1)(1-e_2)$).
10. `test_10_residual_risk_and_residual_ale_reduction`: Kontroller sonrası artık olasılık, etki, skor ve ALE düşüşü.
11. `test_11_rosi_calculation_accuracy`: ROSI formülü ($[(\Delta ALE - Maliyet) / Maliyet] \times 100$) doğrulaması.
12. `test_12_risk_avoidance_treatment_strategy`: KAÇIN stratejisinde artık ALE sıfırlanması ve taban seviye.
13. `test_13_governance_mitigate_without_controls_flagged`: Kontrolsüz azaltma stratejisinin ihlal tespiti.
14. `test_14_governance_unapproved_risk_acceptance_fails`: Risk iştahını aşan onaysız kabulün reddi (CWE-1025).
15. `test_15_governance_executive_sign_off_passes_and_report_generation`: C-Level onaylı riskin geçişi ve Markdown rapor üretimi.

### B. Negatif Kontroller (`ornek_veri/invalid_risk_scenarios.json`)
- **Toplam Senaryo:** 9
- **Başarılı (Beklenen Hata Alındı):** 9 / 9
- Senaryo Tipleri: Negatif Varlık Değeri, Aşırı EF (>1.0), Negatif ARO, Sıfır Olasılık, Aşırı Etki (>5), Geçersiz Kontrol Etkinliği, Mükerrer Kontrol ID, Kontrolsüz Azaltma İhlali, Onaysız Kritik Risk Kabulü (CWE-1025).

### C. Kanıt Dosyaları Listesi
1. `kanit/gercek/test_sonuclari.txt` (15/15 PASS detaylı çıktı)
2. `kanit/gercek/negatif_kontrol_sonuclari.txt` (9/9 PASS negatif senaryolar)
3. `kanit/gercek/komut_ve_cikis.txt` (CLI evaluate ve rosi komut çıktıları)
4. `kanit/gercek/risk_analiz_raporu.txt` (Detaylı Markdown formatında kurumsal risk analizi)
5. `kanit/temsili/risk_mimarisi.txt` (ASCII mimari illüstrasyonu)

---

## 4. Standartlar ve CWE Eşleme Tablosu

| Güvenlik Standardı / CWE | Tanım | Motordaki Karşılığı |
|---|---|---|
| **CWE-1025** | Comparison Using Wrong Factors (Hatalı Faktörlerle Karşılaştırma) | Risk iştahını aşan risklerin C-Level resmi onayı (`executive_sign_off`) olmadan kabul edilmesinin programatik olarak engellenmesi (`RiskAppetiteExceededError`). |
| **NIST SP 800-30** | Guide for Conducting Risk Assessments | Nitel olasılık/etki matrisi (1-25) ve nicel finansal kayıp (SLE, ARO, ALE) hesaplama modeli. |
| **ISO 27005** | Information Security Risk Management | 4 temel risk iyileştirme stratejisinin uygulanması (Mitigate, Avoid, Transfer, Accept). |
| **NIST SP 800-53 Rev 5** | Security and Privacy Controls for Information Systems | AC, IA, SC, SI, AU, CP kontrol aileleri ve önleyici, tespit edici, düzeltici kontrol sınıflandırması. |
| **CIS Controls v8** | Center for Internet Security Critical Controls | PAM, EDR, Yedekleme ve WAF kontrollerinin etkinlik oranlarıyla entegrasyonu. |
| **CWE-250 / CWE-285** | Execution with Unnecessary Privileges / Improper Authorization | Geliştirici veya teknisyenin tek başına kurumsal risk kabulü yapmasının engellenmesi. |
