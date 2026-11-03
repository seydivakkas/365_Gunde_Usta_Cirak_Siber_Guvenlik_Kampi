# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 121: Risk Skorlama ve Kontrol Seçimi Birim Testleri.
15 kapsamlı test senaryosu: Nitel/nicel hesaplamalar, SLE/ALE, ROSI,
kontrol kataloğu, çoklu kontrol etkinliği, kurumsal yönetişim ve CWE-1025 kontrolleri.
"""

# Standart unittest çerçevesi içe aktarılıyor
import unittest
# Sistem yolu manipülasyonu için sys ve os içe aktarılıyor
import sys
import os

# Uygulama modülünü arama yoluna eklemek için dizin çözümleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama dizini yolu belirleniyor
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Arama yolunun başına uygulama dizini ekleniyor
sys.path.insert(0, app_dir)

# Test edilecek motor sınıfları ve istisnalar içe aktarılıyor
from risk_control_engine import (
    RiskAssessmentManager,
    SecurityControl,
    RiskItem,
    RiskLevel,
    RiskTreatmentStrategy,
    ControlFamily,
    ControlType,
    InvalidRiskScoreError,
    RiskAppetiteExceededError,
    InvalidControlSelectionError,
    DuplicateControlError,
    DuplicateRiskError,
    InvalidFinancialMetricError,
    RiskEngineError
)


class TestRiskControlEngine(unittest.TestCase):
    """Risk ve Kontrol Yönetim Motoru test takımı."""

    def setUp(self):
        """Her testten önce standart bir test ortamı kurar."""
        # Test için örnek bir kurum yöneticisi oluşturulur
        self.manager = RiskAssessmentManager(
            organization_name="Finansal Guvenlik A.S.",
            risk_appetite_score=10,
            max_acceptable_ale=40000.0
        )
        # Örnek güvenlik kontrolü oluşturulur
        self.mfa_control = SecurityControl(
            control_id="NIST-IA-2",
            name="Çok Faktörlü Kimlik Doğrulama (MFA)",
            family=ControlFamily.IA,
            control_type=ControlType.PREVENTIVE,
            annual_cost=12000.0,
            implementation_cost=15000.0,
            effectiveness_ratio=0.85,
            lifecycle_years=3
        )
        # İkinci örnek güvenlik kontrolü oluşturulur
        self.waf_control = SecurityControl(
            control_id="NIST-SC-7",
            name="Web Uygulama Güvenlik Duvarı (WAF)",
            family=ControlFamily.SC,
            control_type=ControlType.PREVENTIVE,
            annual_cost=18000.0,
            implementation_cost=10000.0,
            effectiveness_ratio=0.75,
            lifecycle_years=3
        )

    def test_01_inherent_risk_score_and_level_calculation(self):
        """Doğal risk skoru ve nitel seviye (LOW, MED, HIGH, CRIT) doğrulanır."""
        # Düşük risk öğesi (2 * 2 = 4 -> LOW)
        r_low = RiskItem("R-01", "Düşük Risk", "", "Varlık A", 10000, 0.1, 0.1, 2, 2)
        self.assertEqual(r_low.get_inherent_score(), 4)
        self.assertEqual(r_low.get_inherent_level(), RiskLevel.LOW)

        # Orta risk öğesi (3 * 3 = 9 -> MEDIUM)
        r_med = RiskItem("R-02", "Orta Risk", "", "Varlık B", 20000, 0.2, 0.5, 3, 3)
        self.assertEqual(r_med.get_inherent_score(), 9)
        self.assertEqual(r_med.get_inherent_level(), RiskLevel.MEDIUM)

        # Yüksek risk öğesi (4 * 4 = 16 -> HIGH)
        r_high = RiskItem("R-03", "Yüksek Risk", "", "Varlık C", 50000, 0.5, 1.0, 4, 4)
        self.assertEqual(r_high.get_inherent_score(), 16)
        self.assertEqual(r_high.get_inherent_level(), RiskLevel.HIGH)

        # Kritik risk öğesi (5 * 5 = 25 -> CRITICAL)
        r_crit = RiskItem("R-04", "Kritik Risk", "", "Varlık D", 100000, 0.8, 2.0, 5, 5)
        self.assertEqual(r_crit.get_inherent_score(), 25)
        self.assertEqual(r_crit.get_inherent_level(), RiskLevel.CRITICAL)

    def test_02_sle_and_inherent_ale_calculation(self):
        """SLE (Asset*EF) ve Doğal ALE (SLE*ARO) finansal hesaplaması test edilir."""
        # 200.000$ varlık, %40 maruz kalma, yılda 1.5 kez oluşma sıklığı
        risk = RiskItem("R-FIN", "Veri İhlali", "", "Müşteri DB", 200000.0, 0.40, 1.5, 4, 5)
        # SLE = 200.000 * 0.40 = 80.000$
        self.assertAlmostEqual(risk.calculate_sle(), 80000.0)
        # Inherent ALE = 80.000 * 1.5 = 120.000$
        self.assertAlmostEqual(risk.calculate_inherent_ale(), 120000.0)

    def test_03_invalid_likelihood_out_of_bounds(self):
        """Olasılık puanı 1-5 aralığı dışında olduğunda InvalidRiskScoreError fırlatılmalıdır."""
        # Olasılık sıfır olamaz
        r_zero = RiskItem("R-ERR1", "Hatalı", "", "Varlık", 1000, 0.1, 1.0, 0, 3)
        with self.assertRaises(InvalidRiskScoreError):
            r_zero.validate_inputs()
        # Olasılık altı olamaz
        r_six = RiskItem("R-ERR2", "Hatalı", "", "Varlık", 1000, 0.1, 1.0, 6, 3)
        with self.assertRaises(InvalidRiskScoreError):
            r_six.validate_inputs()

    def test_04_invalid_impact_out_of_bounds(self):
        """Etki puanı 1-5 aralığı dışında olduğunda InvalidRiskScoreError fırlatılmalıdır."""
        # Etki sıfır olamaz
        r_zero = RiskItem("R-ERR3", "Hatalı", "", "Varlık", 1000, 0.1, 1.0, 3, 0)
        with self.assertRaises(InvalidRiskScoreError):
            r_zero.validate_inputs()
        # Etki yedi olamaz
        r_seven = RiskItem("R-ERR4", "Hatalı", "", "Varlık", 1000, 0.1, 1.0, 3, 7)
        with self.assertRaises(InvalidRiskScoreError):
            r_seven.validate_inputs()

    def test_05_invalid_financial_metrics(self):
        """Negatif varlık değeri, 1'den büyük EF veya negatif ARO hata vermelidir."""
        # Negatif varlık değeri
        r_neg_val = RiskItem("R-FIN1", "Test", "", "Varlık", -500.0, 0.5, 1.0, 3, 3)
        with self.assertRaises(InvalidFinancialMetricError):
            r_neg_val.validate_inputs()
        # EF 1.0'dan büyük olamaz
        r_big_ef = RiskItem("R-FIN2", "Test", "", "Varlık", 1000.0, 1.5, 1.0, 3, 3)
        with self.assertRaises(InvalidFinancialMetricError):
            r_big_ef.validate_inputs()
        # Negatif ARO olamaz
        r_neg_aro = RiskItem("R-FIN3", "Test", "", "Varlık", 1000.0, 0.5, -0.5, 3, 3)
        with self.assertRaises(InvalidFinancialMetricError):
            r_neg_aro.validate_inputs()

    def test_06_control_registration_and_duplicate_rejection(self):
        """Kontrol kaydı ve aynı ID ile mükerrer kontrol ekleme denemesi engellenmelidir."""
        # Kontrol ilk kez kaydedilir
        self.manager.register_control(self.mfa_control)
        self.assertIn("NIST-IA-2", self.manager.controls_catalog)
        # Aynı kontrol tekrar eklenmeye çalışıldığında hata beklenir
        with self.assertRaises(DuplicateControlError):
            self.manager.register_control(self.mfa_control)

    def test_07_invalid_control_effectiveness_bounds(self):
        """Etkinlik oranı 0.01 altı veya 0.99 üstü olduğunda kontrol reddedilmelidir."""
        # %0 etkinlikli geçersiz kontrol
        ctrl_zero = SecurityControl("C-BAD1", "Etkisiz", ControlFamily.AC, ControlType.PREVENTIVE, 100, 100, 0.00)
        with self.assertRaises(InvalidControlSelectionError):
            self.manager.register_control(ctrl_zero)
        # %100'ü aşan kontrol
        ctrl_over = SecurityControl("C-BAD2", "Aşırı", ControlFamily.AC, ControlType.PREVENTIVE, 100, 100, 1.05)
        with self.assertRaises(InvalidControlSelectionError):
            self.manager.register_control(ctrl_over)

    def test_08_assign_control_to_risk_and_duplicate_assignment(self):
        """Riske kontrol atama ve aynı riske aynı kontrolü çift atama testi."""
        risk = RiskItem("R-ACC", "Hesap Ele Geçirme", "", "Web Portali", 50000, 0.5, 1.0, 4, 4)
        self.manager.register_risk(risk)
        self.manager.register_control(self.mfa_control)

        # Kontrol riske atanır
        self.manager.assign_control_to_risk("R-ACC", "NIST-IA-2")
        self.assertEqual(len(risk.applied_controls), 1)

        # Aynı kontrol tekrar atanmaya çalışılırsa DuplicateControlError beklenir
        with self.assertRaises(DuplicateControlError):
            self.manager.assign_control_to_risk("R-ACC", "NIST-IA-2")

        # Olmayan kontrol atanmaya çalışılırsa InvalidControlSelectionError beklenir
        with self.assertRaises(InvalidControlSelectionError):
            self.manager.assign_control_to_risk("R-ACC", "NIST-NON-EXISTENT")

    def test_09_multi_control_combined_effectiveness_calculation(self):
        """Birden fazla kontrol uygulandığında birleşik etkinlik formülü doğrulanır."""
        risk = RiskItem("R-MULTI", "SQL Injection", "", "Veritabanı", 100000, 0.6, 1.0, 5, 5)
        # MFA %85 (0.85), WAF %75 (0.75) etkinliğe sahip
        risk.applied_controls.append(self.mfa_control)
        risk.applied_controls.append(self.waf_control)
        # Birleşik kalan risk = (1 - 0.85) * (1 - 0.75) = 0.15 * 0.25 = 0.0375
        # Toplam etkinlik = 1 - 0.0375 = 0.9625 (%96.25)
        expected_eff = 1.0 - (0.15 * 0.25)
        self.assertAlmostEqual(risk.get_total_control_effectiveness(), expected_eff, places=4)

    def test_10_residual_risk_and_residual_ale_reduction(self):
        """Kontroller uygulandıktan sonra artık olasılık, etki, skor ve ALE düşüşü doğrulanır."""
        risk = RiskItem("R-RED", "Veri Sızıntısı", "", "API", 80000.0, 0.5, 1.0, 4, 4)
        # Doğal değerler
        self.assertEqual(risk.get_inherent_score(), 16)
        self.assertAlmostEqual(risk.calculate_inherent_ale(), 40000.0)

        # Güçlü MFA kontrolü atanır (%85 etkinlik)
        risk.applied_controls.append(self.mfa_control)

        # Artık skor doğal skordan kesinlikle düşük olmalıdır
        self.assertLess(risk.get_residual_score(), 16)
        # Artık ALE doğal ALE'den düşük olmalıdır
        self.assertLess(risk.calculate_residual_ale(), 40000.0)
        # Artık ALE = 40.000 * (1 - 0.85) = 6.000$
        self.assertAlmostEqual(risk.calculate_residual_ale(), 6000.0)

    def test_11_rosi_calculation_accuracy(self):
        """ROSI = [(ALE_inh - ALE_res) - Maliyet] / Maliyet * 100 formülü doğrulanır."""
        risk = RiskItem("R-ROSI", "Ransomware", "", "Dosya Sunucusu", 150000.0, 0.8, 1.0, 5, 5)
        # Doğal ALE = 150.000 * 0.8 * 1.0 = 120.000$
        # Kontrol yıllıklandırılmış maliyeti: 15.000 / 3 + 12.000 = 17.000$
        # Kontrol etkinliği: %85 -> Residual ALE = 120.000 * 0.15 = 18.000$
        # Önlenen kayıp = 120.000 - 18.000 = 102.000$
        # Net tasarruf = 102.000 - 17.000 = 85.000$
        # ROSI = (85.000 / 17.000) * 100 = %500
        risk.applied_controls.append(self.mfa_control)
        expected_cost = (15000.0 / 3) + 12000.0
        self.assertAlmostEqual(risk.calculate_total_annual_control_cost(), expected_cost)
        self.assertAlmostEqual(risk.calculate_rosi(), 500.0)

    def test_12_risk_avoidance_treatment_strategy(self):
        """KAÇIN (AVOID) stratejisinde artık ALE sıfırlanmalı ve skor taban değere inmelidir."""
        risk = RiskItem("R-AVOID", "Riskli Yeni Hizmet", "", "Pilot Servis", 50000.0, 0.5, 2.0, 4, 4)
        risk.treatment_strategy = RiskTreatmentStrategy.AVOID
        # Kaçınılan riskte artık ALE sıfır olmalıdır
        self.assertEqual(risk.calculate_residual_ale(), 0.0)
        # Artık olasılık ve etki 1 olmalıdır (skor 1)
        self.assertEqual(risk.get_residual_score(), 1)
        self.assertEqual(risk.get_residual_level(), RiskLevel.LOW)

    def test_13_governance_mitigate_without_controls_flagged(self):
        """Strateji AZALT iken kontrol atanmamışsa yönetişim bunu ihlal olarak raporlamalıdır."""
        risk = RiskItem("R-NOCONTROL", "Eksik Kontrol", "", "Sunucu", 30000, 0.3, 1.0, 3, 3)
        self.manager.register_risk(risk)
        passed, violations = self.manager.validate_corporate_risk_governance()
        self.assertFalse(passed)
        self.assertTrue(any("hiçbir güvenlik kontrolü atanmamış" in v for v in violations))

    def test_14_governance_unapproved_risk_acceptance_fails(self):
        """Risk iştahını aşan risk üst yönetim onaysız KABUL_ET yapılırsa hata fırlatmalıdır (CWE-1025)."""
        # Kurum iştahı 10 iken doğal skoru 20 olan kritik risk
        risk = RiskItem("R-CRIT-ACCEPT", "Kritik Açık", "", "Ödeme Sistemi", 100000, 0.5, 2.0, 4, 5)
        risk.treatment_strategy = RiskTreatmentStrategy.ACCEPT
        risk.executive_sign_off = False  # Onay YOK!
        self.manager.register_risk(risk)

        # enforce_readiness çağrıldığında RiskAppetiteExceededError fırlatılmalıdır
        with self.assertRaises(RiskAppetiteExceededError):
            self.manager.enforce_readiness()

    def test_15_governance_executive_sign_off_passes_and_report_generation(self):
        """Üst yönetim onayı olduğunda yönetişim geçmeli ve Markdown raporu eksiksiz üretilmelidir."""
        # Yönetim onaylı risk
        risk = RiskItem(
            "R-OK", "İstisnalı Risk", "", "Legacy Sistem", 50000, 0.2, 0.5, 4, 3,
            treatment_strategy=RiskTreatmentStrategy.ACCEPT,
            executive_sign_off=True,
            sign_off_notes="Yeni sisteme geçiş yapılana kadar CIO onayıyla kabul edildi."
        )
        self.manager.register_risk(risk)
        # Yönetişim başarılı olmalıdır
        passed, violations = self.manager.validate_corporate_risk_governance()
        self.assertTrue(passed)
        # enforce_readiness istisna fırlatmamalıdır
        self.manager.enforce_readiness()
        # Markdown raporu üretilir
        report = self.manager.generate_executive_report()
        self.assertIn("# Finansal Guvenlik A.S.", report)
        self.assertIn("İstisnalı Risk", report)
        self.assertIn("UYUMLU", report)


# Test modülü doğrudan çalıştırılırsa unittest ana fonksiyonu çağrılır
if __name__ == "__main__":
    unittest.main()
