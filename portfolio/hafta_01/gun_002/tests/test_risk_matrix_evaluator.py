"""
Tehdit, Zafiyet, Olay ve Risk Matrisi Birim ve Entegrasyon Testleri
================================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu test paketi, Gün 002 için matematiksel risk formülü doğrulamalarını,
senaryo sütun ayrıştırmasını, pozitif senaryoları ve negatif kontrolleri
(geçersiz parametre, eksik alan, sıfır risk yanılgısı tespiti) denetler.
"""

import os
import sys
import tempfile
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from risk_matrix_evaluator import (
    RiskMatrixEvaluator,
    InvalidRiskParameterError,
    MissingScenarioFieldError,
    UnrealisticSecurityClaimError
)


class TestRiskMatrixEvaluator(unittest.TestCase):
    def setUp(self):
        """Test senaryoları dosyası hazırlar."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
        self.sample_data = [
            {
                "id": "SCN-TEST-1",
                "baslik": "Test Web Zafiyeti",
                "varlik": "Web Sunucusu",
                "tehdit": "Dış Saldırgan",
                "zafiyet": "SQL Injection",
                "olay": "Veritabanı sızıntısı",
                "olasilik": 4,
                "etki": 5,
                "onlem": "Prepared Statements ve WAF",
                "onlem_sonrasi_olasilik": 1,
                "onlem_sonrasi_etki": 2
            },
            {
                "id": "SCN-TEST-2",
                "baslik": "Test Zayıf Parola",
                "varlik": "E-posta Kutusu",
                "tehdit": "Brute Force Bot",
                "zafiyet": "Tahmin edilebilir parola",
                "olay": "Hesap ele geçirme",
                "olasilik": 3,
                "etki": 3,
                "onlem": "MFA ve Karmaşık Parola Politikası",
                "onlem_sonrasi_olasilik": 1,
                "onlem_sonrasi_etki": 1
            }
        ]
        json.dump(self.sample_data, self.temp_file, ensure_ascii=False)
        self.temp_file.close()
        self.evaluator = RiskMatrixEvaluator(self.temp_file.name)

    def tearDown(self):
        """Geçici dosyayı temizler."""
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    # -------------------------------------------------------------
    # 1. POZİTİF KONTROLLER: MATEMATİKSEL RİSK FORMÜLÜ VE SEVİYELER
    # -------------------------------------------------------------
    def test_calculate_risk_score_and_levels(self):
        """Risk Skoru = Olasılık x Etki formülü ve seviye eşleştirmelerini doğrular."""
        # 1x1 = 1 (Düşük)
        score, level = RiskMatrixEvaluator.calculate_score_and_level(1, 1)
        self.assertEqual(score, 1)
        self.assertEqual(level, "DÜŞÜK")

        # 3x2 = 6 (Orta)
        score, level = RiskMatrixEvaluator.calculate_score_and_level(3, 2)
        self.assertEqual(score, 6)
        self.assertEqual(level, "ORTA")

        # 4x4 = 16 (Yüksek)
        score, level = RiskMatrixEvaluator.calculate_score_and_level(4, 4)
        self.assertEqual(score, 16)
        self.assertEqual(level, "YÜKSEK")

        # 5x5 = 25 (Kritik)
        score, level = RiskMatrixEvaluator.calculate_score_and_level(5, 5)
        self.assertEqual(score, 25)
        self.assertEqual(level, "KRİTİK")

    def test_mitigation_and_residual_risk(self):
        """Önlem sonrası artık risk ve azalma yüzdesi hesabını doğrular."""
        # İlk risk: 4 * 5 = 20. Önlem sonrası: 1 * 2 = 2.
        post_score, post_level, reduction = RiskMatrixEvaluator.evaluate_mitigation(20, 1, 2)
        self.assertEqual(post_score, 2)
        self.assertEqual(post_level, "DÜŞÜK")
        self.assertEqual(reduction, 90.0)

    def test_full_evaluation_flow(self):
        """JSON dosyasındaki senaryoların eksiksiz değerlendirildiğini doğrular."""
        results = self.evaluator.run_full_evaluation()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["inherent_score"], 20)
        self.assertEqual(results[0]["inherent_level"], "KRİTİK")
        self.assertEqual(results[0]["residual_score"], 2)
        self.assertEqual(results[1]["inherent_score"], 9)
        self.assertEqual(results[1]["inherent_level"], "ORTA")

    # -------------------------------------------------------------
    # 2. NEGATİF KONTROLLER: HATALI GİRDİ VE YANILGI ENGELLEME
    # -------------------------------------------------------------
    def test_negative_invalid_likelihood_out_of_bounds(self):
        """Olasılık değeri 1-5 aralığı dışında olduğunda InvalidRiskParameterError vermelidir."""
        with self.assertRaises(InvalidRiskParameterError):
            RiskMatrixEvaluator.calculate_score_and_level(6, 3)

        with self.assertRaises(InvalidRiskParameterError):
            RiskMatrixEvaluator.calculate_score_and_level(0, 3)

        with self.assertRaises(InvalidRiskParameterError):
            RiskMatrixEvaluator.calculate_score_and_level(-1, 3)

    def test_negative_invalid_impact_out_of_bounds(self):
        """Etki değeri 1-5 aralığı dışında olduğunda InvalidRiskParameterError vermelidir."""
        with self.assertRaises(InvalidRiskParameterError):
            RiskMatrixEvaluator.calculate_score_and_level(3, 10)

        with self.assertRaises(InvalidRiskParameterError):
            RiskMatrixEvaluator.calculate_score_and_level(3, 0)

    def test_negative_missing_required_field(self):
        """Senaryoda 'tehdit' veya 'zafiyet' gibi zorunlu alan eksikse MissingScenarioFieldError vermelidir."""
        bad_scenario = {
            "id": "SCN-BAD",
            "baslik": "Eksik Senaryo",
            "varlik": "Sunucu",
            # "tehdit" eksik!
            "zafiyet": "Yok",
            "olay": "Yok",
            "olasilik": 2,
            "etki": 2,
            "onlem": "Yok"
        }
        with self.assertRaises(MissingScenarioFieldError):
            self.evaluator.validate_scenario(bad_scenario)

    def test_negative_unrealistic_zero_residual_risk_claim(self):
        """'Tek bir önlemle riski 0 yaptık' iddiası UnrealisticSecurityClaimError ile reddedilmelidir."""
        with self.assertRaises(UnrealisticSecurityClaimError):
            # Olasılığı veya etkiyi 0 girerek riski sıfırlamaya çalışma yanılgısı
            RiskMatrixEvaluator.evaluate_mitigation(20, 0, 1)

    # -------------------------------------------------------------
    # 3. GERÇEK VERİ SENARYOLARI TESTİ
    # -------------------------------------------------------------
    def test_actual_curriculum_scenarios(self):
        """Örnek verideki 3 ana müfredat senaryosunu (Hastane, E-Ticaret, Muhasebe) doğrular."""
        actual_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "senaryolar.json")
        actual_evaluator = RiskMatrixEvaluator(actual_path)
        results = actual_evaluator.run_full_evaluation()

        self.assertEqual(len(results), 3)
        # SCN-01: Hastane (20 -> 2)
        self.assertEqual(results[0]["id"], "SCN-01")
        self.assertEqual(results[0]["inherent_score"], 20)
        self.assertEqual(results[0]["residual_score"], 2)

        # SCN-02: E-Ticaret (25 -> 4)
        self.assertEqual(results[1]["id"], "SCN-02")
        self.assertEqual(results[1]["inherent_score"], 25)
        self.assertEqual(results[1]["residual_score"], 4)

        # SCN-03: Muhasebe (16 -> 2)
        self.assertEqual(results[2]["id"], "SCN-03")
        self.assertEqual(results[2]["inherent_score"], 16)
        self.assertEqual(results[2]["residual_score"], 2)


if __name__ == "__main__":
    unittest.main()
